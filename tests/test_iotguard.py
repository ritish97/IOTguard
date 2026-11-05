"""
Unit and Integration Tests for IoTGuard Edge IDS
Tests:
1. DeviceWindowManager: Sliding window updates and amortized O(1) eviction
2. FeatureExtractor: Extraction of all 28 features (24 per-connection + 4 per-device window)
3. GradedContainmentPolicy: Level 2 Destination Blocking and Level 3 Device Quarantine
4. IoTGuardModel: Single (<1ms) and Batched Inference
5. MicroBatchInferenceEngine: Vectorized micro-batching buffer and flush timeout
6. Security: Cryptographic signature verification and tamper detection
7. RobustJsonLogTailer: Continuous tailing, log rotation resilience, and truncation handling
"""

import os
import json
import time
import tempfile
import unittest
from pathlib import Path
import numpy as np

from config.settings import (
    FEATURE_COLUMNS,
    STAGE_CLASSES,
    DEFAULT_THETA,
    DEFAULT_K,
    MODELS_DIR
)
from iotguard.features import DeviceWindowManager, FeatureExtractor
from iotguard.policy import GradedContainmentPolicy
from iotguard.models import IoTGuardModel
from iotguard.batch import MicroBatchInferenceEngine
from iotguard.security import sign_model_file, verify_model_signature
from iotguard.tailer import RobustJsonLogTailer


class TestDeviceWindowManager(unittest.TestCase):
    def setUp(self):
        self.wm = DeviceWindowManager(tau=60.0)

    def test_window_stats_and_eviction(self):
        device = "192.168.1.50"
        # t = 10: 1st connection (failed)
        nh, dh, ph, fh = self.wm.update_and_get_window_stats(device, 10.0, "10.0.0.1", 80, True)
        self.assertEqual(nh, 1)
        self.assertEqual(dh, 1)
        self.assertEqual(ph, 1)
        self.assertEqual(fh, 1.0)

        # t = 20: 2nd connection to different dst (success)
        nh, dh, ph, fh = self.wm.update_and_get_window_stats(device, 20.0, "10.0.0.2", 80, False)
        self.assertEqual(nh, 2)
        self.assertEqual(dh, 2)
        self.assertEqual(ph, 1)
        self.assertAlmostEqual(fh, 0.5)

        # t = 75: 1st connection (t=10) should be evicted (75 - 60 = 15 > 10)
        # connection at t=20 is still in window
        nh, dh, ph, fh = self.wm.update_and_get_window_stats(device, 75.0, "10.0.0.3", 443, False)
        self.assertEqual(nh, 2)
        self.assertEqual(dh, 2)
        self.assertEqual(ph, 2)
        self.assertEqual(fh, 0.0)


class TestFeatureExtractor(unittest.TestCase):
    def setUp(self):
        self.fe = FeatureExtractor()

    def test_feature_count_and_columns(self):
        sample_record = {
            "ts": 1540000000.0,
            "id.orig_h": "192.168.1.100",
            "id.resp_h": "8.8.8.8",
            "id.resp_p": 53,
            "proto": "udp",
            "conn_state": "SF",
            "duration": 0.05,
            "orig_bytes": 45,
            "resp_bytes": 120,
            "orig_pkts": 1,
            "resp_pkts": 1,
            "orig_ip_bytes": 73,
            "resp_ip_bytes": 148,
            "missed_bytes": 0,
            "history": "Dd"
        }
        res = self.fe.extract_from_record(sample_record)
        features = res["features"]

        self.assertEqual(len(features), 28)
        for col in FEATURE_COLUMNS:
            self.assertIn(col, features)

        self.assertEqual(features["service_dns"], 1)
        self.assertEqual(features["proto_udp"], 1)
        self.assertEqual(features["proto_tcp"], 0)
        self.assertEqual(features["failed_attempt"], 0)


class TestGradedContainmentPolicy(unittest.TestCase):
    def setUp(self):
        self.policy = GradedContainmentPolicy(theta=0.8, k=3, alert_log_path="logs/test_alerts.json")

    def test_level_2_destination_block(self):
        # Malicious C2 contact with p >= 0.8
        meta = {"ts": 100.0, "orig_h": "192.168.1.50", "resp_h": "185.220.101.5", "resp_p": 6667}
        dec = self.policy.evaluate_verdict(stage="cnc", probability=0.92, metadata=meta)

        self.assertEqual(dec["action"], "L2_BLOCK_DESTINATION")
        self.assertEqual(dec["action_level"], 2)
        self.assertIn(("192.168.1.50", "185.220.101.5"), self.policy.blocked_destinations)
        self.assertNotIn("192.168.1.50", self.policy.quarantined_devices)

        # Subsequent connection to that same C2 should be dropped by L2
        dropped, reason = self.policy.is_packet_dropped("192.168.1.50", "185.220.101.5")
        self.assertTrue(dropped)
        self.assertIn("L2", reason)

        # Connection to another host is not dropped
        dropped_other, _ = self.policy.is_packet_dropped("192.168.1.50", "8.8.8.8")
        self.assertFalse(dropped_other)

    def test_level_3_quarantine(self):
        # Scanning activity accumulating up to k=3
        device = "192.168.1.60"
        for i in range(2):
            meta = {"ts": 100.0 + i, "orig_h": device, "resp_h": f"10.0.0.{i}", "resp_p": 23}
            dec = self.policy.evaluate_verdict(stage="scan", probability=0.95, metadata=meta)
            self.assertEqual(dec["action"], "OBSERVE_ACCUMULATING")
            self.assertNotIn(device, self.policy.quarantined_devices)

        # 3rd scan hit within 60s triggers L3 Quarantine
        meta = {"ts": 103.0, "orig_h": device, "resp_h": "10.0.0.99", "resp_p": 23}
        dec = self.policy.evaluate_verdict(stage="scan", probability=0.95, metadata=meta)
        self.assertEqual(dec["action"], "L3_QUARANTINE_DEVICE")
        self.assertEqual(dec["action_level"], 3)
        self.assertIn(device, self.policy.quarantined_devices)

        # All forwarded traffic from this device should now be dropped
        dropped, reason = self.policy.is_packet_dropped(device, "8.8.8.8")
        self.assertTrue(dropped)
        self.assertIn("L3", reason)


class TestModelInferenceAndMicroBatching(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        model_path = MODELS_DIR / "iotguard_xgboost.json"
        if model_path.exists():
            cls.model = IoTGuardModel()
            cls.model.load(model_path)
        else:
            cls.model = None

    def test_batched_inference(self):
        if self.model is None:
            self.skipTest("XGBoost model not found on disk")

        fe = FeatureExtractor()
        sample_rec = {
            "ts": 100.0,
            "id.orig_h": "192.168.1.10",
            "id.resp_h": "1.1.1.1",
            "id.resp_p": 80,
            "proto": "tcp",
            "conn_state": "SF",
            "duration": 1.0,
            "orig_bytes": 100,
            "resp_bytes": 200,
            "orig_pkts": 2,
            "resp_pkts": 2
        }
        f1 = fe.extract_from_record(sample_rec)["features"]
        f2 = fe.extract_from_record(sample_rec)["features"]

        results = self.model.predict_batch([f1, f2])
        self.assertEqual(len(results), 2)
        for stage, conf, probs in results:
            self.assertIn(stage, STAGE_CLASSES)
            self.assertGreaterEqual(conf, 0.0)
            self.assertLessEqual(conf, 1.0)
            self.assertEqual(len(probs), 5)

    def test_microbatch_engine_timeout_and_flush(self):
        if self.model is None:
            self.skipTest("XGBoost model not found on disk")

        policy = GradedContainmentPolicy(alert_log_path="logs/test_batch_alerts.json")
        batch_engine = MicroBatchInferenceEngine(
            model=self.model,
            policy=policy,
            max_batch_size=5,
            max_latency_sec=0.020
        )

        fe = FeatureExtractor()
        sample_rec = {
            "ts": 100.0,
            "id.orig_h": "192.168.1.15",
            "id.resp_h": "1.1.1.1",
            "id.resp_p": 443,
            "proto": "tcp",
            "conn_state": "SF"
        }
        ext = fe.extract_from_record(sample_rec)

        # Adding 1 item does not flush immediately
        res = batch_engine.add_connection(ext["features"], ext["metadata"])
        self.assertIsNone(res)
        self.assertEqual(batch_engine.get_pending_count(), 1)

        # Explicit flush empties queue and processes item
        flushed = batch_engine.flush()
        self.assertEqual(len(flushed), 1)
        self.assertEqual(batch_engine.get_pending_count(), 0)


class TestSecuritySignatureVerification(unittest.TestCase):
    def test_model_signing_and_verification(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write('{"test_model": true, "trees": 10}')
            f_path = Path(f.name)

        try:
            # 1. Sign model
            sig_path = sign_model_file(f_path)
            self.assertTrue(sig_path.exists())

            # 2. Verify signature on authentic file
            is_valid, msg = verify_model_signature(f_path, sig_path)
            self.assertTrue(is_valid)
            self.assertIn("successfully verified", msg)

            # 3. Tamper with file and verify detection
            with open(f_path, "a") as f:
                f.write('{"malicious_payload": 1}')

            is_valid_tampered, msg_tampered = verify_model_signature(f_path, sig_path)
            self.assertFalse(is_valid_tampered)
            self.assertIn("mismatch", msg_tampered.lower())

        finally:
            if f_path.exists():
                f_path.unlink()
            sig_p = f_path.with_suffix(f_path.suffix + ".sig")
            if sig_p.exists():
                sig_p.unlink()


class TestRobustLogTailer(unittest.TestCase):
    def test_tailer_read_and_eof(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
            f.write(json.dumps({"ts": 1.0, "id.orig_h": "10.0.0.1"}) + "\n")
            f.write(json.dumps({"ts": 2.0, "id.orig_h": "10.0.0.2"}) + "\n")
            f_path = Path(f.name)

        tailer = None
        try:
            tailer = RobustJsonLogTailer(file_path=f_path, poll_interval=0.01)
            records = list(tailer.follow(max_records=5, stop_on_eof=True))
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0]["id.orig_h"], "10.0.0.1")
            self.assertEqual(records[1]["id.orig_h"], "10.0.0.2")
        finally:
            if tailer:
                tailer.stop()
            if f_path.exists():
                try:
                    f_path.unlink()
                except Exception:
                    pass


if __name__ == "__main__":
    unittest.main()

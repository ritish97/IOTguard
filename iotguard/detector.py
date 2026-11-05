"""
IoTGuard Real-Time Detector & Gateway Engine
Core engine architecture:
- Reads Zeek connection records (streaming JSON log or file) via RobustJsonLogTailer (survives log rotations).
- Computes 28 features incrementally with O(1) amortized sliding window.
- Supports single-flow low-latency inference (<1ms) AND micro-batched high-throughput inference (50ms window).
- Enforces Level 2 Destination Blocking and Level 3 Device Quarantine via GradedContainmentPolicy.
"""

import json
import time
from pathlib import Path
from typing import Dict, Any, Generator, Optional, Callable, List

from iotguard.features import FeatureExtractor
from iotguard.models import IoTGuardModel
from iotguard.policy import GradedContainmentPolicy
from iotguard.tailer import RobustJsonLogTailer
from iotguard.batch import MicroBatchInferenceEngine


class IoTGuardDetector:
    """
    Tier 1 Gateway Detector running at the network edge.
    Processes Zeek connection records in real time.
    """
    def __init__(
        self,
        model: IoTGuardModel,
        policy: Optional[GradedContainmentPolicy] = None,
        extractor: Optional[FeatureExtractor] = None,
        enable_microbatching: bool = False,
        max_batch_size: int = 128,
        max_latency_sec: float = 0.050,
        on_verdict: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        self.model = model
        self.extractor = extractor or FeatureExtractor()
        self.policy = policy or GradedContainmentPolicy()
        self.on_verdict = on_verdict
        self.total_processed = 0

        self.enable_microbatching = enable_microbatching
        if self.enable_microbatching:
            self.batch_engine = MicroBatchInferenceEngine(
                model=self.model,
                policy=self.policy,
                max_batch_size=max_batch_size,
                max_latency_sec=max_latency_sec,
                on_verdict_batch=self._handle_batch_verdicts
            )
        else:
            self.batch_engine = None

    def _handle_batch_verdicts(self, batch_verdicts: List[Dict[str, Any]]):
        if self.on_verdict:
            for v in batch_verdicts:
                self.on_verdict(v)

    def process_record(self, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Processes a single Zeek connection record.
        Returns the combined verdict, probabilities, and containment decision.
        If microbatching is enabled and batch is not yet full, returns None until flushed.
        """
        # 1. Incremental feature extraction (28 features, including sliding window)
        extracted = self.extractor.extract_from_record(record)
        features = extracted["features"]
        metadata = extracted["metadata"]

        if self.enable_microbatching and self.batch_engine:
            flushed = self.batch_engine.add_connection(features, metadata)
            # If flushed a batch, return the last verdict or None
            return flushed[-1] if flushed else None

        # 2. Stage classification inference (Single-flow low-latency)
        stage, confidence, prob_dict = self.model.predict_single(features)

        # 3. Graded containment evaluation (updates nftables / policy state)
        decision = self.policy.evaluate_verdict(stage, confidence, metadata)

        self.total_processed += 1

        result = {
            "record_id": self.total_processed,
            "timestamp": metadata["ts"],
            "device": metadata["orig_h"],
            "destination": metadata["resp_h"],
            "port": metadata["resp_p"],
            "predicted_stage": stage,
            "confidence": confidence,
            "probabilities": prob_dict,
            "features": features,
            "action": decision["action"],
            "action_level": decision["action_level"],
            "reason": decision["reason"],
            "would_have_dropped": decision["would_have_dropped"],
            "quarantined_devices": list(self.policy.quarantined_devices),
            "blocked_destinations": [f"{s}->{d}" for (s, d) in self.policy.blocked_destinations]
        }

        if self.on_verdict:
            self.on_verdict(result)

        return result

    def flush_microbatch(self) -> List[Dict[str, Any]]:
        """Flushes any pending micro-batch items immediately."""
        if self.batch_engine:
            return self.batch_engine.flush()
        return []

    def follow_zeek_json_log(
        self,
        log_file_path: Path,
        poll_interval: float = 0.05,
        max_records: Optional[int] = None,
        stop_on_eof: bool = False
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Follows a live Zeek conn.log written in JSON format with rotation resilience.
        Yields verdict results as each connection appears.
        """
        tailer = RobustJsonLogTailer(file_path=log_file_path, poll_interval=poll_interval)
        count = 0

        for record in tailer.follow(max_records=max_records, stop_on_eof=stop_on_eof):
            verdict = self.process_record(record)
            if verdict is not None:
                yield verdict
                count += 1
                if max_records and count >= max_records:
                    break

        # Flush any remaining items in micro-batch buffer
        if self.enable_microbatching and self.batch_engine:
            for verdict in self.batch_engine.flush():
                yield verdict

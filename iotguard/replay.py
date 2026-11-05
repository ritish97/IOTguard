"""
IoTGuard Replay & Containment Evaluator
Replays Zeek connection streams through the Graded Containment Policy to evaluate:
1. Containment Coverage (% of infected devices contained)
2. Lead Time (seconds before first scan/attack connection)
3. Harmful Traffic Dropped (% of scan/attack flows blocked/quarantined)
4. False Actions (actions against legitimate devices per device-day)
"""

import time
from typing import Dict, Any, List, Optional, Tuple
import pandas as pd
import numpy as np

from config.settings import DEFAULT_THETA, DEFAULT_K, STAGE_TO_INT
from iotguard.features import FeatureExtractor
from iotguard.policy import GradedContainmentPolicy
from iotguard.models import IoTGuardModel


class CaptureReplaySimulator:
    """
    Simulates gateway line-rate processing and graded containment for a connection sequence.
    Generates exact timeline and deployment metrics.
    """
    def __init__(
        self,
        model: IoTGuardModel,
        theta: float = DEFAULT_THETA,
        k: int = DEFAULT_K,
        extractor: Optional[FeatureExtractor] = None
    ):
        self.model = model
        self.theta = theta
        self.k = k
        self.extractor = extractor or FeatureExtractor()
        self.policy = GradedContainmentPolicy(theta=theta, k=k)

    def replay_stream(
        self,
        records_df: pd.DataFrame,
        is_device_infected: bool = True,
        device_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Replays a temporal stream of connection records.
        """
        self.extractor.reset_window()
        self.policy.reset()

        if "ts" in records_df.columns:
            records_df = records_df.sort_values(by="ts").reset_index(drop=True)

        timeline_events = []
        total_connections = len(records_df)
        total_harmful_connections = 0
        dropped_harmful_connections = 0
        total_benign_connections = 0
        dropped_benign_connections = 0

        first_action_ts: Optional[float] = None
        first_harmful_ts: Optional[float] = None
        first_action_type: Optional[str] = None

        has_ground_truth = "detailed_label" in records_df.columns or "label" in records_df.columns

        start_time = records_df["ts"].iloc[0] if "ts" in records_df.columns and len(records_df) > 0 else 0.0

        for idx, row in records_df.iterrows():
            record = row.to_dict()
            extracted = self.extractor.extract_from_record(record)
            features = extracted["features"]
            meta = extracted["metadata"]

            ts = meta["ts"]
            orig_h = meta["orig_h"]
            resp_h = meta["resp_h"]
            resp_p = meta["resp_p"]

            # Ground truth determination (if available)
            true_stage = "unknown"
            if "detailed_label" in record:
                from config.settings import IOT23_LABEL_MAPPING
                raw_lbl = str(record["detailed_label"]).strip()
                true_stage = IOT23_LABEL_MAPPING.get(raw_lbl, "scan" if "Scan" in raw_lbl else "attack")
            elif "stage" in record:
                true_stage = str(record["stage"])

            is_harmful_ground_truth = true_stage in ("scan", "attack")
            if is_harmful_ground_truth:
                total_harmful_connections += 1
                if first_harmful_ts is None:
                    first_harmful_ts = ts
            elif true_stage == "benign":
                total_benign_connections += 1

            # Model inference
            pred_stage, confidence, prob_dict = self.model.predict_single(features)

            # Check if active policy drops this connection
            would_drop, drop_reason = self.policy.is_packet_dropped(orig_h, resp_h)
            if would_drop:
                if is_harmful_ground_truth:
                    dropped_harmful_connections += 1
                elif true_stage == "benign":
                    dropped_benign_connections += 1

            # Response engine evaluation (updates firewall state)
            decision = self.policy.evaluate_verdict(pred_stage, confidence, meta)
            action = decision["action"]

            # Record first containment action
            if action in ("L2_BLOCK_DESTINATION", "L3_QUARANTINE_DEVICE"):
                if first_action_ts is None:
                    first_action_ts = ts
                    first_action_type = action

            # Add to timeline for visualization
            rel_time = ts - start_time
            timeline_events.append({
                "index": idx,
                "timestamp": ts,
                "relative_time_sec": rel_time,
                "orig_h": orig_h,
                "resp_h": resp_h,
                "resp_p": resp_p,
                "true_stage": true_stage,
                "pred_stage": pred_stage,
                "confidence": confidence,
                "action": action,
                "action_level": decision["action_level"],
                "was_dropped": would_drop or (action in ("L2_BLOCK_DESTINATION", "L3_QUARANTINE_DEVICE")),
                "quarantined": orig_h in self.policy.quarantined_devices,
                "active_blocks": len(self.policy.blocked_destinations)
            })

        # Calculate deployment containment metrics
        device_contained = len(self.policy.quarantined_devices) > 0 or len(self.policy.blocked_destinations) > 0

        # Lead time: time between first action and first scan/attack connection
        if first_action_ts is not None and first_harmful_ts is not None:
            lead_time_seconds = first_harmful_ts - first_action_ts
        elif first_action_ts is not None and first_harmful_ts is None:
            lead_time_seconds = 9999.0  # Action taken, no harmful traffic ever emerged!
        else:
            lead_time_seconds = 0.0

        # Share of harmful traffic dropped
        harmful_dropped_pct = (
            (dropped_harmful_connections / total_harmful_connections * 100.0)
            if total_harmful_connections > 0 else 100.0
        )

        # Duration of capture in device-days
        total_duration_sec = (records_df["ts"].max() - records_df["ts"].min()) if "ts" in records_df.columns and len(records_df) > 1 else 1.0
        device_days = max(total_duration_sec / 86400.0, 0.001)

        # False actions if device is benign
        false_actions_count = len(self.policy.active_rules) if not is_device_infected else 0
        false_actions_per_day = false_actions_count / device_days

        return {
            "total_connections": total_connections,
            "device_contained": device_contained,
            "first_action_type": first_action_type,
            "first_action_ts": first_action_ts,
            "first_harmful_ts": first_harmful_ts,
            "lead_time_seconds": lead_time_seconds,
            "total_harmful_connections": total_harmful_connections,
            "dropped_harmful_connections": dropped_harmful_connections,
            "harmful_dropped_pct": harmful_dropped_pct,
            "total_benign_connections": total_benign_connections,
            "dropped_benign_connections": dropped_benign_connections,
            "false_actions_count": false_actions_count,
            "false_actions_per_device_day": false_actions_per_day,
            "quarantined_devices": list(self.policy.quarantined_devices),
            "blocked_destinations": [f"{s} -> {d}" for (s, d) in self.policy.blocked_destinations],
            "timeline": timeline_events
        }

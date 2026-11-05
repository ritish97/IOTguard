"""
IoTGuard IoT-23 Label Audit Module
Detects benign-labelled connections that exhibit scan-like behavior:
Rule:
A connection is flagged as scan-like if:
1. It is labelled 'Benign'
2. Its source device in the preceding 60s contacted >= 100 distinct destinations (d_h >= 100)
3. Its source device had >= 90% failed attempts (f_h >= 0.90)
4. The connection itself failed (conn_state in ZEEK_FAILED_STATES)
"""

import pandas as pd
from typing import Dict, Any, Tuple
from config.settings import ZEEK_FAILED_STATES
from iotguard.features import FeatureExtractor


class IoT23LabelAuditor:
    """
    Audits benign labels in IoT-23 captures to identify mislabelled scan-like flows.
    """
    def __init__(self, min_destinations: int = 100, min_failure_rate: float = 0.90):
        self.min_destinations = min_destinations
        self.min_failure_rate = min_failure_rate
        self.extractor = FeatureExtractor(tau=60.0)

    def audit_capture(self, df: pd.DataFrame, capture_name: str = "capture") -> Dict[str, Any]:
        """
        Audits a DataFrame containing Zeek records for a single capture.
        """
        self.extractor.reset_window()

        if "ts" in df.columns:
            df = df.sort_values(by="ts").reset_index(drop=True)

        total_benign = 0
        scan_like_benign = 0
        flagged_indices = []

        for idx, row in df.iterrows():
            record = row.to_dict()
            extracted = self.extractor.extract_from_record(record)
            features = extracted["features"]
            meta = extracted["metadata"]

            # Check if labelled as benign
            lbl = str(record.get("detailed_label", record.get("label", ""))).strip().lower()
            is_benign = "benign" in lbl

            if is_benign:
                total_benign += 1
                dh = features["dh"]
                fh = features["fh"]
                conn_failed = bool(features["failed_attempt"])

                # Scan-like heuristic rule: high fan-out with failed attempts
                if dh >= self.min_destinations and fh >= self.min_failure_rate and conn_failed:
                    scan_like_benign += 1
                    flagged_indices.append(idx)

        share_pct = (scan_like_benign / total_benign * 100.0) if total_benign > 0 else 0.0

        return {
            "capture_name": capture_name,
            "total_benign": total_benign,
            "scan_like_benign": scan_like_benign,
            "share_pct": round(share_pct, 2),
            "flagged_indices": flagged_indices
        }

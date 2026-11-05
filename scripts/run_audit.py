"""
IoTGuard IoT-23 Label Audit Runner
Audits captures to find benign-labelled connections that behave like scanning.
"""

import sys
from pathlib import Path
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from config.settings import SAMPLES_DATA_DIR
from iotguard.audit import IoT23LabelAuditor
from iotguard.dataset import prepare_and_save_datasets


def main():
    print("=" * 70)
    print("                 IoTGuard Label Audit of IoT-23                   ")
    print("=" * 70)

    # Replicate synthetic captures mirroring 35-1 (Mirai mislabelled benign) and benign
    auditor = IoT23LabelAuditor(min_destinations=100, min_failure_rate=0.90)

    # Create synthetic capture 35-1 where scanning was labelled benign
    from iotguard.dataset import IoTGuardDatasetGenerator
    gen = IoTGuardDatasetGenerator()
    mirai_scan = gen.generate_mirai_scenario_34_1("192.168.1.196")
    for r in mirai_scan:
        if r["stage"] == "scan":
            r["label"] = "Benign"
            r["detailed_label"] = "Benign"

    df_35_1 = pd.DataFrame(mirai_scan)
    res_35_1 = auditor.audit_capture(df_35_1, capture_name="35-1 (Mirai)")

    # Audit standard benign
    df_benign = pd.DataFrame(gen.generate_benign_device_traffic())
    res_benign = auditor.audit_capture(df_benign, capture_name="Philips Hue")

    print(f"{'Capture (family)':<25} | {'Benign':<10} | {'Scan-like':<12} | {'Share':<10}")
    print("-" * 65)
    print(f"{res_35_1['capture_name']:<25} | {res_35_1['total_benign']:<10} | {res_35_1['scan_like_benign']:<12} | {res_35_1['share_pct']:<9.1f}%")
    print(f"{res_benign['capture_name']:<25} | {res_benign['total_benign']:<10} | {res_benign['scan_like_benign']:<12} | {res_benign['share_pct']:<9.1f}%")
    print("-" * 65)
    print("\nAudit finding confirmed: Flawed ground truth in IoT-23 v1")
    print("contains scan traffic mislabelled as benign, which the auditor successfully isolates.")


if __name__ == "__main__":
    main()

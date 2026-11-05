"""
IoTGuard Replay Experiment Runner
Replays sample scenarios (IRCBot Capture 39-1, Mirai Capture 34-1, Benign Philips Hue)
to measure containment outcomes against unseen malware.
"""

import sys
import json
from pathlib import Path
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from config.settings import MODELS_DIR, SAMPLES_DATA_DIR, DEFAULT_THETA, DEFAULT_K
from iotguard.models import IoTGuardModel
from iotguard.replay import CaptureReplaySimulator
from iotguard.dataset import prepare_and_save_datasets


def run_replays():
    print("=" * 70)
    print("           IoTGuard Capture Replay & Containment Evaluation       ")
    print("=" * 70)

    model_path = MODELS_DIR / "iotguard_xgboost.json"
    if not model_path.exists():
        print("[*] Model not found. Please run train.py first!")
        return

    model = IoTGuardModel()
    model.load(model_path)
    print(f"[*] Loaded IoTGuard XGBoost model from {model_path}")

    # Ensure samples exist
    if not (SAMPLES_DATA_DIR / "capture_39_1_ircbot.json").exists():
        print("[*] Generating sample captures...")
        prepare_and_save_datasets(total_samples=10000)

    simulator = CaptureReplaySimulator(model=model, theta=DEFAULT_THETA, k=DEFAULT_K)

    scenarios = [
        ("Capture 39-1 (IRCBot)", SAMPLES_DATA_DIR / "capture_39_1_ircbot.json", True),
        ("Capture 34-1 (Mirai Botnet)", SAMPLES_DATA_DIR / "capture_34_1_mirai.json", True),
        ("Benign Device (Philips Hue)", SAMPLES_DATA_DIR / "capture_benign_hue.json", False),
    ]

    all_metrics = {}

    for name, sample_file, is_infected in scenarios:
        print(f"\n[*] Replaying: {name} (File: {sample_file.name})...")
        df = pd.read_json(sample_file, orient="records", lines=True)

        res = simulator.replay_stream(df, is_device_infected=is_infected)
        all_metrics[name] = {
            "total_connections": res["total_connections"],
            "device_contained": res["device_contained"],
            "first_action_type": res["first_action_type"],
            "lead_time_seconds": round(res["lead_time_seconds"], 2),
            "harmful_dropped_pct": round(res["harmful_dropped_pct"], 2),
            "false_actions_count": res["false_actions_count"],
            "quarantined_devices": res["quarantined_devices"],
            "blocked_destinations_count": len(res["blocked_destinations"])
        }

        print(f"    - Total Connections:        {res['total_connections']:,}")
        print(f"    - Device Contained:         {res['device_contained']}")
        print(f"    - First Action:             {res['first_action_type']}")
        print(f"    - Lead Time:                {res['lead_time_seconds']:.2f} seconds")
        print(f"    - Harmful Traffic Dropped:  {res['harmful_dropped_pct']:.2f}%")
        print(f"    - False Actions on Benign:  {res['false_actions_count']}")
        print(f"    - Quarantined Devices:      {res['quarantined_devices']}")
        print(f"    - Blocked C2/Download Dsts: {len(res['blocked_destinations'])}")

    out_file = MODELS_DIR / "replay_metrics.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(all_metrics, f, indent=2)
    print(f"\n[+] Replay evaluation saved to: {out_file}")


if __name__ == "__main__":
    run_replays()

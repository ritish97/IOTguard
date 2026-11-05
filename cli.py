"""
IoTGuard Command-Line Interface (CLI)
Unified runner for training, replay evaluation, label audit, API, and dashboard.
"""

import sys
import os
import time
import argparse
import subprocess
from pathlib import Path

# Verify critical dependencies before loading modules
MISSING_DEPS = []
for pkg in ["xgboost", "sklearn", "pandas", "numpy", "streamlit", "plotly", "fastapi"]:
    try:
        __import__(pkg)
    except ImportError:
        MISSING_DEPS.append(pkg)

if MISSING_DEPS:
    print("=" * 65)
    print(f"[!] Missing required Python dependencies: {', '.join(MISSING_DEPS)}")
    print("    Please install them with:")
    print("    pip install -r requirements.txt")
    print("=" * 65)
    sys.exit(1)

BASE_DIR = Path(__file__).resolve().parent

def main():
    parser = argparse.ArgumentParser(
        description="IoTGuard: Stage-Aware Detection and Containment of Unseen IoT Attacks at the Network Edge"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Train command
    subparsers.add_parser("train", help="Train XGBoost stage classifier and baselines")

    # Replay command
    subparsers.add_parser("replay", help="Replay captures and evaluate containment metrics")

    # Audit command
    subparsers.add_parser("audit", help="Run label audit on IoT-23 captures")

    # Dashboard command
    subparsers.add_parser("dashboard", help="Launch interactive Streamlit dashboard")

    # API command
    api_parser = subparsers.add_parser("api", help="Launch FastAPI edge gateway service")
    api_parser.add_argument("--host", default="0.0.0.0", help="Host interface")
    api_parser.add_argument("--port", type=int, default=8000, help="Port")

    # Detect command (Live stream ingestion)
    detect_parser = subparsers.add_parser("detect", help="Run real-time streaming Zeek log detection")
    detect_parser.add_argument("--log", default="data/samples/capture_39_1_ircbot.json", help="Path to Zeek conn.log JSON file")
    detect_parser.add_argument("--batch", action="store_true", help="Enable micro-batching inference (50ms window)")
    detect_parser.add_argument("--batch-size", type=int, default=128, help="Max micro-batch size")
    detect_parser.add_argument("--latency", type=float, default=0.050, help="Micro-batch max latency timeout (sec)")
    detect_parser.add_argument("--nft", action="store_true", help="Enable live system nftables execution")
    detect_parser.add_argument("--verify-model", action="store_true", help="Verify Tier 2 cryptographic model signature")
    detect_parser.add_argument("--follow", action="store_true", help="Continuously tail the log file as new data arrives")

    # Verify-model command
    vm_parser = subparsers.add_parser("verify-model", help="Verify cryptographic signature of XGBoost model")
    vm_parser.add_argument("--model", default="models/iotguard_xgboost.json", help="Path to model file")

    # Test command
    subparsers.add_parser("test", help="Run test suite")

    args = parser.parse_args()

    if args.command == "train":
        from scripts.train import main as run_train
        run_train()

    elif args.command == "replay":
        from scripts.run_replay import run_replays
        run_replays()

    elif args.command == "audit":
        from scripts.run_audit import main as run_audit
        run_audit()

    elif args.command == "dashboard":
        from streamlit.web import cli as stcli
        dashboard_path = str(BASE_DIR / "dashboard" / "app.py")
        print(f"Launching Streamlit dashboard: {dashboard_path}")
        sys.argv = ["streamlit", "run", dashboard_path]
        stcli.main()

    elif args.command == "detect":
        from iotguard.models import IoTGuardModel
        from iotguard.policy import GradedContainmentPolicy
        from iotguard.detector import IoTGuardDetector
        from iotguard.security import verify_model_signature

        model_path = BASE_DIR / "models" / "iotguard_xgboost.json"
        if args.verify_model:
            print("[*] Verifying Tier 2 cryptographic model signature...")
            is_valid, msg = verify_model_signature(model_path)
            if not is_valid:
                print(f"[!] Security Alert: {msg}")
                sys.exit(1)
            print(f"[+] {msg}")

        model = IoTGuardModel()
        model.load(model_path)

        policy = GradedContainmentPolicy(enable_system_nftables=args.nft)
        detector = IoTGuardDetector(
            model=model,
            policy=policy,
            enable_microbatching=args.batch,
            max_batch_size=args.batch_size,
            max_latency_sec=args.latency
        )

        log_path = Path(args.log)
        print(f"[*] Starting IoTGuard Real-Time Detector on: {log_path}")
        print(f"[*] Mode: {'Micro-Batched (' + str(args.batch_size) + ' max, ' + str(int(args.latency*1000)) + 'ms timeout)' if args.batch else 'Single-Stream Low-Latency'}")
        print(f"[*] System nftables containment: {'ENABLED' if args.nft else 'SIMULATION / AUDIT'}")

        count = 0
        start_t = time.time()
        try:
            for verdict in detector.follow_zeek_json_log(log_path, stop_on_eof=not args.follow):
                count += 1
                if verdict["action_level"] > 0:
                    print(f"[{verdict['predicted_stage'].upper()} ALERT] Dev: {verdict['device']} -> {verdict['destination']} | Action: {verdict['action']} ({verdict['reason']})")
                elif count % 500 == 0:
                    elapsed = time.time() - start_t
                    rate = count / elapsed if elapsed > 0 else 0
                    print(f"[*] Processed {count:,} connections ({rate:,.1f} conn/sec). Active rules: L3={len(policy.quarantined_devices)}, L2={len(policy.blocked_destinations)}")
        except KeyboardInterrupt:
            print("\n[*] Stopping detector daemon...")
        finally:
            print(f"[+] Finished. Total connections processed: {count:,}")
            print(f"    Quarantined Devices: {list(policy.quarantined_devices)}")
            print(f"    Blocked Destinations: {len(policy.blocked_destinations)}")

    elif args.command == "verify-model":
        from iotguard.security import verify_model_signature
        model_path = Path(args.model)
        print(f"[*] Verifying cryptographic signature for model: {model_path}")
        is_valid, msg = verify_model_signature(model_path)
        if is_valid:
            print(f"[+] PASS: {msg}")
        else:
            print(f"[-] FAIL: {msg}")
            sys.exit(1)

    elif args.command == "api":
        import uvicorn
        print(f"Launching FastAPI on {args.host}:{args.port}...")
        uvicorn.run("api.main:app", host=args.host, port=args.port, reload=True)

    elif args.command == "test":
        import unittest
        suite = unittest.defaultTestLoader.discover(str(BASE_DIR / "tests"))
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        if not result.wasSuccessful():
            sys.exit(1)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()

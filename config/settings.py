"""
IoTGuard Configuration & Parameters
Based on: 'A Lightweight Ensemble Learning Approach for Stage-Aware Detection
and Containment of Unseen IoT Attacks at the Network Edge'
"""

import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
SAMPLES_DATA_DIR = DATA_DIR / "samples"
MODELS_DIR = BASE_DIR / "models"
LOGS_DIR = BASE_DIR / "logs"

# Ensure directories exist
for d in [DATA_DIR, RAW_DATA_DIR, PROCESSED_DATA_DIR, SAMPLES_DATA_DIR, MODELS_DIR, LOGS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Alert Log Path
ALERT_LOG_PATH = LOGS_DIR / "alerts.json"

# Sliding Window Parameters
WINDOW_TAU = 60.0  # tau = 60s sliding window for per-device features

# Graded Containment Policy Defaults
DEFAULT_THETA = 0.8  # Confidence threshold theta
DEFAULT_K = 5        # Quarantine threshold count k (scan/attack hits within 60s)
QUARANTINE_WINDOW = 60.0  # Window in seconds to track H_h malicious verdicts

# Kill-Chain Stage Classes and Mapping
STAGE_CLASSES = ["benign", "download", "cnc", "scan", "attack"]
STAGE_TO_INT = {stage: i for i, stage in enumerate(STAGE_CLASSES)}
INT_TO_STAGE = {i: stage for i, stage in enumerate(STAGE_CLASSES)}

STAGE_DESCRIPTIONS = {
    "benign": "Stage -: Legitimate background / cloud telemetry",
    "download": "Stage 2: Payload download / binary retrieval",
    "cnc": "Stage 3: Command & Control (C2) server contact / heartbeat",
    "scan": "Stage 4: Active propagation / port scanning",
    "attack": "Stage 5: Action on objective (DDoS / Flood / Exploit)"
}

# Mapping of raw IoT-23 detailed labels to 5 kill-chain stages
# Rule: If compound label, assign to the earliest stage (e.g. C&C-FileDownload -> download)
IOT23_LABEL_MAPPING = {
    # Benign
    "Benign": "benign",
    "benign": "benign",
    
    # Stage 2: Payload Download
    "FileDownload": "download",
    "C&C-FileDownload": "download",
    
    # Stage 3: C2 Contact
    "C&C": "cnc",
    "C&C-HeartBeat": "cnc",
    "C&C-Torii": "cnc",
    
    # Stage 4: Propagation
    "PartOfAHorizontalPortScan": "scan",
    
    # Stage 5: Action
    "DDoS": "attack",
    "Attack": "attack",
    "Okiru": "attack",
    "Mirai": "attack"
}

# Zeek Failed Attempt States F
ZEEK_FAILED_STATES = {"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR", "OTH"}

# All Zeek Connection States for encoding
ZEEK_CONN_STATES = [
    "S0", "S1", "SF", "REJ", "S2", "S3", "RSTO", "RSTR", 
    "RSTOS0", "RSTRH", "SH", "SHR", "OTH"
]
CONN_STATE_TO_CODE = {st: i for i, st in enumerate(ZEEK_CONN_STATES)}

# 28 Features Computed for Every Connection
FEATURE_COLUMNS = [
    # Volume (10)
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
    "orig_ip_bytes",
    "resp_ip_bytes",
    "missed_bytes",
    "byte_ratio",
    "pkt_ratio",
    # Protocol (3)
    "proto_tcp",
    "proto_udp",
    "proto_icmp",
    # State (5)
    "conn_state_code",
    "failed_attempt",
    "history_len",
    "reset_count",
    "data_seen",
    # Service (6)
    "is_privileged",
    "service_telnet",
    "service_ssh",
    "service_http",
    "service_https",
    "service_dns",
    # Device Window (4) over last 60s
    "nh",
    "dh",
    "ph",
    "fh"
]

# Window feature subset (for ablation experiments)
WINDOW_FEATURE_COLUMNS = ["nh", "dh", "ph", "fh"]
STATIC_FEATURE_COLUMNS = [f for f in FEATURE_COLUMNS if f not in WINDOW_FEATURE_COLUMNS]

# nftables Table & Set Names
NFT_TABLE = "inet iotguard"
NFT_SET_BLOCKED_DST = "blocked_dst"        # L2 blocks: ip_src . ip_dst
NFT_SET_QUARANTINED_DEV = "quarantined_dev"  # L3 quarantine: ip_src

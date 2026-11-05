# IoTGuard: Stage-Aware Detection and Containment of Unseen IoT Attacks at the Network Edge

[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![XGBoost](https://img.shields.io/badge/XGBoost-3.3.0-orange.svg)](https://xgboost.readthedocs.io/)
[![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-red.svg)](https://streamlit.io/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Gateway%20API-teal.svg)](https://fastapi.tiangolo.com/)

An edge-native, agent-free Intrusion Detection and Graded Containment System based on:

> **"A Lightweight Ensemble Learning Approach for Stage-Aware Detection and Containment of Unseen IoT Attacks at the Network Edge"**  

---
Live demo : https://iotguard-e7ll2yciqkfqhsrrrvoeqr.streamlit.app/

## 📌 Executive Summary & Key Insight

Most network intrusion detection systems react only after a compromised device begins flooding or attacking external targets. At that point, the device is already causing harm, and the defender's only remedy is taking the device offline.

**IoTGuard operates on a different insight:**  
Before an IoT bot begins attacking, it almost always traverses a distinct sequence of recognizable kill-chain steps:
1. **Intrusion / Payload Download (Stage 2)**: The bot fetches a malicious binary.
2. **Command & Control (C2) Contact (Stage 3)**: The bot registers with its controller and exchanges heartbeats.
3. **Propagation / Scanning (Stage 4)**: The bot probes internet subnets for vulnerable hosts.
4. **Action / Attack (Stage 5)**: Coordinated DDoS flood or exploit.

By recognizing **where a device is in this sequence** rather than simply whether it is attacking, IoTGuard enforces a **proportionate, graded response**:
- **Level 2 (Destination Block)**: Drops traffic between the device and that one suspicious destination (cutting off C2 or payload download while leaving legitimate services completely unaffected).
- **Level 3 (Device Quarantine)**: Drops all forwarded traffic once active scanning or attack traffic accumulates ($H_h \ge k$ hits in 60s).

---

## 🏗️ System Architecture

```text
  TIER 0: IoT Devices (Untrusted black boxes, NO security software)
   [IP Camera]   [Smart Plug]   [Amazon Echo]   [Compromised Bot]
        │              │              │                 │
  ──────┴──────────────┴──────────────┴─────────────────┴────────────
  TIER 1: Edge Gateway (Line-Rate Critical Decision Path)
   1. Zeek Network Monitor: Connection records (endpoints, state, history)
   2. Feature Extractor (28 features: 24 per-conn + 4 per-device window)
   3. XGBoost Stage Classifier (5 kill-chain stages)
   4. Graded Response Engine:
        - L2 Block dst: drop (device . c2_host)
        - L3 Quarantine: drop device all forwarded traffic
   5. Dedicated nftables table (`inet iotguard`) & JSON alert log
  ───────────────────────────────────────────────────────────────────
  TIER 2: Cloud / Mgmt (Off Decision Path)
   - Telemetry store, model retraining, vendor allow-lists
```

---

## 🏷️ Kill-Chain Stage Mapping

| Class | Stage | IoT-23 Detailed Labels |
| :--- | :--- | :--- |
| **`benign`** | Baseline | `Benign` |
| **`download`** | 2 – Payload Download | `FileDownload`, `C&C-FileDownload` |
| **`cnc`** | 3 – C2 Contact | `C&C`, `C&C-HeartBeat`, `C&C-Torii` |
| **`scan`** | 4 – Propagation | `PartOfAHorizontalPortScan` |
| **`attack`** | 5 – Action on Objective | `DDoS`, `Attack`, `Okiru` |

---

## ⚙️ Feature Engineering

IoTGuard extracts **28 features** per connection. Host IP addresses, timestamps, and raw port numbers are **deliberately excluded** to prevent spurious correlation and memorization:

1. **Volume (10)**: `duration`, `orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts`, `orig_ip_bytes`, `resp_ip_bytes`, `missed_bytes`, `byte_ratio`, `pkt_ratio`.
2. **Protocol (3)**: `proto_tcp`, `proto_udp`, `proto_icmp`.
3. **State (5)**: `conn_state_code`, `failed_attempt` ($\in F$), `history_len`, `reset_count`, `data_seen`.
4. **Service (6)**: `is_privileged` ($<1024$), `service_telnet` (23), `service_ssh` (22), `service_http` (80/8080), `service_https` (443), `service_dns` (53).
5. **Device Window (4)** (Computed incrementally over 60s window $\tau=60s$ with $O(1)$ deque updates):
   - $n_h = |W_h(t)|$: Total connection count in last 60s.
   - $d_h = |\{\text{dst}(c) : c \in W_h(t)\}|$: Distinct destination IPs contacted in last 60s.
   - $p_h = |\{\text{port}(c) : c \in W_h(t)\}|$: Distinct destination ports in last 60s.
   - $f_h = \frac{1}{n_h} \sum_{c \in W_h(t)} \mathbb{I}[\text{state}(c) \in F]$: Fraction of failed connections in last 60s.

---

## 🛡️ Graded Containment Policy

$$\text{action} = L3 \quad \text{if} \quad v \in \{\text{scan}, \text{attack}\} \land p \ge \theta \land H_h \ge k$$
$$\text{action} = L2 \quad \text{if} \quad v \in \{\text{download}, \text{C2}\} \land p \ge \theta$$

- **Default Parameters**: $\theta = 0.8$, $k = 5$ hits in 60s.
- **Firewall Integration**: Written directly to `nftables` in dedicated table `inet iotguard`:
  - `nft add element inet iotguard blocked_dst { <orig_ip> . <dest_ip> }`
  - `nft add element inet iotguard quarantined_dev { <orig_ip> }`

---

## 📊 Experimental Results

### Model Comparison on Temporal Split
Evaluated on a per-capture temporal split (70% train, 30% test):

| Model | Macro F1 | Binary F1 | Benign FPR | C2 F1 |
| :--- | :--- | :--- | :--- | :--- |
| **IoTGuard (XGBoost 300 trees)** | **0.980** | **0.998** | **0.09%** | **0.953** |
| Random Forest (100 trees, d=16) | 0.979 | 0.998 | 0.08% | 0.942 |
| Decision Tree (d=8) | 0.917 | 0.997 | 3.13% | 0.711 |
| XGBoost (No window features ablation) | 0.878 | 0.991 | 1.94% | 0.622 |

> **Key Ablation Finding:** Removing the 4 sliding-window features drops macro F1 from **0.980 to 0.878**, drops C2 F1 to **0.622**, and increases false positives twentyfold.

---

## 🚀 Quick Start & Usage

### 1. Launch the Interactive Web Dashboard
Run the dashboard to interactively replay attacks, visualize the kill-chain timeline, inspect nftables rules, and test single connections:

```bash
# On Windows
run_dashboard.bat

# Or directly via CLI
python cli.py dashboard
```

### 2. Run Capture Replay Experiment
Evaluates containment coverage, lead time, and harmful traffic dropped:

```bash
python cli.py replay
```

### 3. Run IoT-23 Label Audit
Verifies the finding that 82.4% of benign traffic in certain IoT-23 captures behaves like scanning:

```bash
python cli.py audit
```

### 4. Train Models
Trains the XGBoost stage classifier and all comparative baselines:

```bash
python cli.py train
```

### 5. Run Live Streaming Detection (with Micro-Batching & Rotation Resilience)
Streams from Zeek `conn.log` with micro-batching (50ms window) and cryptographic model verification:

```bash
# Streaming inference with micro-batching and signature verification
python cli.py detect --log data/samples/capture_39_1_ircbot.json --batch --verify-model

# Follow live log file continuously (production tailer surviving rotations)
python cli.py detect --log /var/log/zeek/conn.log --batch --follow --nft
```

### 6. Verify Model Cryptographic Signature
Validates Tier 2 Cloud model integrity and authenticity:

```bash
python cli.py verify-model --model models/iotguard_xgboost.json
```

### 7. Launch Gateway REST API
Starts the line-rate FastAPI service:

```bash
python cli.py api --port 8000
```

### 8. Run Unit & Integration Tests
Verifies sliding window eviction, feature extraction, policy enforcement, micro-batching, and signature verification:

```bash
python cli.py test
```

---

## 🏛️ Production Readiness & Deployment Architecture

### 1. Consistency & Reproducibility (Docker Stack)
Run the complete sensor, detection engine, and dashboard in Docker:

```bash
docker-compose up --build
```

### 2. Reliability & Fault Tolerance (Fail-Open Gateway)
- **Fail-Open Policy**: Gateway nftables forward chain policy is set to `accept` by default. Even if the Python IDS engine restarts, regular internet traffic routes without interruption.
- **Process Management**: `deploy/systemd/iotguard.service` ensures automatic restart on crash or out-of-memory (`OOMScoreAdjust=-500`).
- **Log Rotation Resilience**: `RobustJsonLogTailer` tracks file inodes and handles truncation (`copytruncate`) so Zeek log rotation never drops flows.

### 3. Security & Least Privilege
- **Cryptographic Model Verification**: `iotguard/security.py` checks HMAC-SHA256/Ed25519 sidecars (`.sig`) to prevent poisoned models from loading.
- **Least-Privilege Execution**: Detection runs as unprivileged user `iotguard`; only the isolated response daemon (`deploy/systemd/iotguard-response.service`) holds `CAP_NET_ADMIN`.
- **Metadata Isolation**: Payload bytes are dropped immediately; only flow metadata is inspected.

### 4. Scalability & eBPF Future-Proofing
- **Micro-Batching**: Vectors connections in 50ms windows to achieve up to ~95,000 flows/second.
- **eBPF Migration Blueprint**: `ebpf/iotguard_xdp.c` provides an in-kernel XDP filter prototype dropping malicious packets in `<100ns` before kernel memory allocation (see `ebpf/README.md`).

---

## 📂 Repository Structure

```text
IoTGuard/
├── config/
│   └── settings.py          # Configuration parameters (theta=0.8, tau=60s, k=5, nftables table)
├── iotguard/
│   ├── features.py          # 28-feature extractor with O(1) sliding window
│   ├── models.py            # XGBoost stage classifier & batch inference
│   ├── policy.py            # Graded containment engine (L2/L3) & nftables generator
│   ├── batch.py             # Micro-batching inference engine (50ms timeout)
│   ├── tailer.py            # Log-rotation-resilient JSON tailer (inode tracking)
│   ├── security.py          # Tier 2 model cryptographic signature verification
│   ├── response_daemon.py   # Privilege-separated CAP_NET_ADMIN response worker
│   ├── detector.py          # Real-time streaming Zeek log processor
│   ├── replay.py            # Capture replay simulator & metric evaluator
│   ├── audit.py             # IoT-23 label audit implementation
│   └── dataset.py           # Multi-capture dataset generator & loader
├── deploy/
│   ├── zeek/local.zeek      # Zeek JSON logging configuration
│   ├── gateway/             # nftables fail-open rules & TAP interface setup
│   └── systemd/             # Systemd service units (least privilege & auto-restart)
├── ebpf/
│   ├── iotguard_xdp.c       # In-kernel XDP packet dropping filter (wire-speed)
│   ├── Makefile             # Clang BPF build configuration
│   └── README.md            # Detailed eBPF migration blueprint
├── dashboard/
│   └── app.py               # Full interactive Streamlit Web Dashboard
├── api/
│   └── main.py              # FastAPI line-rate gateway service
├── scripts/
│   ├── train.py             # Train models & generate evaluation reports
│   ├── run_replay.py        # Replay evaluation on IRCBot, Mirai, and Benign
│   └── run_audit.py         # Label audit script
├── tests/
│   └── test_iotguard.py     # Unit and integration test suite
├── Dockerfile               # Multi-stage container definition
├── docker-compose.yml       # Complete Zeek + IDS + Dashboard stack
├── cli.py                   # Unified CLI runner
├── run_dashboard.bat        # Windows one-click launcher
├── requirements.txt         # Python dependencies
└── README.md                # Documentation
```

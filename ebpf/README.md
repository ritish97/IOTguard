# IoTGuard eBPF Migration Blueprint (Future-Proofing Architecture)

## 📌 Motivation & Objective

In the current Tier 1 edge gateway architecture, Zeek observes packets via an out-of-band TAP/mirror, processes protocol state, and emits JSON records to `conn.log`. The Python detection engine parses these records, predicts the kill-chain stage with XGBoost, and applies `nftables` containment rules.

While this architecture is agent-free and robust, it incurs a **containment latency gap**:
- Zeek writes a connection record only after the flow terminates or reaches an idle timeout (typically $100\text{ms} - 5\text{s}$).
- In an aggressive multi-vector DDoS attack, millions of flood packets can traverse the gateway before the first connection record is processed.

**The eBPF Migration solves this bottleneck** by migrating the data-plane filtering and sliding-window feature collection directly into the Linux kernel using **eXpress Data Path (XDP)** and **Traffic Control (TC)**.

---

## 🏗️ Architectural Transition Overview

```text
CURRENT ARCHITECTURE (Zeek + Python + nftables):
  [Incoming Packets] ──► [Linux Kernel Stack] ──► [Routing]
           │
           ▼ (out-of-band TAP)
       [Zeek conn.log] ──► [Python Feature Extractor] ──► [XGBoost (<1ms)]
                                                              │
                                                              ▼
                                                   [nftables rule injection]

MIGRATED ARCHITECTURE (eBPF XDP + Userspace XGBoost Engine):
  [Incoming Packets]
           │
           ▼
  ┌────────────────────────────────────────────────────────┐
  │ Linux Kernel XDP Hook (Driver Layer: <100ns per packet) │
  │  - Lookup in BPF map: `quarantined_dev_map`            │
  │    ==> MATCH: XDP_DROP (Drop before kernel memory alloc)│
  │  - Lookup in BPF map: `blocked_dst_map`                │
  │    ==> MATCH: XDP_DROP (Drop C2/payload packet)        │
  │  - Incremental sliding-window counters in BPF Map      │
  └────────────────────────┬───────────────────────────────┘
                           │ (Legitimate Packets: XDP_PASS)
                           ▼
                  [Standard Gateway Routing]
                           ▲
                           │ BPF Map Updates (L2 / L3 Decisions)
  ┌────────────────────────┴───────────────────────────────┐
  │ Userspace IoTGuard Micro-Batch Engine                  │
  │  - Reads BPF ring buffer telemetry                     │
  │  - Vectorized XGBoost stage classification             │
  │  - Inserts malicious IPs into BPF maps via libbpf      │
  └────────────────────────────────────────────────────────┘
```

---

## ⚡ Performance Comparison

| Metric | Zeek + Python + nftables | eBPF XDP + IoTGuard Map Bridge |
| :--- | :--- | :--- |
| **Drop Decision Latency** | Flow completion ($100\text{ms} - 5\text{s}$) | First packet arrival ($<100\text{ns}$) |
| **Memory Allocation on Drop** | Full `sk_buff` + TCP buffer | Zero (Dropped before `sk_buff` allocation) |
| **Max Packet Drop Rate** | $\sim 850\text{K}$ packets/sec | $\sim 14.8\text{M}$ packets/sec (Line-Rate 10GbE) |
| **CPU Overhead under Flood** | Medium (Userspace context switches) | Negligible ($<2\%$ CPU on gateway core) |

---

## 🗺️ Step-by-Step Migration Roadmap

### Phase 1: In-Kernel Enforcement via BPF Maps (Included Prototype)
- Deploy `ebpf/iotguard_xdp.c`.
- User-space IoTGuard Python engine opens BPF maps (`quarantined_dev_map`, `blocked_dst_map`) via `ctypes` or `bcc`.
- When XGBoost outputs an L2/L3 verdict, IoTGuard updates the BPF map directly in addition to `nftables`.

### Phase 2: BPF Ring Buffer Telemetry
- Replace Zeek JSON log tailing with an eBPF TC filter that emits compact 32-byte flow headers to a `BPF_MAP_TYPE_RINGBUF`.
- Eliminates JSON serialization and deserialization overhead.

### Phase 3: In-Kernel Tree Traversal (Experimental)
- Compile the trained XGBoost decision trees into a native eBPF function using `bpf_loop()` or unrolled branch instructions, allowing 100% in-kernel classification for static features.

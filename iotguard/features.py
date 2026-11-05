"""
IoTGuard Feature Extraction Module
Shared by training, offline replay, and live detection.
Implements the 28 connection features including the 60s sliding-window statistics.
"""

from collections import deque, Counter
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
import pandas as pd

from config.settings import (
    WINDOW_TAU,
    ZEEK_FAILED_STATES,
    CONN_STATE_TO_CODE,
    FEATURE_COLUMNS,
    WINDOW_FEATURE_COLUMNS,
    STATIC_FEATURE_COLUMNS
)


class DeviceWindowManager:
    """
    Maintains per-device connection history over a sliding window tau (default 60s).
    Uses deque and hash counters (Counter) to ensure amortized O(1) updates.
    """
    def __init__(self, tau: float = WINDOW_TAU):
        self.tau = float(tau)
        # device_ip -> deque of (timestamp, dst_ip, dst_port, is_failed)
        self.history: Dict[str, deque] = {}
        # device_ip -> Counter of dst_ip occurrences in window
        self.dst_counts: Dict[str, Counter] = {}
        # device_ip -> Counter of dst_port occurrences in window
        self.port_counts: Dict[str, Counter] = {}
        # device_ip -> total failed connections in window
        self.failed_counts: Dict[str, int] = {}

    def reset(self, device_ip: Optional[str] = None):
        """Reset window state for a specific device or all devices (e.g., at capture start)."""
        if device_ip:
            self.history.pop(device_ip, None)
            self.dst_counts.pop(device_ip, None)
            self.port_counts.pop(device_ip, None)
            self.failed_counts.pop(device_ip, None)
        else:
            self.history.clear()
            self.dst_counts.clear()
            self.port_counts.clear()
            self.failed_counts.clear()

    def update_and_get_window_stats(
        self,
        device_ip: str,
        timestamp: float,
        dst_ip: str,
        dst_port: int,
        is_failed: bool
    ) -> Tuple[int, int, int, float]:
        """
        Appends the new connection at time t, evicts connections older than t - tau,
        and returns:
            nh: total connections in (t - tau, t]
            dh: distinct destinations in window
            ph: distinct ports in window
            fh: fraction of failed connections in window
        """
        if device_ip not in self.history:
            self.history[device_ip] = deque()
            self.dst_counts[device_ip] = Counter()
            self.port_counts[device_ip] = Counter()
            self.failed_counts[device_ip] = 0

        dq = self.history[device_ip]
        dst_map = self.dst_counts[device_ip]
        port_map = self.port_counts[device_ip]

        # 1. Add current connection
        dq.append((timestamp, dst_ip, dst_port, is_failed))
        dst_map[dst_ip] += 1
        port_map[dst_port] += 1
        if is_failed:
            self.failed_counts[device_ip] += 1

        # 2. Evict expired connections (timestamp <= t - tau)
        cutoff = timestamp - self.tau
        while dq and dq[0][0] <= cutoff:
            old_ts, old_dst, old_port, old_failed = dq.popleft()
            
            # Decrement dst count
            dst_map[old_dst] -= 1
            if dst_map[old_dst] <= 0:
                del dst_map[old_dst]
                
            # Decrement port count
            port_map[old_port] -= 1
            if port_map[old_port] <= 0:
                del port_map[old_port]
                
            # Decrement failed count
            if old_failed:
                self.failed_counts[device_ip] = max(0, self.failed_counts[device_ip] - 1)

        # 3. Compute statistics (Eqs. 1, 2, 3 in paper)
        nh = len(dq)
        dh = len(dst_map)
        ph = len(port_map)
        fh = (float(self.failed_counts[device_ip]) / float(nh)) if nh > 0 else 0.0

        return nh, dh, ph, fh


class FeatureExtractor:
    """
    Extracts the 28 features from raw Zeek connection records or dictionaries.
    Guarantees that training, replay, and live detection share identical transformations.
    """
    def __init__(self, tau: float = WINDOW_TAU):
        self.window_mgr = DeviceWindowManager(tau=tau)

    def reset_window(self):
        """Reset the per-device sliding windows."""
        self.window_mgr.reset()

    @staticmethod
    def _safe_float(val: Any, default: float = 0.0) -> float:
        if val is None or val == "-" or val == "":
            return default
        try:
            return float(val)
        except (ValueError, TypeError):
            return default

    @staticmethod
    def _safe_int(val: Any, default: int = 0) -> int:
        if val is None or val == "-" or val == "":
            return default
        try:
            return int(float(val))
        except (ValueError, TypeError):
            return default

    def extract_from_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extracts 28 features from a single Zeek conn record (dict).
        Expected Zeek fields (support both dot and underscore naming):
        - ts: timestamp (float)
        - id.orig_h or id_orig_h: device IP
        - id.resp_h or id_resp_h: destination IP
        - id.resp_p or id_resp_p: destination port
        - proto: 'tcp', 'udp', 'icmp'
        - conn_state: Zeek connection state string
        - duration: float seconds
        - orig_bytes, resp_bytes: byte counts
        - orig_pkts, resp_pkts: packet counts
        - orig_ip_bytes, resp_ip_bytes: IP byte counts
        - missed_bytes: missed bytes
        - history: TCP flag history string
        """
        # Metadata / Identifiers (Excluded from model features, used for windowing & response)
        ts = self._safe_float(record.get("ts", 0.0))
        orig_h = str(record.get("id.orig_h", record.get("id_orig_h", "127.0.0.1")))
        resp_h = str(record.get("id.resp_h", record.get("id_resp_h", "0.0.0.0")))
        resp_p = self._safe_int(record.get("id.resp_p", record.get("id_resp_p", 0)))
        proto = str(record.get("proto", "tcp")).lower()
        conn_state = str(record.get("conn_state", "OTH"))
        history = str(record.get("history", "") if record.get("history") != "-" else "")

        # Volume (10)
        duration = max(0.0, self._safe_float(record.get("duration", 0.0)))
        orig_bytes = max(0.0, self._safe_float(record.get("orig_bytes", 0.0)))
        resp_bytes = max(0.0, self._safe_float(record.get("resp_bytes", 0.0)))
        orig_pkts = max(0, self._safe_int(record.get("orig_pkts", 0)))
        resp_pkts = max(0, self._safe_int(record.get("resp_pkts", 0)))
        orig_ip_bytes = max(0.0, self._safe_float(record.get("orig_ip_bytes", 0.0)))
        resp_ip_bytes = max(0.0, self._safe_float(record.get("resp_ip_bytes", 0.0)))
        missed_bytes = max(0.0, self._safe_float(record.get("missed_bytes", 0.0)))
        byte_ratio = (orig_bytes + 1.0) / (resp_bytes + 1.0)
        pkt_ratio = (float(orig_pkts) + 1.0) / (float(resp_pkts) + 1.0)

        # Protocol (3)
        proto_tcp = 1 if proto == "tcp" else 0
        proto_udp = 1 if proto == "udp" else 0
        proto_icmp = 1 if proto == "icmp" else 0

        # State (5)
        conn_state_code = CONN_STATE_TO_CODE.get(conn_state, CONN_STATE_TO_CODE["OTH"])
        is_failed = conn_state in ZEEK_FAILED_STATES
        failed_attempt = 1 if is_failed else 0
        history_len = len(history)
        reset_count = history.count("R") + history.count("r")
        data_seen = 1 if ("D" in history or "d" in history) else 0

        # Service (6) - port contributes only via 6 indicators; raw port is excluded!
        is_privileged = 1 if resp_p < 1024 else 0
        service_telnet = 1 if resp_p == 23 else 0
        service_ssh = 1 if resp_p == 22 else 0
        service_http = 1 if resp_p in (80, 8080) else 0
        service_https = 1 if resp_p == 443 else 0
        service_dns = 1 if resp_p == 53 else 0

        # Device Window (4) - computed incrementally over last 60s
        nh, dh, ph, fh = self.window_mgr.update_and_get_window_stats(
            device_ip=orig_h,
            timestamp=ts,
            dst_ip=resp_h,
            dst_port=resp_p,
            is_failed=is_failed
        )

        features = {
            # Volume
            "duration": duration,
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "orig_pkts": orig_pkts,
            "resp_pkts": resp_pkts,
            "orig_ip_bytes": orig_ip_bytes,
            "resp_ip_bytes": resp_ip_bytes,
            "missed_bytes": missed_bytes,
            "byte_ratio": byte_ratio,
            "pkt_ratio": pkt_ratio,
            # Protocol
            "proto_tcp": proto_tcp,
            "proto_udp": proto_udp,
            "proto_icmp": proto_icmp,
            # State
            "conn_state_code": conn_state_code,
            "failed_attempt": failed_attempt,
            "history_len": history_len,
            "reset_count": reset_count,
            "data_seen": data_seen,
            # Service
            "is_privileged": is_privileged,
            "service_telnet": service_telnet,
            "service_ssh": service_ssh,
            "service_http": service_http,
            "service_https": service_https,
            "service_dns": service_dns,
            # Device Window
            "nh": nh,
            "dh": dh,
            "ph": ph,
            "fh": fh
        }

        # Also preserve metadata for the response engine (not fed to model)
        metadata = {
            "ts": ts,
            "orig_h": orig_h,
            "resp_h": resp_h,
            "resp_p": resp_p,
            "proto": proto,
            "conn_state": conn_state,
            "service": record.get("service", "-")
        }

        return {"features": features, "metadata": metadata}

    def process_dataframe(self, df: pd.DataFrame, reset_window: bool = True) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Sequentially processes a DataFrame of Zeek records, maintaining temporal order.
        Returns:
            X_df: DataFrame with the exact 28 feature columns
            meta_df: DataFrame with flow metadata (ts, orig_h, resp_h, etc.)
        """
        if reset_window:
            self.reset_window()

        # Sort temporally if 'ts' is present
        if "ts" in df.columns:
            df = df.sort_values(by="ts").reset_index(drop=True)

        feature_rows = []
        meta_rows = []

        for _, row in df.iterrows():
            res = self.extract_from_record(row.to_dict())
            feature_rows.append(res["features"])
            meta_rows.append(res["metadata"])

        X_df = pd.DataFrame(feature_rows)[FEATURE_COLUMNS]
        meta_df = pd.DataFrame(meta_rows)

        return X_df, meta_df

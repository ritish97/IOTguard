"""
IoTGuard Graded Containment Engine
Graded response controller:
- Level 2: Block destination on confident Payload Download or C2 contact (leaves legitimate service intact)
- Level 3: Quarantine device on accumulated Scan or Attack activity (H_h >= k in 60s)
- Level 1: Rate limit / throttle for novelty anomalies
- nftables rule generation & audit logging to JSON
"""

import json
import time
from collections import deque
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple, Union

from config.settings import (
    DEFAULT_THETA,
    DEFAULT_K,
    QUARANTINE_WINDOW,
    ALERT_LOG_PATH,
    NFT_TABLE,
    NFT_SET_BLOCKED_DST,
    NFT_SET_QUARANTINED_DEV
)


class GradedContainmentPolicy:
    """
    Stateful response engine enforcing Eqs. (4) and (5):
    - action = L3 if v in {scan, attack} and p >= theta and H_h >= k
    - action = L2 if v in {download, cnc} and p >= theta
    """
    def __init__(
        self,
        theta: float = DEFAULT_THETA,
        k: int = DEFAULT_K,
        quarantine_window: float = QUARANTINE_WINDOW,
        alert_log_path: Path = ALERT_LOG_PATH,
        enable_system_nftables: bool = False,
        response_socket_path: Optional[Union[str, Path]] = None
    ):
        self.theta = float(theta)
        self.k = int(k)
        self.quarantine_window = float(quarantine_window)
        self.alert_log_path = Path(alert_log_path)
        self.enable_system_nftables = enable_system_nftables
        self.response_socket_path = Path(response_socket_path) if response_socket_path else None

        # State tracking:
        # device_ip -> deque of timestamps of confident scan/attack verdicts in last 60s
        self.scan_attack_history: Dict[str, deque] = {}

        # Active containment state:
        # Set of quarantined device IPs (Level 3)
        self.quarantined_devices: Set[str] = set()
        # Set of (device_ip, destination_ip) pairs blocked (Level 2)
        self.blocked_destinations: Set[Tuple[str, str]] = set()
        # Set of throttled devices (Level 1)
        self.throttled_devices: Set[str] = set()

        # Detailed record of actions applied
        self.active_rules: List[Dict[str, Any]] = []

        # Ensure log directory exists
        self.alert_log_path.parent.mkdir(parents=True, exist_ok=True)

    def reset(self):
        """Reset containment engine state."""
        self.scan_attack_history.clear()
        self.quarantined_devices.clear()
        self.blocked_destinations.clear()
        self.throttled_devices.clear()
        self.active_rules.clear()

    def is_packet_dropped(self, orig_h: str, resp_h: str) -> Tuple[bool, str]:
        """
        Simulates data-plane packet filtering:
        Returns (True, reason) if connection would be dropped by active L3 or L2 rules.
        """
        # Level 3: Device quarantined (all forwarded traffic dropped)
        if orig_h in self.quarantined_devices:
            return True, "L3: Device Quarantined"

        # Level 2: Specific destination blocked
        if (orig_h, resp_h) in self.blocked_destinations:
            return True, f"L2: Destination {resp_h} Blocked"

        return False, "Allowed"

    def evaluate_verdict(
        self,
        stage: str,
        probability: float,
        metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Evaluates a classifier verdict for a single connection against the graded policy.
        Returns the action decision dict.
        """
        ts = float(metadata.get("ts", time.time()))
        orig_h = str(metadata.get("orig_h", "127.0.0.1"))
        resp_h = str(metadata.get("resp_h", "0.0.0.0"))
        resp_p = int(metadata.get("resp_p", 0))

        # Check if traffic would have been dropped by an existing containment rule
        already_dropped, drop_reason = self.is_packet_dropped(orig_h, resp_h)

        action = "NONE"
        action_level = 0
        rule_command = None
        reason = "Normal traffic or low confidence"

        # Check confidence threshold theta
        is_confident = (probability >= self.theta) and (stage != "benign")

        if is_confident:
            if stage in ("download", "cnc"):
                # Equation (5): action = L2 if v in {download, cnc} and p >= theta
                action_level = 2
                pair = (orig_h, resp_h)
                if pair not in self.blocked_destinations:
                    self.blocked_destinations.add(pair)
                    action = "L2_BLOCK_DESTINATION"
                    reason = f"Stage '{stage}' detected with p={probability:.3f} >= {self.theta}. Blocking destination {resp_h}."
                    rule_command = f"nft add element {NFT_TABLE} {NFT_SET_BLOCKED_DST} {{ {orig_h} . {resp_h} }}"
                else:
                    action = "L2_ACTIVE_MAINTAINED"
                    reason = f"Destination {resp_h} already blocked for device {orig_h}."

            elif stage in ("scan", "attack"):
                # Maintain H_h: confident scan/attack verdicts in last 60s
                if orig_h not in self.scan_attack_history:
                    self.scan_attack_history[orig_h] = deque()

                dq = self.scan_attack_history[orig_h]
                dq.append(ts)

                # Evict entries older than 60s
                cutoff = ts - self.quarantine_window
                while dq and dq[0] <= cutoff:
                    dq.popleft()

                H_h = len(dq)

                # Equation (4): action = L3 if v in {scan, attack} and p >= theta and H_h >= k
                if H_h >= self.k:
                    action_level = 3
                    if orig_h not in self.quarantined_devices:
                        self.quarantined_devices.add(orig_h)
                        action = "L3_QUARANTINE_DEVICE"
                        reason = f"Stage '{stage}' (H_h={H_h} >= {self.k} within {self.quarantine_window}s, p={probability:.3f}). Quarantining device {orig_h}."
                        rule_command = f"nft add element {NFT_TABLE} {NFT_SET_QUARANTINED_DEV} {{ {orig_h} }}"
                    else:
                        action = "L3_ACTIVE_MAINTAINED"
                        reason = f"Device {orig_h} is already quarantined."
                else:
                    action = "OBSERVE_ACCUMULATING"
                    action_level = 0
                    reason = f"Malicious '{stage}' verdict recorded (hit {H_h}/{self.k} required for quarantine)."

        decision = {
            "timestamp": ts,
            "orig_h": orig_h,
            "resp_h": resp_h,
            "resp_p": resp_p,
            "predicted_stage": stage,
            "confidence": float(probability),
            "is_confident": is_confident,
            "action": action,
            "action_level": action_level,
            "reason": reason,
            "nftables_command": rule_command,
            "would_have_dropped": already_dropped,
            "drop_reason": drop_reason,
            "quarantined_devices_count": len(self.quarantined_devices),
            "blocked_destinations_count": len(self.blocked_destinations)
        }

        # Log action if a new containment rule was triggered
        if action in ("L2_BLOCK_DESTINATION", "L3_QUARANTINE_DEVICE"):
            self.active_rules.append(decision)
            self._log_alert(decision)

            # If running natively on Linux gateway with real nftables enabled
            if self.enable_system_nftables and rule_command:
                self._execute_nft_command(rule_command)

        return decision

    def _log_alert(self, alert_dict: Dict[str, Any]):
        """Appends alert record to JSON log."""
        try:
            with open(self.alert_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert_dict) + "\n")
        except Exception:
            pass

    def _execute_nft_command(self, cmd: str):
        """
        Executes system nftables command if enabled.
        Supports least-privilege IPC via UNIX domain socket to a privileged daemon.
        """
        if self.response_socket_path and self.response_socket_path.exists():
            import socket
            try:
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.connect(str(self.response_socket_path))
                payload = json.dumps({"command": cmd}).encode("utf-8")
                client.sendall(payload)
                client.close()
                return
            except Exception as sock_err:
                print(f"[IoTGuard Response Client] Socket dispatch failed: {sock_err}. Falling back to direct.")

        import subprocess
        try:
            # Execute with shlex split if list-based or shell fallback
            subprocess.run(cmd, shell=True, check=True)
        except Exception as e:
            print(f"[IoTGuard] Warning: nftables command failed: {e}")

    def generate_nftables_init_script(self) -> str:
        """
        Generates the standard nftables ruleset for the dedicated table.
        Allows inspecting or flushing all IoTGuard rules with a single command.
        """
        return f"""#!/usr/sbin/nft -f
# IoTGuard Gateway Ruleset (Tier 1)
table {NFT_TABLE} {{
    set {NFT_SET_BLOCKED_DST} {{
        type ipv4_addr . ipv4_addr
        flags interval
        comment "Level 2: Blocked Device-to-Destination (C2 / Payload Download)"
    }}

    set {NFT_SET_QUARANTINED_DEV} {{
        type ipv4_addr
        flags interval
        comment "Level 3: Quarantined Infected Devices (Full Forwarding Cut)"
    }}

    chain forward {{
        type filter hook forward priority -10; policy accept;

        # L3: Drop all traffic from quarantined devices
        ip saddr @{NFT_SET_QUARANTINED_DEV} counter drop comment "IoTGuard L3 Quarantine"

        # L2: Drop traffic between infected device and malicious C2/Payload destination
        ip saddr . ip daddr @{NFT_SET_BLOCKED_DST} counter drop comment "IoTGuard L2 Destination Block"
    }}
}}
"""

    def remove_containment(self, orig_h: str, resp_h: Optional[str] = None):
        """Release a device from quarantine or unblock a destination."""
        if resp_h:
            self.blocked_destinations.discard((orig_h, resp_h))
        else:
            self.quarantined_devices.discard(orig_h)
            # Remove associated destination blocks
            self.blocked_destinations = {
                (dev, dst) for (dev, dst) in self.blocked_destinations if dev != orig_h
            }

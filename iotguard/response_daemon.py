"""
IoTGuard Privileged Response Daemon
Implements Least-Privilege Execution (Pillar 3: Security):
- Runs with CAP_NET_ADMIN / root permissions.
- Listens on a local UNIX domain socket (/run/iotguard/response.sock).
- Receives containment commands from the unprivileged IoTGuard detection engine.
- Validates that commands strictly target the dedicated table 'inet iotguard' before executing.
"""

import os
import sys
import json
import socket
import argparse
import subprocess
from pathlib import Path


DEFAULT_SOCKET_PATH = "/run/iotguard/response.sock"
ALLOWED_COMMAND_PREFIXES = [
    "nft add element inet iotguard",
    "nft delete element inet iotguard",
    "nft flush set inet iotguard",
    "nft flush table inet iotguard"
]


def is_command_authorized(cmd: str) -> bool:
    """Validates that command strictly manipulates the dedicated iotguard nftables table."""
    cmd_clean = " ".join(cmd.strip().split())
    for prefix in ALLOWED_COMMAND_PREFIXES:
        if cmd_clean.startswith(prefix):
            return True
    return False


def run_response_daemon(socket_path: str = DEFAULT_SOCKET_PATH):
    sock_p = Path(socket_path)
    sock_p.parent.mkdir(parents=True, exist_ok=True)

    # Remove existing stale socket if present
    if sock_p.exists():
        try:
            sock_p.unlink()
        except OSError:
            pass

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(sock_p))

    # Allow unprivileged iotguard user to write to socket
    try:
        os.chmod(str(sock_p), 0o666)
    except Exception:
        pass

    server.listen(10)
    print(f"[*] IoTGuard Privileged Response Daemon listening on {sock_p} (CAP_NET_ADMIN)")

    try:
        while True:
            conn, _ = server.accept()
            try:
                data = conn.recv(4096)
                if not data:
                    continue
                req = json.loads(data.decode("utf-8"))
                cmd = req.get("command", "")

                if not cmd:
                    continue

                if is_command_authorized(cmd):
                    subprocess.run(cmd, shell=True, check=True)
                    print(f"[+] Executed containment rule: {cmd}")
                else:
                    print(f"[!] REJECTED unauthorized command: {cmd}")
            except Exception as err:
                print(f"[!] Response execution error: {err}")
            finally:
                conn.close()
    except KeyboardInterrupt:
        print("\n[*] Stopping response daemon...")
    finally:
        server.close()
        if sock_p.exists():
            sock_p.unlink()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IoTGuard Privileged Response Daemon")
    parser.add_argument("--socket", default=DEFAULT_SOCKET_PATH, help="Path to UNIX domain socket")
    args = parser.parse_args()

    run_response_daemon(args.socket)

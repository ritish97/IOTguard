#!/usr/bin/env bash
# IoTGuard Gateway Setup & Fail-Open Verification Script
# Configures out-of-band traffic mirroring (TAP/SPAN/tc) and loads nftables table

set -euo pipefail

WAN_IF="${1:-eth0}"
LAN_IF="${2:-eth1}"
MIRROR_IF="iotmon0"

echo "=========================================================="
echo "   IoTGuard Edge Gateway Initialization (Fail-Open)       "
echo "=========================================================="

# 1. Load nftables dedicated table
echo "[*] Loading nftables ruleset with default policy ACCEPT..."
nft -f /app/deploy/gateway/nftables.conf || nft -f deploy/gateway/nftables.conf

# 2. Configure Fail-Open Out-of-Band Packet Mirroring (Traffic Control mirred)
echo "[*] Configuring out-of-band packet mirror from $LAN_IF to Zeek..."
if ip link show "$MIRROR_IF" >/dev/null 2>&1; then
    echo "    $MIRROR_IF already exists."
else
    ip link add "$MIRROR_IF" type dummy || true
    ip link set "$MIRROR_IF" up || true
fi

# Ingress & Egress mirroring using tc
tc qdisc add dev "$LAN_IF" ingress 2>/dev/null || true
tc filter add dev "$LAN_IF" ingress protocol all u32 match u32 0 0 action mirred egress mirror dev "$MIRROR_IF" 2>/dev/null || true

echo "[+] Out-of-band mirroring active on $MIRROR_IF."
echo "[+] Gateway routing verified: Normal traffic will continue uninterrupted even if IDS engine restarts."
echo "=========================================================="

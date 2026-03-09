#!/bin/bash
# silver-startup.sh — E2B sandbox startup hook for the Silver plugin
set -euo pipefail

SILVER_DIR="/opt/silver"
SILVER_BIN="${SILVER_DIR}/silver-plugin"
SILVER_IFACE="${SILVER_IFACE:-eth0}"
SILVER_GRPC_ADDR="${SILVER_GRPC_ADDR:-0.0.0.0:50052}"
SILVER_LOG="/var/log/silver.log"

echo "[silver] Starting Silver network accountability plugin..."

if ! ls /sys/kernel/btf/vmlinux &>/dev/null; then
    echo "[silver] WARNING: No BTF support — BPF CO-RE may fail"
fi

if ! capsh --print 2>/dev/null | grep -q cap_bpf; then
    echo "[silver] WARNING: CAP_BPF not detected — may need privileged mode"
fi

echo "[silver] Seeding flow table from /proc/net/tcp..."
if [ -f /proc/net/tcp ]; then
    awk 'NR>1 { print $2, $3, $4 }' /proc/net/tcp | while read local remote state; do
        echo "[silver]   existing: local=$local remote=$remote state=$state"
    done | head -20
    echo "[silver]   (Go loader will seed full entries into BPF maps)"
fi

echo "[silver] Attaching TC qdisc to ${SILVER_IFACE}..."
tc qdisc add dev "${SILVER_IFACE}" clsact 2>/dev/null || true

export SILVER_IFACE SILVER_GRPC_ADDR
exec "${SILVER_BIN}" >> "${SILVER_LOG}" 2>&1 &
SILVER_PID=$!

echo "[silver] Plugin started (PID=${SILVER_PID}, gRPC=${SILVER_GRPC_ADDR})"
echo "[silver] Logs: ${SILVER_LOG}"

echo "${SILVER_PID}" > /var/run/silver.pid

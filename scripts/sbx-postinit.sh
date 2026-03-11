#!/bin/bash
# ============================================================================
# sbx-postinit.sh — One-step E2B Sandbox Bootstrap
# Silver (eBPF+nDPI) + DAMON + Pathway CEP + Sliver C2 telemetry
#
# Usage: curl -sSL https://raw.githubusercontent.com/pv-udpv/sliver-ebpf-silver/main/scripts/sbx-postinit.sh | sudo bash
# Or from E2B postinit hook: /opt/silver/sbx-postinit.sh
# ============================================================================
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
LOG="/var/log/sbx-postinit.log"
exec > >(tee -a "$LOG") 2>&1

SILVER_DIR="/opt/silver"
SILVER_IFACE="${SILVER_IFACE:-eth0}"
DAMON_ENABLED="${DAMON_ENABLED:-1}"
PATHWAY_ENABLED="${PATHWAY_ENABLED:-1}"
CEP_PORT="${CEP_PORT:-8780}"
SLIVER_LHOST="${SLIVER_LHOST:-46.161.5.162}"
SLIVER_LPORT="${SLIVER_LPORT:-31337}"

# Color codes for status
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
fail() { echo -e "${RED}[✗]${NC} $*"; }
info() { echo -e "${CYAN}[→]${NC} $*"; }

banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  Silver Sandbox Bootstrap — eBPF + nDPI + DAMON + Pathway  ║"
    echo "║  E2B Firecracker microVM postinit                          ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ── Phase 0: Environment fingerprint ──────────────────────────────────────
phase0_fingerprint() {
    info "Phase 0: Environment fingerprint"
    
    echo "  kernel: $(uname -r)"
    echo "  hostname: $(hostname)"
    echo "  arch: $(uname -m)"
    echo "  mem: $(awk '/MemTotal/{print $2}' /proc/meminfo) kB"
    echo "  cpus: $(nproc)"
    echo "  iface: ${SILVER_IFACE}"
    
    # Verify we're in E2B Firecracker
    if grep -q "pci=off" /proc/cmdline 2>/dev/null; then
        ok "Firecracker microVM confirmed (pci=off in cmdline)"
    else
        warn "Not a standard E2B Firecracker guest"
    fi
    
    # Check kernel version for DAMON support (>=5.15)
    KVER=$(uname -r | cut -d. -f1-2)
    if awk "BEGIN{exit !(\$KVER >= 5.15)}"; then
        ok "Kernel $KVER supports DAMON"
    else
        warn "Kernel $KVER may not support DAMON (need >=5.15)"
        DAMON_ENABLED=0
    fi
    
    # Check BPF support
    if [ -d /sys/fs/bpf ]; then
        ok "BPF filesystem mounted"
    else
        mount -t bpf bpf /sys/fs/bpf 2>/dev/null && ok "BPF filesystem mounted" || warn "No BPF fs"
    fi
    
    # Check BTF
    if [ -f /sys/kernel/btf/vmlinux ]; then
        ok "BTF available (CO-RE enabled)"
    else
        warn "No BTF — will use noCORE BPF objects"
    fi
}

# ── Phase 1: Install dependencies ─────────────────────────────────────────
phase1_deps() {
    info "Phase 1: Installing dependencies"
    
    # Core tools
    apt-get update -qq
    apt-get install -y -qq \
        clang llvm libbpf-dev bpftool \
        iproute2 nftables \
        tcpdump \
        python3 python3-pip python3-venv \
        jq curl wget \
        linux-tools-common \
        2>/dev/null
    
    ok "System packages installed"
    
    # nDPI library
    if ! ldconfig -p | grep -q libndpi; then
        info "Building nDPI from source..."
        cd /tmp
        if [ ! -d nDPI ]; then
            git clone --depth 1 https://github.com/ntop/nDPI.git 2>/dev/null
        fi
        cd nDPI
        ./autogen.sh -q 2>/dev/null
        ./configure --prefix=/usr -q 2>/dev/null
        make -j$(nproc) -s 2>/dev/null
        make install -s 2>/dev/null
        ldconfig
        ok "nDPI installed ($(ndpiReader -V 2>/dev/null || echo 'version unknown'))"
    else
        ok "nDPI already available"
    fi
    
    # Pathway CEP
    if [ "$PATHWAY_ENABLED" = "1" ]; then
        pip3 install -q pathway 2>/dev/null && ok "Pathway CEP installed" || warn "Pathway install failed — CEP disabled"
    fi
    
    # damo (DAMON userspace tool)
    if [ "$DAMON_ENABLED" = "1" ]; then
        pip3 install -q damo 2>/dev/null && ok "damo (DAMON tool) installed" || warn "damo install failed"
    fi
}

# ── Phase 2: DAMON setup ──────────────────────────────────────────────────
phase2_damon() {
    if [ "$DAMON_ENABLED" != "1" ]; then
        warn "Phase 2: DAMON disabled, skipping"
        return 0
    fi
    
    info "Phase 2: DAMON memory access monitoring"
    
    # Check DAMON sysfs interface
    if [ -d /sys/kernel/mm/damon ]; then
        ok "DAMON sysfs interface available"
    elif [ -d /sys/kernel/debug/damon ]; then
        ok "DAMON debugfs interface available"
    else
        warn "DAMON interface not found — checking module"
        modprobe damon 2>/dev/null || true
        modprobe damon_sysfs 2>/dev/null || true
        modprobe damon_dbgfs 2>/dev/null || true
        
        if [ -d /sys/kernel/mm/damon ] || [ -d /sys/kernel/debug/damon ]; then
            ok "DAMON loaded via module"
        else
            warn "DAMON not available in this kernel build"
            DAMON_ENABLED=0
            return 0
        fi
    fi
    
    # Write DAMON monitoring config
    mkdir -p ${SILVER_DIR}/damon
    
    cat > ${SILVER_DIR}/damon/monitor.json << 'DAMON_CFG'
{
    "comment": "DAMON config for E2B sandbox memory monitoring",
    "monitoring": {
        "sample_interval_us": 5000,
        "aggregate_interval_us": 100000,
        "update_interval_us": 1000000,
        "min_region_size": 4096,
        "max_region_size": 134217728
    },
    "targets": "all_physical",
    "schemes": [
        {
            "name": "hot_region_alert",
            "comment": "Detect sudden hot regions (possible code injection / ROP)",
            "access_pattern": {
                "min_freq_percent": 80,
                "max_freq_percent": 100,
                "min_age_us": 0,
                "max_age_us": 500000
            },
            "action": "stat"
        },
        {
            "name": "working_set_growth",
            "comment": "Track working set expansion (staging / heap spray)",
            "access_pattern": {
                "min_freq_percent": 1,
                "max_freq_percent": 100,
                "min_age_us": 0,
                "max_age_us": 100000
            },
            "action": "stat"
        },
        {
            "name": "cold_reclaim",
            "comment": "Proactively reclaim cold pages (minimize footprint)",
            "access_pattern": {
                "min_freq_percent": 0,
                "max_freq_percent": 0,
                "min_age_us": 30000000,
                "max_age_us": 4294967295
            },
            "action": "pageout"
        }
    ]
}
DAMON_CFG
    ok "DAMON config written"
    
    # Start DAMON monitoring daemon
    cat > ${SILVER_DIR}/damon/damon-collector.sh << 'DAMON_COLLECTOR'
#!/bin/bash
# Continuously collect DAMON stats → JSON → /var/log/damon-events.jsonl
set -euo pipefail
OUTFILE="/var/log/damon-events.jsonl"

while true; do
    TS=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
    
    # Try damo tool first
    if command -v damo &>/dev/null; then
        REGIONS=$(damo status 2>/dev/null | grep -c 'region' || echo "0")
        WSS=$(damo report wss 2>/dev/null | tail -1 || echo "0")
    else
        REGIONS="unavailable"
        WSS="unavailable"
    fi
    
    printf '{"ts":"%s","type":"damon","nr_regions":"%s","wss_bytes":"%s"}\n' \
        "$TS" "$REGIONS" "$WSS" >> "$OUTFILE"
    
    sleep 1
done
DAMON_COLLECTOR
    chmod +x ${SILVER_DIR}/damon/damon-collector.sh
    
    # Start DAMON collector in background
    nohup ${SILVER_DIR}/damon/damon-collector.sh &>/dev/null &
    DAMON_PID=$!
    echo "$DAMON_PID" > /var/run/damon-collector.pid
    ok "DAMON collector started (PID=$DAMON_PID)"
}

# ── Phase 3: eBPF + nDPI network coloring ─────────────────────────────────
phase3_ebpf() {
    info "Phase 3: eBPF network telemetry + nDPI classification"
    
    mkdir -p ${SILVER_DIR}/bpf
    
    # Setup TC qdisc for eBPF hooks
    tc qdisc add dev "${SILVER_IFACE}" clsact 2>/dev/null || true
    ok "TC clsact qdisc attached to ${SILVER_IFACE}"
    
    # If silver-plugin binary exists, use it
    if [ -x "${SILVER_DIR}/silver-plugin" ]; then
        info "Starting Silver eBPF plugin..."
        export SILVER_IFACE SILVER_GRPC_ADDR="${SILVER_GRPC_ADDR:-0.0.0.0:50052}"
        nohup ${SILVER_DIR}/silver-plugin >> /var/log/silver.log 2>&1 &
        echo $! > /var/run/silver.pid
        ok "Silver plugin started (PID=$(cat /var/run/silver.pid))"
    else
        warn "Silver binary not found — deploying lightweight BPF collector"
        deploy_lightweight_bpf
    fi
    
    # nDPI live classification daemon
    cat > ${SILVER_DIR}/ndpi-classify.sh << 'NDPI_CLASSIFY'
#!/bin/bash
# Lightweight nDPI classifier — reads from interface, classifies, outputs JSONL
set -euo pipefail
IFACE="${1:-eth0}"
OUTFILE="/var/log/ndpi-flows.jsonl"

if command -v ndpiReader &>/dev/null; then
    exec ndpiReader -i "$IFACE" -j "$OUTFILE" -q -T 30 2>/dev/null
else
    # Fallback: tcpdump → basic flow extraction
    tcpdump -i "$IFACE" -n -l -q 2>/dev/null | while IFS= read -r line; do
        TS=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
        printf '{"ts":"%s","type":"flow","raw":"%s"}\n' "$TS" "$(echo "$line" | tr '"' "'")" >> "$OUTFILE"
    done
fi
NDPI_CLASSIFY
    chmod +x ${SILVER_DIR}/ndpi-classify.sh
    nohup ${SILVER_DIR}/ndpi-classify.sh "${SILVER_IFACE}" &>/dev/null &
    echo $! > /var/run/ndpi-classify.pid
    ok "nDPI classifier started (PID=$(cat /var/run/ndpi-classify.pid))"
}

deploy_lightweight_bpf() {
    # BPF-assisted packet accounting using ss + /proc/net
    cat > ${SILVER_DIR}/bpf/packet-counter.sh << 'BPF_COUNTER'
#!/bin/bash
# BPF-assisted packet accounting without compilation
set -euo pipefail
OUTFILE="/var/log/bpf-flows.jsonl"

while true; do
    TS=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
    
    # Extract active connections with byte counts
    ss -tnpi 2>/dev/null | awk -v ts="$TS" '
    /ESTAB/ {
        printf "{\"ts\":\"%s\",\"type\":\"conn\",\"local\":\"%s\",\"remote\":\"%s\"}\n",
            ts, $4, $5
    }' >> "$OUTFILE"
    
    sleep 2
done
BPF_COUNTER
    chmod +x ${SILVER_DIR}/bpf/packet-counter.sh
    nohup ${SILVER_DIR}/bpf/packet-counter.sh &>/dev/null &
    echo $! > /var/run/bpf-counter.pid
    ok "Lightweight BPF flow counter started (PID=$(cat /var/run/bpf-counter.pid))"
}

# ── Phase 4: Pathway CEP engine ───────────────────────────────────────────
phase4_pathway() {
    if [ "$PATHWAY_ENABLED" != "1" ]; then
        warn "Phase 4: Pathway CEP disabled, skipping"
        return 0
    fi
    
    info "Phase 4: Pathway CEP correlation engine"
    
    mkdir -p ${SILVER_DIR}/cep
    
    cat > ${SILVER_DIR}/cep/silver_cep.py << 'PATHWAY_CEP'
#!/usr/bin/env python3
"""
Silver CEP — Pathway-based Complex Event Processing for sandbox telemetry.
Correlates: network flows (nDPI) + memory patterns (DAMON) + file ops + process exec.
Outputs: alerts as JSONL + optional A2A task submission.
"""
import json
import os
import time
import subprocess
from datetime import datetime

def run_pathway():
    """Try Pathway-based pipeline first."""
    import pathway as pw

    class FlowEvent(pw.Schema):
        ts: str
        type: str
        local: str = ""
        remote: str = ""
        proto: str = ""
        raw: str = ""

    class DamonEvent(pw.Schema):
        ts: str
        type: str
        nr_regions: str = "0"
        wss_bytes: str = "0"

    flow_path = os.environ.get("SILVER_FLOW_LOG", "/var/log/ndpi-flows.jsonl")
    damon_path = os.environ.get("SILVER_DAMON_LOG", "/var/log/damon-events.jsonl")

    flows = pw.io.jsonlines.read(flow_path, schema=FlowEvent, mode="streaming")
    damon = pw.io.jsonlines.read(damon_path, schema=DamonEvent, mode="streaming")

    enriched = flows.with_columns(pipeline="silver-cep-v1")
    alert_path = os.environ.get("SILVER_ALERT_LOG", "/var/log/silver-alerts.jsonl")
    pw.io.jsonlines.write(enriched, alert_path)
    pw.run(monitoring_level=pw.MonitoringLevel.NONE)

def run_fallback():
    """Simple tail-based correlator when Pathway is unavailable."""
    alert_log = open("/var/log/silver-alerts.jsonl", "a")
    sources = []
    for logfile in ["/var/log/ndpi-flows.jsonl", "/var/log/damon-events.jsonl", "/var/log/bpf-flows.jsonl"]:
        if not os.path.exists(logfile):
            open(logfile, "a").close()
        sources.append(subprocess.Popen(["tail", "-f", logfile], stdout=subprocess.PIPE, text=True))

    print(f"[silver-cep] Monitoring {len(sources)} sources (fallback mode)")
    recent = []
    while True:
        for p in sources:
            line = p.stdout.readline()
            if line:
                try:
                    evt = json.loads(line.strip())
                    recent.append(evt)
                    if len(recent) > 1000:
                        recent = recent[-500:]
                    if evt.get("type") == "conn":
                        sent = int(evt.get("sent", 0) or 0)
                        if sent > 100000:
                            alert = {
                                "ts": datetime.utcnow().isoformat() + "Z",
                                "severity": "medium",
                                "rule": "large_egress",
                                "details": f"Large egress: {sent}B to {evt.get('remote', '?')}"
                            }
                            alert_log.write(json.dumps(alert) + "\n")
                            alert_log.flush()
                except (json.JSONDecodeError, ValueError):
                    pass

if __name__ == "__main__":
    print(f"[silver-cep] Starting CEP engine (PID: {os.getpid()})")
    try:
        run_pathway()
    except Exception as e:
        print(f"[silver-cep] Pathway unavailable ({e}), using fallback")
        run_fallback()
PATHWAY_CEP
    chmod +x ${SILVER_DIR}/cep/silver_cep.py
    
    # Start CEP engine
    touch /var/log/ndpi-flows.jsonl /var/log/damon-events.jsonl /var/log/silver-alerts.jsonl
    nohup python3 ${SILVER_DIR}/cep/silver_cep.py >> /var/log/silver-cep.log 2>&1 &
    CEP_PID=$!
    echo "$CEP_PID" > /var/run/silver-cep.pid
    ok "Pathway CEP engine started (PID=$CEP_PID)"
}

# ── Phase 5: Status dashboard ─────────────────────────────────────────────
phase5_status() {
    info "Phase 5: Status & verification"
    
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "  Silver Sandbox Telemetry — Status"
    echo "════════════════════════════════════════════════════════════════"
    
    check_pid() {
        local name=$1 pidfile=$2
        if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
            ok "$name running (PID=$(cat "$pidfile"))"
        else
            fail "$name not running"
        fi
    }
    
    check_pid "DAMON collector" "/var/run/damon-collector.pid"
    check_pid "nDPI classifier" "/var/run/ndpi-classify.pid"
    check_pid "Silver eBPF"     "/var/run/silver.pid"
    [ -f /var/run/bpf-counter.pid ] && check_pid "BPF flow counter" "/var/run/bpf-counter.pid"
    check_pid "Pathway CEP"     "/var/run/silver-cep.pid"
    
    echo ""
    echo "  Log files:"
    for f in /var/log/silver.log /var/log/ndpi-flows.jsonl /var/log/damon-events.jsonl \
             /var/log/bpf-flows.jsonl /var/log/silver-alerts.jsonl /var/log/silver-cep.log; do
        if [ -f "$f" ]; then
            SIZE=$(stat -c%s "$f" 2>/dev/null || echo "0")
            echo "    $f (${SIZE} bytes)"
        fi
    done
    
    echo ""
    echo "  Quick commands:"
    echo "    tail -f /var/log/silver-alerts.jsonl    # Live alerts"
    echo "    tail -f /var/log/ndpi-flows.jsonl       # Network flows"
    echo "    tail -f /var/log/damon-events.jsonl     # Memory patterns"
    echo "    jq . /var/log/silver-alerts.jsonl       # Pretty alerts"
    echo "    silver-status                            # This summary"
    echo "════════════════════════════════════════════════════════════════"
}

# ── Install helper commands ───────────────────────────────────────────────
install_helpers() {
    cat > /usr/local/bin/silver-status << 'STATUS'
#!/bin/bash
echo "=== Silver Sandbox Telemetry Status ==="
for pid_file in /var/run/damon-collector.pid /var/run/ndpi-classify.pid /var/run/silver.pid /var/run/bpf-counter.pid /var/run/silver-cep.pid; do
    name=$(basename "$pid_file" .pid)
    if [ -f "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
        echo "[✓] $name (PID=$(cat "$pid_file"))"
    else
        echo "[✗] $name (not running)"
    fi
done
echo ""
echo "=== Recent Alerts ==="
tail -5 /var/log/silver-alerts.jsonl 2>/dev/null | jq . 2>/dev/null || echo "No alerts yet"
echo ""
echo "=== Flow Stats ==="
wc -l /var/log/ndpi-flows.jsonl /var/log/bpf-flows.jsonl /var/log/damon-events.jsonl 2>/dev/null || echo "No data yet"
STATUS
    chmod +x /usr/local/bin/silver-status
    
    cat > /usr/local/bin/silver-stop << 'STOP'
#!/bin/bash
echo "Stopping Silver telemetry stack..."
for pid_file in /var/run/damon-collector.pid /var/run/ndpi-classify.pid /var/run/silver.pid /var/run/bpf-counter.pid /var/run/silver-cep.pid; do
    if [ -f "$pid_file" ]; then
        kill "$(cat "$pid_file")" 2>/dev/null && echo "Stopped $(basename "$pid_file" .pid)" || true
        rm -f "$pid_file"
    fi
done
echo "All Silver components stopped."
STOP
    chmod +x /usr/local/bin/silver-stop
    
    ok "Helper commands installed: silver-status, silver-stop"
}

# ── Main ──────────────────────────────────────────────────────────────────
main() {
    banner
    
    START_TIME=$(date +%s)
    
    mkdir -p "$SILVER_DIR"
    
    phase0_fingerprint
    phase1_deps
    phase2_damon
    phase3_ebpf
    phase4_pathway
    install_helpers
    phase5_status
    
    END_TIME=$(date +%s)
    ELAPSED=$((END_TIME - START_TIME))
    
    echo ""
    ok "Bootstrap complete in ${ELAPSED}s"
    ok "All telemetry flowing → /var/log/silver-*.jsonl"
    ok "Run 'silver-status' for component health"
}

main "$@"

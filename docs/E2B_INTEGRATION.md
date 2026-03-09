# Silver E2B Integration Guide

## Overview

Deploy Silver eBPF network accountability into E2B sandboxes for full packet→process correlation across all containers, with zero-copy AF_XDP DPI and L7 protocol classification.

## Architecture: Host-Side vs In-MicroVM

E2B's Firecracker isolation gives two deployment options:

### Option A: In-MicroVM (Current Implementation)

eBPF programs run inside the E2B sandbox kernel:

```
┌────────────────────────────────────────────────────┐
│  E2B Sandbox (Firecracker microVM)                  │
│  ┌──────────────────────────────────────────────┐  │
│  │  Kernel 6.1 (shared by all containers)       │  │
│  │  ┌────────────────────────────────────────┐  │  │
│  │  │  Silver eBPF Programs                   │  │  │
│  │  │  • cgroup/sock_create (PID capture)     │  │  │
│  │  │  • cgroup/connect4 (flow seed)          │  │  │
│  │  │  • sock_ops (TCP lifecycle)             │  │  │
│  │  │  • XDP generic (packet classify)        │  │  │
│  │  │  • XSKMAP → AF_XDP (L7 DPI)             │  │  │
│  │  └────────────────────────────────────────┘  │  │
│  │  ┌────────────────────────────────────────┐  │  │
│  │  │  Shared BPF Maps                        │  │  │
│  │  │  • proc_by_cookie (PID→socket)          │  │  │
│  │  │  • flow_table (5-tuple→process+L7)      │  │  │
│  │  │  • dns_cache (IP→domain)                │  │  │
│  │  └────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────┐  │
│  │  User Space                                   │  │
│  │  • Silver daemon (AF_XDP consumer + nDPI)    │  │
│  │  • Docker containers (tracked)               │  │
│  └──────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────┘
```

**Pros**: Full visibility into all container traffic from one attach point  
**Cons**: User with `CAP_SYS_MODULE` can disable/bypass eBPF layer

### Option B: Host-Side TAP (Defense-in-Depth)

eBPF programs attach to the Firecracker TAP device on the host:

```
┌────────────────────────────────────────────────────┐
│  Firecracker Host                                   │
│  ┌────────────────────────────────────────────┐  │
│  │  tap0 (microVM network)                       │  │
│  │  ▲                                            │  │
│  │  │ XDP/TC attach here (outside guest reach)  │  │
│  │  └────────────────────────────────────────────┘  │
│  │  Silver control plane (untrusted user can't   │  │
│  │  modify or observe this enforcement point)    │  │
│  └────────────────────────────────────────────┘  │
│         ▲                                           │
│         │ All packets flow through TAP             │
│         ▼                                           │
│  ┌────────────────────────────────────────────┐  │
│  │  E2B Sandbox microVM (untrusted)              │  │
│  │  User cannot bypass host-side eBPF            │  │
│  └────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────┘
```

**Pros**: Enforcement outside attacker control  
**Cons**: No in-VM process context (PID, comm) — must correlate via DNS/SNI/IP

## Dockerfile for E2B Template

Create `Dockerfile.e2b-silver`:

```dockerfile
FROM ghcr.io/e2b-dev/code-interpreter:latest

# Install eBPF dependencies
RUN apt-get update && apt-get install -y \
    clang-17 libbpf-dev bpftool \
    linux-headers-generic \
    ca-certificates wget

# Install Sliver client
RUN wget https://github.com/BishopFox/sliver/releases/download/v1.7.3/sliver-client_linux \
    -O /usr/local/bin/sliver-client && \
    chmod +x /usr/local/bin/sliver-client

# Download Silver extension from GitHub Release
RUN mkdir -p /opt/silver && \
    wget https://github.com/pv-udpv/sliver-ebpf-silver/releases/latest/download/silver-extension.tar.gz \
    -O /tmp/silver.tar.gz && \
    tar xzf /tmp/silver.tar.gz -C /opt/silver && \
    rm /tmp/silver.tar.gz

# Download Silver-nDPI extension
RUN mkdir -p /opt/silver-ndpi && \
    wget https://github.com/pv-udpv/sliver-ebpf-silver/releases/latest/download/silver-ndpi-extension.tar.gz \
    -O /tmp/silver-ndpi.tar.gz && \
    tar xzf /tmp/silver-ndpi.tar.gz -C /opt/silver-ndpi && \
    rm /tmp/silver-ndpi.tar.gz

# Add startup script
COPY silver-startup.sh /etc/e2b/startup.d/50-silver.sh
RUN chmod +x /etc/e2b/startup.d/50-silver.sh

WORKDIR /home/user
```

## Startup Script

`silver-startup.sh` (auto-runs on E2B sandbox start):

```bash
#!/bin/bash
set -e

ARCH=$(uname -m)
SILVER_SO="/opt/silver/silver-plugin-linux-${ARCH}"
SILVER_NDPI_SO="/opt/silver-ndpi/silver-ndpi-plugin-linux-${ARCH}"

# Check kernel requirements
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "[Silver] Warning: BTF not available, using non-CO-RE fallback"
fi

# Load Silver core (cgroup + sock_ops + XDP)
if [ -x "$SILVER_SO" ]; then
    echo "[Silver] Starting core eBPF layer..."
    "$SILVER_SO" start &
    SILVER_PID=$!
    echo $SILVER_PID > /var/run/silver.pid
else
    echo "[Silver] Error: Binary not found at $SILVER_SO"
    exit 1
fi

# Wait for BPF programs to attach
sleep 2

# Load Silver-nDPI (AF_XDP + L7 DPI)
if [ -x "$SILVER_NDPI_SO" ] && [ "$(cat /proc/sys/net/core/bpf_jit_enable)" = "1" ]; then
    echo "[Silver-nDPI] Starting L7 DPI engine..."
    "$SILVER_NDPI_SO" start &
    SILVER_NDPI_PID=$!
    echo $SILVER_NDPI_PID > /var/run/silver-ndpi.pid
fi

# Verify attach
if bpftool prog show | grep -q silver; then
    echo "[Silver] ✓ BPF programs loaded"
    bpftool prog show | grep silver
else
    echo "[Silver] ✗ BPF attach failed"
    exit 1
fi

# Export gRPC endpoint for telemetry
export SILVER_GRPC_ADDR="127.0.0.1:50052"
echo "[Silver] gRPC telemetry: $SILVER_GRPC_ADDR"
```

## E2B SDK Usage

Once the template is built, start a sandbox with Silver pre-loaded:

```python
from e2b import Sandbox

sandbox = Sandbox(template="e2b-silver")

# Silver is already running — query flows via gRPC or exec
result = sandbox.commands.run("silver flows")
print(result.stdout)  # All tracked flows with PID, comm, L7 proto

# Query DNS cache
result = sandbox.commands.run("silver dns 8.8.8.8")
print(result.stdout)  # Observed domains for this IP

# Real-time event stream
proc = sandbox.commands.start("silver stream --l7 HTTP")
for line in proc.stdout:
    print(f"[Event] {line}")  # Live HTTP flow events

sandbox.close()
```

## Sliver C2 Integration

For red-team/post-exploitation use, load Silver as a Sliver extension:

```bash
# On Sliver server
armory add https://raw.githubusercontent.com/pv-udpv/sliver-ebpf-silver/main/armory-index.json
armory install Silver
armory install Silver-nDPI

# In an active Linux implant session
sliver (TARGET) > silver start
sliver (TARGET) > silver-ndpi start
sliver (TARGET) > silver flows --pid 1234
sliver (TARGET) > silver stream --l7 TLS
```

## Performance & Resource Usage

| Metric | Value | Notes |
|--------|-------|-------|
| CPU overhead | 0.5–2% | XDP + cgroup hooks are negligible |
| Memory (core) | ~8 MB | BPF maps + flow tracker |
| Memory (nDPI) | ~50 MB | Protocol signatures + flow state |
| Packet loss | 0% | XDP generic mode, no drops observed |
| Flow table size | 10,000 entries | LRU eviction after 300s TTL |

## Security Considerations

### Privilege Escalation Paths

E2B sandboxes with `CAP_SYS_MODULE` + `/dev/mem` expose kernel modification:

- User can unload eBPF programs via `bpftool prog detach`
- User can load malicious kernel module to hook BPF syscall
- User can write to `/dev/mem` to patch kernel `.text` segment

**Mitigation**: Deploy Silver on host-side TAP (Option B) for untrusted workloads.

### Container Escape

Silver tracks Docker-in-Docker via `bpf_get_current_cgroup_id()`:

- Each container has unique cgroup ID (mapped to Docker container ID)
- Silver logs all network events with cgroup ID → full audit trail
- If container escapes (exploit), new processes inherit host cgroup → visible in logs

### DNS Spoofing

Silver's `dns_cache` trusts observed DNS answers:

- Attacker can poison cache via fake UDP/53 responses
- Mitigation: validate DNS via DNSSEC or upstream resolver logs

## Troubleshooting

### "Operation not permitted" on BPF attach

```bash
# Check capabilities
capsh --print | grep cap_bpf

# Grant CAP_BPF + CAP_NET_ADMIN
sudo setcap cap_bpf,cap_net_admin+ep /opt/silver/silver-plugin-linux-amd64
```

### XDP attach fails: "Device or resource busy"

Another XDP program is already attached. List and detach:

```bash
ip link show eth0 | grep xdp
sudo ip link set dev eth0 xdp off
```

### TC attach fails: "No such device"

Kernel missing `CONFIG_NET_SCH_INGRESS` or `CONFIG_NET_CLS_BPF`:

```bash
zcat /proc/config.gz | grep SCH_INGRESS
# If =n, TC programs won't attach (XDP + cgroup still work)
```

### nDPI not detecting protocols

Check sampling config:

```bash
silver-ndpi config ports 80,443,53,22,8080  # Add ports to always-redirect
silver-ndpi config sample 10                # Sample 1-in-10 of remaining traffic
```

## OpenAPI Telemetry Integration

Silver exposes a gRPC server (port 50052) with OpenAPI v3.1 spec:

```bash
# Query flows with filters
curl http://localhost:50052/api/v1/flows?pid=1234&proto=TCP

# Get DNS reverse cache
curl http://localhost:50052/api/v1/dns/8.8.8.8

# Real-time event stream (SSE)
curl -N http://localhost:50052/api/v1/events/stream
```

Full spec: `https://raw.githubusercontent.com/pv-udpv/sliver-ebpf-silver/main/openapi-v3.yaml`

## References

- E2B Docs: https://e2b.dev/docs
- Sliver C2: https://github.com/BishopFox/sliver
- Cilium eBPF: https://github.com/cilium/ebpf
- nDPI: https://github.com/ntop/nDPI
- Silver Repo: https://github.com/pv-udpv/sliver-ebpf-silver

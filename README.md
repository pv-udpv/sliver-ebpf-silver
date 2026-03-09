# Silver — eBPF Network Accountability Plugin for Sliver C2

> **Every packet in, every packet out — classified and correlated to the originating process, protocol used, purpose, and target. No dark corners.**

Silver is a [Sliver C2](https://github.com/BishopFox/sliver) extension that provides **full kernel-level network visibility** via eBPF. It runs as a post-exploitation module on Linux targets, giving operators real-time flow attribution with zero user-space packet capture overhead.

## How It Works

Silver deploys **6 eBPF programs** sharing **7 BPF maps** to correlate packets across the entire kernel networking stack:

```
┌─────────────────────────────────────────────────────────────┐
│                     USERSPACE                                │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │ Sliver       │  │ Silver gRPC  │  │ Policy Control     │  │
│  │ Implant      │←→│ Server       │←→│ Plane              │  │
│  │ (extension)  │  │ :50052       │  │ (rules, stats)     │  │
│  └─────────────┘  └──────┬───────┘  └────────────────────┘  │
│                          │ ringbuf                            │
├──────────────────────────┼──────────────────────────────────┤
│                     KERNEL (eBPF)                             │
│                          │                                    │
│  ┌───────────────┐  ┌───┴───────────┐  ┌─────────────────┐  │
│  │ cgroup/       │  │  sock_ops     │  │ XDP (ingress)   │  │
│  │ sock_create   │  │  TCP lifecycle│  │ fast classify   │  │
│  │ connect4      │  │  SYN→EST→FIN │  │ flow_table      │  │
│  └───────┬───────┘  └───────┬───────┘  └────────┬────────┘  │
│          │                  │                    │            │
│          └──────────┬───────┘                    │            │
│                     ▼                            │            │
│  ┌─────────────────────────────────────┐        │            │
│  │          SHARED BPF MAPS            │←───────┘            │
│  │  proc_by_cookie  │  flow_table      │                     │
│  │  dns_cache       │  decision_stats  │  ┌───────────────┐  │
│  │  policy_rules    │  events (ring)   │  │ TC ingress    │  │
│  │  policy_count    │                  │  │ L7 detect     │  │
│  └─────────────────────────────────────┘  │ cookie join   │  │
│                                           ├───────────────┤  │
│                                           │ TC egress     │  │
│                                           │ egress acct   │  │
│                                           └───────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Integration with Sliver C2

Silver is designed as a **Sliver extension** that gets reflectively loaded into the implant process on Linux targets. It follows the [Sliver Extensions manifest format](https://github.com/BishopFox/sliver/wiki/Aliases-&-Extensions).

See `extension.json` for the full manifest.

### Operator Commands

Once loaded in a Sliver session:

```
sliver (TARGET) > silver flows              # List all tracked flows with process attribution
sliver (TARGET) > silver flows --pid 1234   # Filter by PID
sliver (TARGET) > silver stream             # Real-time event stream
sliver (TARGET) > silver stream --l7 HTTP   # Stream only HTTP events
sliver (TARGET) > silver stats              # Aggregate stats per-process
sliver (TARGET) > silver stats --by target  # Stats grouped by destination
sliver (TARGET) > silver dns 10.0.0.5       # Reverse-resolve IP to observed DNS name
sliver (TARGET) > silver policy add --deny --dst 198.51.100.0/24  # Block subnet
```

## File Structure

```
├── bpf/
│   ├── silver_types.h     # Shared BPF structs and enums
│   └── silver.bpf.c       # All 6 eBPF programs in one compilation unit
├── proto/
│   └── network.proto       # gRPC service definition
├── cmd/
│   └── silver_loader.go    # Go loader: open → load → attach → serve → cleanup
├── scripts/
│   └── silver-startup.sh   # Startup hook for E2B/container deployment
├── extension.json          # Sliver extension manifest
├── silver-plugin.skill.md  # agentskills.io skill manifest
├── Makefile                # Build system
└── README.md
```

## The 6 BPF Programs

| # | Program | Hook Type | Attach Point | Purpose |
|---|---------|-----------|--------------|--------|
| 1 | `silver_sock_create` | `cgroup/sock_create` | Root cgroup | Capture PID, comm, cgroup at socket birth |
| 2 | `silver_connect4` | `cgroup/connect4` | Root cgroup | Record outbound connection intent + seed flow_table |
| 3 | `silver_sock_ops` | `sockops` | Root cgroup | TCP lifecycle: SYN→ESTABLISHED→FIN state tracking |
| 4 | `silver_xdp` | `xdp` | eth0 | Fast-path ingress classify, flow_table lookup by 5-tuple |
| 5 | `silver_tc_ingress` | `tc/ingress` | eth0 clsact | Socket cookie join after demux + L7 protocol detection |
| 6 | `silver_tc_egress` | `tc/egress` | eth0 clsact | Egress accounting for complete bidirectional flow tracking |

## The 7 Shared Maps

| Map | Type | Key → Value | Purpose |
|-----|------|------------|--------|
| `proc_by_cookie` | HASH | socket_cookie → proc_identity | Join packets to processes via cookie |
| `flow_table` | LRU_HASH | 5-tuple → flow_value | Full flow state with process, protocol, counters |
| `dns_cache` | LRU_HASH | dst_ip → dns_entry | Reverse IP→domain from observed DNS |
| `decision_stats` | PERCPU_HASH | reason → counters | Always-on aggregate packet/byte stats |
| `events` | RINGBUF | — → net_event | Structured event export to userspace |
| `policy_rules` | ARRAY | index → policy_rule | Runtime allow/deny/sample rules |
| `policy_count` | ARRAY | 0 → count | Active rule count |

## L7 Protocol Detection

Silver detects application protocols in-kernel at TC hook:

- **HTTP** — `GET `, `POST`, `PUT `, `HTTP` prefix in first 4 payload bytes
- **SSH** — `SSH-` prefix
- **TLS** — Content type `0x16` + handshake type `0x01` (ClientHello)
- **DNS** — Port 53 traffic (UDP/TCP)
- **gRPC** — HTTP/2 magic prefix + gRPC content-type (planned)

## Build

```bash
# Prerequisites: clang >= 14, bpftool, protoc, go >= 1.21
make all

# Or step by step:
make bpf          # Compile BPF C → silver.bpf.o
make proto         # Generate Go protobuf code
make go            # Build the Go binary
```

## Requirements

- Linux kernel >= 5.15 with BTF enabled
- `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN` capabilities
- Root cgroup v2 mounted at `/sys/fs/cgroup`

## Research Context

This plugin was developed as part of ongoing E2B sandbox security research. The architecture covers:

- Multi-layer eBPF hook correlation (XDP has no process context, cgroup hooks have no packets)
- Socket cookie as the universal join key between kernel subsystems
- Pre-existing socket gap mitigation via `/proc/net/tcp` seeding
- TC ingress socket cookie NULL before demux — fallback to 5-tuple lookup
- Production validation against Tetragon, Pixie, ntopng/libebpfflow, Cilium conntrack

## License

GPL-2.0 OR BSD-2-Clause (BPF programs) / MIT (userspace code)

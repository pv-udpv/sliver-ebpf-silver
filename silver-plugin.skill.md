---
name: silver-network-plugin
version: 0.1.0
description: >
  Silver — Full packet accountability plugin for Sliver C2 / E2B sandboxes.
  Correlates every packet in/out to the originating process, protocol used,
  purpose, and target. No dark corners. Implemented as a Sliver extension
  backed by 6 eBPF programs sharing 7 BPF maps.
author: pv-udpv
tags: [ebpf, network, security, sliver, c2, observability, e2b, sandbox, grpc]
requires:
  - linux-kernel: ">=5.15"
  - btf: true
  - capabilities: [CAP_BPF, CAP_NET_ADMIN, CAP_SYS_ADMIN]
  - tools: [clang, bpftool, protoc, go]

components:
  bpf_programs:
    - name: silver_sock_create
      type: cgroup/sock_create
      attach: /sys/fs/cgroup
      purpose: Capture process identity (PID, comm, cgroup) at socket birth
      
    - name: silver_connect4
      type: cgroup/connect4
      attach: /sys/fs/cgroup
      purpose: Record outbound connection intent with destination and process

    - name: silver_sock_ops
      type: sockops
      attach: /sys/fs/cgroup
      purpose: Track TCP lifecycle (SYN, ESTABLISHED, FIN) with state callbacks

    - name: silver_xdp
      type: xdp
      attach: ${SILVER_IFACE:-eth0}
      purpose: Fast-path ingress packet classification and flow table lookup

    - name: silver_tc_ingress
      type: tc/ingress
      attach: ${SILVER_IFACE:-eth0}
      purpose: Post-demux socket cookie join and L7 protocol detection

    - name: silver_tc_egress
      type: tc/egress
      attach: ${SILVER_IFACE:-eth0}
      purpose: Egress accounting mirror for complete bidirectional flow tracking

  bpf_maps:
    - name: proc_by_cookie
      type: HASH
      key: __u64 (socket cookie)
      value: cookie_proc {proc_identity, created_ns}
      
    - name: flow_table
      type: LRU_HASH
      key: flow5_key (5-tuple + direction)
      value: flow_value {proc, cookie, l7, state, counters, dns_name, tls_sni}

    - name: dns_cache
      type: LRU_HASH
      key: __u32 (dst IPv4)
      value: dns_entry {qname, ttl, observed_ns}

    - name: decision_stats
      type: PERCPU_HASH
      key: stats_key {reason}
      value: stats_value {packets, bytes}

    - name: events
      type: RINGBUF
      size: 256KB
      purpose: Structured event export to userspace gRPC server

    - name: policy_rules
      type: ARRAY
      purpose: Runtime-loadable allow/deny/sample rules from control plane

    - name: policy_count
      type: ARRAY
      purpose: Track number of active policy rules

  grpc_service:
    proto: proto/network.proto
    package: network
    rpcs:
      - StreamEvents (server-streaming)
      - ListFlows (unary)
      - GetFlow (unary)
      - GetStats (unary)
      - SetPolicy (unary)
      - GetPolicy (unary)
      - ResolveDNS (unary)

lifecycle:
  startup: scripts/silver-startup.sh
  build: make all
  env:
    SILVER_IFACE: eth0
    SILVER_GRPC_ADDR: "0.0.0.0:50052"

integration:
  sliver_c2:
    manifest: extension.json
    command: silver
    subcommands: [flows, stream, stats, dns, policy]
  envd:
    port: 50052
    health: /health via gRPC health check
---

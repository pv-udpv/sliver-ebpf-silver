// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
// silver_xsk.bpf.c — XDP with AF_XDP redirect for L7 DPI via nDPI
//
// Replaces TC ingress/egress for L7 classification.
// Interesting packets are redirected to AF_XDP socket for user-space nDPI processing.
// Non-interesting packets pass through with L4 flow accounting only.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "silver_types.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Shared maps (pinned, reused from silver.bpf.c via MapReplacements)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, FLOW_TABLE_SIZE);
    __type(key,   struct flow5_key);
    __type(value, struct flow_value);
} flow_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PROC_TABLE_SIZE);
    __type(key,   __u64);
    __type(value, struct cookie_proc);
} proc_by_cookie SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 256);
    __type(key,   struct stats_key);
    __type(value, struct stats_value);
} decision_stats SEC(".maps");

// XSKMAP for AF_XDP socket redirect
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key,   __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

// Configuration: which ports trigger DPI redirect
#define XSK_CFG_MAX 64
struct xsk_cfg_entry {
    __u16 port;
    __u16 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, XSK_CFG_MAX);
    __type(key,   __u32);
    __type(value, struct xsk_cfg_entry);
} xsk_dpi_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u32);
} xsk_sample_rate SEC(".maps");

static __always_inline void bump_stats(__u32 reason, __u64 bytes)
{
    struct stats_key sk = { .reason = reason };
    struct stats_value *sv = bpf_map_lookup_elem(&decision_stats, &sk);
    if (sv) {
        sv->packets += 1;
        sv->bytes   += bytes;
    } else {
        struct stats_value new_sv = { .packets = 1, .bytes = bytes };
        bpf_map_update_elem(&decision_stats, &sk, &new_sv, BPF_NOEXIST);
    }
}

static __always_inline int should_redirect(__u16 sport, __u16 dport)
{
    #pragma unroll
    for (__u32 i = 0; i < XSK_CFG_MAX; i++) {
        struct xsk_cfg_entry *e = bpf_map_lookup_elem(&xsk_dpi_ports, &i);
        if (!e || e->port == 0)
            return 0;
        if (e->port == sport || e->port == dport)
            return 1;
    }
    return 0;
}

SEC("xdp")
int silver_xsk_xdp(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct flow5_key key = {};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.direction = DIR_INGRESS;
    __u32 pkt_len = data_end - data;
    __u16 sport = 0, dport = 0;

    if (ip->protocol == IPPROTO_TCP) {
        key.l4_proto = L4_TCP;
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);
        key.src_port = sport;
        key.dst_port = dport;
    } else if (ip->protocol == IPPROTO_UDP) {
        key.l4_proto = L4_UDP;
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        sport = bpf_ntohs(udp->source);
        dport = bpf_ntohs(udp->dest);
        key.src_port = sport;
        key.dst_port = dport;
    } else if (ip->protocol == IPPROTO_ICMP) {
        key.l4_proto = L4_ICMP;
    } else {
        return XDP_PASS;
    }

    // Update flow_table counters
    struct flow_value *fv = bpf_map_lookup_elem(&flow_table, &key);
    if (fv) {
        fv->packets_in += 1;
        fv->bytes_in   += pkt_len;
        fv->last_seen_ns = bpf_ktime_get_ns();
    }

    bump_stats(key.l4_proto, pkt_len);

    // Decide: redirect to AF_XDP for DPI or pass
    int redirect = should_redirect(sport, dport);

    if (!redirect) {
        // Sampling fallback: check sample rate
        __u32 zero = 0;
        __u32 *rate = bpf_map_lookup_elem(&xsk_sample_rate, &zero);
        if (rate && *rate > 0) {
            __u32 rand = bpf_get_prandom_u32();
            if ((rand % *rate) == 0)
                redirect = 1;
        }
    }

    if (redirect)
        return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);

    return XDP_PASS;
}

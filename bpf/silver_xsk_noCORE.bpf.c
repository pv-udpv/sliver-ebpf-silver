// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
// silver_xsk_noCORE.bpf.c — XDP program with XSKMAP redirect for nDPI
//
// Non-CO-RE version for kernels without BTF.
// Compile:
//   ln -sf bpf/vmlinux_shim.h vmlinux.h
//   clang -O2 -target bpf -D__TARGET_ARCH_x86 -I. -Ibpf \
//     -I/usr/include -g0 -c bpf/silver_xsk_noCORE.bpf.c -o silver_xsk.bpf.o
//
// This XDP program redirects interesting packets (by port) to an AF_XDP
// socket for user-space nDPI classification, while passing the rest.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "silver_types.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* AF_XDP socket map — user-space creates XSK and inserts fd here */
struct { __uint(type, BPF_MAP_TYPE_XSKMAP); __uint(max_entries, 64);
    __type(key, __u32); __type(value, __u32); } xsk_map SEC(".maps");

/* Configuration: which ports to redirect for DPI */
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 256);
    __type(key, __u16); __type(value, __u8); } xsk_ports SEC(".maps");

/* Sampling config: 1 = redirect every Nth non-port-matched packet */
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, __u32); } xsk_sample_rate SEC(".maps");

/* Packet counter for sampling */
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, __u64); } xsk_pkt_counter SEC(".maps");

SEC("xdp")
int silver_xsk_redirect(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    __u16 src_port = 0, dst_port = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end) return XDP_PASS;
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
    } else {
        return XDP_PASS;
    }

    /* Check if either port is in the DPI-redirect set */
    int redirect = 0;
    if (bpf_map_lookup_elem(&xsk_ports, &dst_port) ||
        bpf_map_lookup_elem(&xsk_ports, &src_port)) {
        redirect = 1;
    }

    /* Sampling fallback for non-matched ports */
    if (!redirect) {
        __u32 zero = 0;
        __u32 *rate = bpf_map_lookup_elem(&xsk_sample_rate, &zero);
        __u64 *cnt  = bpf_map_lookup_elem(&xsk_pkt_counter, &zero);
        if (rate && cnt && *rate > 0) {
            *cnt += 1;
            if ((*cnt % *rate) == 0)
                redirect = 1;
        }
    }

    if (redirect)
        return bpf_redirect_map(&xsk_map, ctx->rx_queue_index, XDP_PASS);

    return XDP_PASS;
}

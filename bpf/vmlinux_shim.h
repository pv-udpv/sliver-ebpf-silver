// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
// vmlinux_shim.h — Complete vmlinux replacement for kernels without BTF
// Use: cp bpf/vmlinux_shim.h vmlinux.h   (or symlink)
//
// Provides all types needed by Silver BPF programs when
// /sys/kernel/btf/vmlinux is not available (CONFIG_DEBUG_INFO_BTF=n).

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
enum { false = 0, true = 1 };
typedef _Bool bool;

/* ---- BPF map types ---- */
enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PROG_ARRAY = 3,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_MAP_TYPE_PERCPU_HASH = 5,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_STACK_TRACE = 7,
    BPF_MAP_TYPE_CGROUP_ARRAY = 8,
    BPF_MAP_TYPE_LRU_HASH = 9,
    BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
    BPF_MAP_TYPE_LPM_TRIE = 11,
    BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
    BPF_MAP_TYPE_HASH_OF_MAPS = 13,
    BPF_MAP_TYPE_DEVMAP = 14,
    BPF_MAP_TYPE_SOCKMAP = 15,
    BPF_MAP_TYPE_CPUMAP = 16,
    BPF_MAP_TYPE_XSKMAP = 17,
    BPF_MAP_TYPE_SOCKHASH = 18,
    BPF_MAP_TYPE_CGROUP_STORAGE = 19,
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
    BPF_MAP_TYPE_QUEUE = 22,
    BPF_MAP_TYPE_STACK = 23,
    BPF_MAP_TYPE_SK_STORAGE = 24,
    BPF_MAP_TYPE_DEVMAP_HASH = 25,
    BPF_MAP_TYPE_STRUCT_OPS = 26,
    BPF_MAP_TYPE_RINGBUF = 27,
};

/* ---- BPF map update flags ---- */
#define BPF_ANY       0
#define BPF_NOEXIST   1
#define BPF_EXIST     2

/* ---- Socket types ---- */
#define SOCK_STREAM 1
#define SOCK_DGRAM  2

/* ---- BPF TCP states ---- */
enum {
    BPF_TCP_ESTABLISHED = 1,
    BPF_TCP_SYN_SENT,
    BPF_TCP_SYN_RECV,
    BPF_TCP_FIN_WAIT1,
    BPF_TCP_FIN_WAIT2,
    BPF_TCP_TIME_WAIT,
    BPF_TCP_CLOSE,
    BPF_TCP_CLOSE_WAIT,
    BPF_TCP_LAST_ACK,
    BPF_TCP_LISTEN,
    BPF_TCP_CLOSING,
    BPF_TCP_NEW_SYN_RECV,
    BPF_TCP_MAX_STATES,
};

/* ---- Network protocol numbers ---- */
#define ETH_P_IP     0x0800
#define ETH_P_IPV6   0x86DD
#define IPPROTO_TCP  6
#define IPPROTO_UDP  17
#define IPPROTO_ICMP 1

/* ---- XDP return codes ---- */
#define XDP_ABORTED  0
#define XDP_DROP     1
#define XDP_PASS     2
#define XDP_TX       3
#define XDP_REDIRECT 4

/* ---- TC return codes ---- */
#define TC_ACT_OK    0
#define TC_ACT_SHOT  2
#define TC_ACT_UNSPEC (-1)

/* ---- sock_ops callbacks ---- */
#define BPF_SOCK_OPS_TCP_CONNECT_CB           3
#define BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB    4
#define BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB   5
#define BPF_SOCK_OPS_TCP_LISTEN_CB            11
#define BPF_SOCK_OPS_STATE_CB                 16
#define BPF_SOCK_OPS_STATE_CB_FLAG            (1U << 4)

/* ---- Network headers ---- */
struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
} __attribute__((packed));

struct iphdr {
    __u8 ihl:4, version:4;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __u16 check;
    __be32 saddr;
    __be32 daddr;
};

struct tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u16 res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
    __be16 window;
    __u16 check;
    __be16 urg_ptr;
};

struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __u16 check;
};

/* ---- BPF context structs ---- */
struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

struct __sk_buff {
    __u32 len; __u32 pkt_type; __u32 mark; __u32 queue_mapping;
    __u32 protocol; __u32 vlan_present; __u32 vlan_tci; __u32 vlan_proto;
    __u32 priority; __u32 ingress_ifindex; __u32 ifindex; __u32 tc_index;
    __u32 cb[5]; __u32 hash; __u32 tc_classid;
    __u32 data; __u32 data_end;
    __u32 napi_id; __u32 family;
    __u32 remote_ip4; __u32 local_ip4;
    __u32 remote_ip6[4]; __u32 local_ip6[4];
    __u32 remote_port; __u32 local_port;
    __u32 data_meta; __u64 tstamp; __u32 wire_len; __u32 gso_segs;
    __u64 sk; __u32 gso_size;
};

struct bpf_sock {
    __u32 bound_dev_if; __u32 family; __u32 type; __u32 protocol;
    __u32 mark; __u32 priority;
    __u32 src_ip4; __u32 src_ip6[4]; __u32 src_port;
    __be32 dst_ip4; __u32 dst_ip6[4]; __u32 dst_port;
    __u32 state; __s32 rx_queue_mapping;
};

struct bpf_sock_addr {
    __u32 user_family; __u32 user_ip4; __u32 user_ip6[4]; __u32 user_port;
    __u32 family; __u32 type; __u32 protocol;
    __u32 msg_src_ip4; __u32 msg_src_ip6[4];
};

struct bpf_sock_ops {
    __u32 op;
    union { __u32 args[4]; __u32 reply; __u32 replylong[4]; };
    __u32 family;
    __u32 remote_ip4; __u32 local_ip4;
    __u32 remote_ip6[4]; __u32 local_ip6[4];
    __u32 remote_port; __u32 local_port;
    __u32 is_fullsock; __u32 snd_cwnd; __u32 srtt_us;
    __u32 bpf_sock_ops_cb_flags; __u32 state;
    __u32 rtt_min; __u32 snd_ssthresh;
    __u32 rcv_nxt; __u32 snd_nxt; __u32 snd_una; __u32 mss_cache;
    __u32 ecn_flags; __u32 rate_delivered; __u32 rate_interval_us;
    __u32 packets_out; __u32 retrans_out; __u32 total_retrans;
    __u32 segs_in; __u32 data_segs_in; __u32 segs_out; __u32 data_segs_out;
    __u32 lost_out; __u32 sacked_out;
    __u64 bytes_received; __u64 bytes_acked;
    __u64 sk;
};

struct task_struct {
    int pid;
    int tgid;
    struct task_struct *real_parent;
    char comm[16];
};

#endif

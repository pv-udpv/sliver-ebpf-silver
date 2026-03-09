// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
// silver_types.h — Shared types between all BPF programs and userspace
#ifndef __SILVER_TYPES_H
#define __SILVER_TYPES_H

#include <linux/types.h>

#define TASK_COMM_LEN    16
#define DNS_NAME_MAX     64
#define FLOW_TABLE_SIZE  65536
#define PROC_TABLE_SIZE  8192
#define DNS_CACHE_SIZE   4096
#define POLICY_MAX       1024
#define EVENT_RINGBUF_SIZE (256 * 1024)

enum l4_proto {
    L4_UNKNOWN = 0,
    L4_TCP     = 1,
    L4_UDP     = 2,
    L4_ICMP    = 3,
};

enum l7_proto {
    L7_UNKNOWN   = 0,
    L7_HTTP      = 1,
    L7_HTTPS_TLS = 2,
    L7_DNS       = 3,
    L7_GRPC      = 4,
    L7_SSH       = 5,
};

enum flow_direction {
    DIR_UNKNOWN = 0,
    DIR_INGRESS = 1,
    DIR_EGRESS  = 2,
};

enum flow_state {
    STATE_UNKNOWN     = 0,
    STATE_SYN_SENT    = 1,
    STATE_ESTABLISHED = 2,
    STATE_FIN_WAIT    = 3,
    STATE_CLOSED      = 4,
    STATE_LISTEN      = 5,
};

enum event_type {
    EVT_FLOW_START   = 0,
    EVT_FLOW_DATA    = 1,
    EVT_FLOW_END     = 2,
    EVT_POLICY_HIT   = 3,
    EVT_DNS_QUERY    = 4,
    EVT_DNS_RESPONSE = 5,
    EVT_ANOMALY      = 6,
};

enum policy_action {
    ACT_ALLOW   = 0,
    ACT_DENY    = 1,
    ACT_SAMPLE  = 2,
    ACT_LOG     = 3,
};

struct proc_identity {
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u32 ppid;
    __u64 cgroup_id;
    char  comm[TASK_COMM_LEN];
};

struct flow5_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  l4_proto;
    __u8  direction;
    __u16 _pad;
};

struct flow_value {
    struct proc_identity proc;
    __u64  socket_cookie;
    __u8   l7_proto;
    __u8   state;
    __u16  _pad;
    __u64  packets_in;
    __u64  packets_out;
    __u64  bytes_in;
    __u64  bytes_out;
    __u64  first_seen_ns;
    __u64  last_seen_ns;
    char   dns_name[DNS_NAME_MAX];
    char   tls_sni[DNS_NAME_MAX];
};

struct cookie_proc {
    struct proc_identity proc;
    __u64 created_ns;
};

struct dns_entry {
    char   qname[DNS_NAME_MAX];
    __u32  ttl;
    __u64  observed_ns;
};

struct policy_rule {
    __u32 priority;
    __u8  action;
    __u8  l4_proto;
    __u8  l7_proto;
    __u8  _pad;
    __u32 dst_ip;
    __u32 dst_mask;
    __u16 dst_port;
    __u16 _pad2;
    char  proc_comm[TASK_COMM_LEN];
    __u64 cgroup_id;
};

struct net_event {
    __u8   type;
    __u8   l4_proto;
    __u8   l7_proto;
    __u8   state;
    __u8   direction;
    __u8   action;
    __u16  _pad;
    __u64  timestamp_ns;
    struct proc_identity proc;
    struct flow5_key flow_key;
    __u64  socket_cookie;
    __u64  packets;
    __u64  bytes;
    char   dns_name[DNS_NAME_MAX];
    char   tls_sni[DNS_NAME_MAX];
};

struct stats_key {
    __u32 reason;
};

struct stats_value {
    __u64 packets;
    __u64 bytes;
};

#endif // __SILVER_TYPES_H

// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
// silver.bpf.c — The "Silver" plugin: full packet accountability
//
// 6 BPF programs in one object:
//   1. cgroup/sock_create   → capture process identity at socket birth
//   2. cgroup/connect4      → capture outbound connection intent
//   3. sock_ops             → track connection lifecycle (SYN, ESTABLISHED, FIN)
//   4. xdp                  → fast-path packet classify + flow table lookup
//   5. tc/ingress           → post-demux join via socket cookie + L7 detect
//   6. tc/egress            → egress mirror for complete accounting

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "silver_types.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// MAPS — shared across all 6 programs via BTF-defined map syntax

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PROC_TABLE_SIZE);
    __type(key,   __u64);
    __type(value, struct cookie_proc);
} proc_by_cookie SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, FLOW_TABLE_SIZE);
    __type(key,   struct flow5_key);
    __type(value, struct flow_value);
} flow_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, DNS_CACHE_SIZE);
    __type(key,   __u32);
    __type(value, struct dns_entry);
} dns_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 256);
    __type(key,   struct stats_key);
    __type(value, struct stats_value);
} decision_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, EVENT_RINGBUF_SIZE);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, POLICY_MAX);
    __type(key,   __u32);
    __type(value, struct policy_rule);
} policy_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u32);
} policy_count SEC(".maps");

// HELPERS

static __always_inline void fill_proc_identity(struct proc_identity *p)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    p->pid = pid_tgid >> 32;
    p->tid = (__u32)pid_tgid;
    p->uid = (__u32)uid_gid;
    p->gid = uid_gid >> 32;
    p->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&p->comm, sizeof(p->comm));

    struct task_struct *task = (void *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = NULL;
        BPF_CORE_READ_INTO(&parent, task, real_parent);
        if (parent)
            BPF_CORE_READ_INTO(&p->ppid, parent, tgid);
    }
}

static __always_inline void emit_event(enum event_type type,
    struct proc_identity *proc,
    struct flow5_key *key,
    __u64 cookie,
    __u8 l7, __u8 state, __u8 dir, __u8 action)
{
    struct net_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return;

    evt->type         = type;
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->l4_proto     = key ? key->l4_proto : 0;
    evt->l7_proto     = l7;
    evt->state        = state;
    evt->direction    = dir;
    evt->action       = action;
    evt->socket_cookie = cookie;

    if (proc)
        __builtin_memcpy(&evt->proc, proc, sizeof(evt->proc));
    if (key)
        __builtin_memcpy(&evt->flow_key, key, sizeof(evt->flow_key));

    if (key) {
        struct dns_entry *dns = bpf_map_lookup_elem(&dns_cache, &key->dst_ip);
        if (dns)
            __builtin_memcpy(evt->dns_name, dns->qname, DNS_NAME_MAX);
    }

    bpf_ringbuf_submit(evt, 0);
}

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

// PROGRAM 1: cgroup/sock_create — Process identity at socket birth

SEC("cgroup/sock_create")
int silver_sock_create(struct bpf_sock *sk)
{
    __u64 cookie = bpf_get_socket_cookie(sk);
    struct cookie_proc cp = {};
    fill_proc_identity(&cp.proc);
    cp.created_ns = bpf_ktime_get_ns();

    bpf_map_update_elem(&proc_by_cookie, &cookie, &cp, BPF_ANY);

    return 1;
}

// PROGRAM 2: cgroup/connect4 — Outbound connection intent capture

SEC("cgroup/connect4")
int silver_connect4(struct bpf_sock_addr *ctx)
{
    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct proc_identity proc = {};
    fill_proc_identity(&proc);

    struct flow5_key key = {};
    key.dst_ip    = ctx->user_ip4;
    key.dst_port  = bpf_ntohl(ctx->user_port) >> 16;
    key.l4_proto  = (ctx->type == SOCK_STREAM) ? L4_TCP : L4_UDP;
    key.direction = DIR_EGRESS;

    struct flow_value val = {};
    val.proc = proc;
    val.socket_cookie = cookie;
    val.state = STATE_SYN_SENT;
    val.first_seen_ns = bpf_ktime_get_ns();
    val.last_seen_ns  = val.first_seen_ns;

    struct dns_entry *dns = bpf_map_lookup_elem(&dns_cache, &key.dst_ip);
    if (dns)
        __builtin_memcpy(val.dns_name, dns->qname, DNS_NAME_MAX);

    bpf_map_update_elem(&flow_table, &key, &val, BPF_ANY);

    struct cookie_proc cp = {};
    cp.proc = proc;
    cp.created_ns = val.first_seen_ns;
    bpf_map_update_elem(&proc_by_cookie, &cookie, &cp, BPF_NOEXIST);

    emit_event(EVT_FLOW_START, &proc, &key, cookie,
               L7_UNKNOWN, STATE_SYN_SENT, DIR_EGRESS, ACT_ALLOW);

    return 1;
}

// PROGRAM 3: sock_ops — Connection lifecycle tracking

SEC("sockops")
int silver_sock_ops(struct bpf_sock_ops *skops)
{
    __u32 op = skops->op;
    __u64 cookie = bpf_get_socket_cookie(skops);

    struct flow5_key key = {};
    key.src_ip   = skops->local_ip4;
    key.dst_ip   = skops->remote_ip4;
    key.src_port = skops->local_port;
    key.dst_port = bpf_ntohl(skops->remote_port) >> 16;
    key.l4_proto = L4_TCP;

    switch (op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        key.direction = DIR_EGRESS;
        {
            struct flow_value *fv = bpf_map_lookup_elem(&flow_table, &key);
            if (fv) {
                fv->state = STATE_ESTABLISHED;
                fv->last_seen_ns = bpf_ktime_get_ns();
            }
            struct cookie_proc *cp = bpf_map_lookup_elem(&proc_by_cookie, &cookie);
            struct proc_identity *p = cp ? &cp->proc : NULL;
            emit_event(EVT_FLOW_DATA, p, &key, cookie,
                       L7_UNKNOWN, STATE_ESTABLISHED, DIR_EGRESS, ACT_ALLOW);
        }
        break;

    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        key.direction = DIR_INGRESS;
        {
            struct flow_value val = {};
            struct cookie_proc *cp = bpf_map_lookup_elem(&proc_by_cookie, &cookie);
            if (cp) {
                val.proc = cp->proc;
            } else {
                fill_proc_identity(&val.proc);
            }
            val.socket_cookie = cookie;
            val.state = STATE_ESTABLISHED;
            val.first_seen_ns = bpf_ktime_get_ns();
            val.last_seen_ns  = val.first_seen_ns;
            bpf_map_update_elem(&flow_table, &key, &val, BPF_NOEXIST);
            emit_event(EVT_FLOW_START, &val.proc, &key, cookie,
                       L7_UNKNOWN, STATE_ESTABLISHED, DIR_INGRESS, ACT_ALLOW);
        }
        break;

    case BPF_SOCK_OPS_STATE_CB:
        if (skops->args[1] == BPF_TCP_CLOSE ||
            skops->args[1] == BPF_TCP_CLOSE_WAIT) {
            key.direction = DIR_EGRESS;
            struct flow_value *fv = bpf_map_lookup_elem(&flow_table, &key);
            if (!fv) {
                key.direction = DIR_INGRESS;
                fv = bpf_map_lookup_elem(&flow_table, &key);
            }
            if (fv) {
                fv->state = STATE_CLOSED;
                fv->last_seen_ns = bpf_ktime_get_ns();
                emit_event(EVT_FLOW_END, &fv->proc, &key, cookie,
                           fv->l7_proto, STATE_CLOSED, key.direction, ACT_ALLOW);
            }
        }
        break;
    }

    if (op == BPF_SOCK_OPS_TCP_CONNECT_CB ||
        op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        bpf_sock_ops_cb_flags_set(skops,
            skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_STATE_CB_FLAG);
    }

    return 1;
}

// PROGRAM 4: XDP — Fast-path packet classification

SEC("xdp")
int silver_xdp(struct xdp_md *ctx)
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

    if (ip->protocol == IPPROTO_TCP) {
        key.l4_proto = L4_TCP;
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.src_port = bpf_ntohs(tcp->source);
        key.dst_port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        key.l4_proto = L4_UDP;
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        key.src_port = bpf_ntohs(udp->source);
        key.dst_port = bpf_ntohs(udp->dest);
    } else if (ip->protocol == IPPROTO_ICMP) {
        key.l4_proto = L4_ICMP;
    } else {
        return XDP_PASS;
    }

    struct flow_value *fv = bpf_map_lookup_elem(&flow_table, &key);
    if (fv) {
        fv->packets_in += 1;
        fv->bytes_in   += pkt_len;
        fv->last_seen_ns = bpf_ktime_get_ns();
    }

    bump_stats(key.l4_proto, pkt_len);

    return XDP_PASS;
}

// PROGRAM 5: TC ingress — Post-demux socket cookie join + L7 detect

SEC("tc")
int silver_tc_ingress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    struct flow5_key key = {};
    key.src_ip    = ip->saddr;
    key.dst_ip    = ip->daddr;
    key.direction = DIR_INGRESS;
    __u32 payload_offset = 0;

    if (ip->protocol == IPPROTO_TCP) {
        key.l4_proto = L4_TCP;
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        key.src_port = bpf_ntohs(tcp->source);
        key.dst_port = bpf_ntohs(tcp->dest);
        payload_offset = (void *)tcp - data + (tcp->doff * 4);
    } else if (ip->protocol == IPPROTO_UDP) {
        key.l4_proto = L4_UDP;
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        key.src_port = bpf_ntohs(udp->source);
        key.dst_port = bpf_ntohs(udp->dest);
        payload_offset = (void *)udp - data + sizeof(*udp);
    } else {
        return TC_ACT_OK;
    }

    __u64 cookie = bpf_get_socket_cookie(skb);
    struct cookie_proc *cp = NULL;
    if (cookie)
        cp = bpf_map_lookup_elem(&proc_by_cookie, &cookie);

    struct flow_value *fv = bpf_map_lookup_elem(&flow_table, &key);
    if (fv) {
        fv->last_seen_ns = bpf_ktime_get_ns();

        if (cp && fv->proc.pid == 0)
            fv->proc = cp->proc;

        if (payload_offset > 0 && payload_offset + 7 <= (data_end - data)) {
            __u8 *payload = data + payload_offset;
            if ((void *)(payload + 7) <= data_end) {
                if (payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' && payload[3] == ' ')
                    fv->l7_proto = L7_HTTP;
                else if (payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T')
                    fv->l7_proto = L7_HTTP;
                else if (payload[0] == 'H' && payload[1] == 'T' && payload[2] == 'T' && payload[3] == 'P')
                    fv->l7_proto = L7_HTTP;
                else if (payload[0] == 'S' && payload[1] == 'S' && payload[2] == 'H' && payload[3] == '-')
                    fv->l7_proto = L7_SSH;
                else if (payload[0] == 0x16 && payload[5] == 0x01)
                    fv->l7_proto = L7_HTTPS_TLS;
            }

            if (key.src_port == 53 || key.dst_port == 53)
                fv->l7_proto = L7_DNS;
        }
    }

    return TC_ACT_OK;
}

// PROGRAM 6: TC egress — Egress mirror for complete accounting

SEC("tc")
int silver_tc_egress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    struct flow5_key key = {};
    key.src_ip    = ip->saddr;
    key.dst_ip    = ip->daddr;
    key.direction = DIR_EGRESS;
    __u32 pkt_len = data_end - data;

    if (ip->protocol == IPPROTO_TCP) {
        key.l4_proto = L4_TCP;
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        key.src_port = bpf_ntohs(tcp->source);
        key.dst_port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        key.l4_proto = L4_UDP;
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        key.src_port = bpf_ntohs(udp->source);
        key.dst_port = bpf_ntohs(udp->dest);
    } else {
        return TC_ACT_OK;
    }

    struct flow_value *fv = bpf_map_lookup_elem(&flow_table, &key);
    if (fv) {
        fv->packets_out += 1;
        fv->bytes_out   += pkt_len;
        fv->last_seen_ns = bpf_ktime_get_ns();
    }

    __u64 cookie = bpf_get_socket_cookie(skb);
    if (cookie && !fv) {
        struct cookie_proc *cp = bpf_map_lookup_elem(&proc_by_cookie, &cookie);
        if (cp) {
            struct flow_value new_fv = {};
            new_fv.proc = cp->proc;
            new_fv.socket_cookie = cookie;
            new_fv.state = STATE_ESTABLISHED;
            new_fv.packets_out = 1;
            new_fv.bytes_out = pkt_len;
            new_fv.first_seen_ns = bpf_ktime_get_ns();
            new_fv.last_seen_ns  = new_fv.first_seen_ns;
            bpf_map_update_elem(&flow_table, &key, &new_fv, BPF_NOEXIST);
        }
    }

    bump_stats(100 + key.l4_proto, pkt_len);

    return TC_ACT_OK;
}

#include "vmlinux.h"
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define ONE_SECOND 1000000000

struct rcv_entry {
    __u64 time;
    char hdr[64];
    __u8 prot_type;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} log_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct sk_buff*);
    __type(value, struct rcv_entry);
    __uint(max_entries, 1 << 20);
} rcv_map SEC(".maps");

SEC("kprobe/tcp_queue_rcv")
int BPF_KPROBE(tcp_v4_receiver, struct sock *sk, struct sk_buff *skb, bool *fragstolen) {
    __u64 cur_time = bpf_ktime_get_ns();
    struct rcv_entry *rcv = bpf_map_lookup_elem(&rcv_map, &skb);
    if (!rcv) return 0;
    if (rcv->prot_type != TCP) return 0;
    __u64 diff_time = cur_time - rcv->time;
    if (diff_time > ONE_SECOND) return 0;
    struct iphdr *iph = (struct iphdr*)rcv->hdr;
    struct tcphdr *tcph = (struct tcphdr*)(rcv->hdr + sizeof(struct iphdr));
    struct log_entry entry = {
        .time = diff_time,
        .sip = iph->saddr,
        .seq = bpf_ntohl(tcph->seq),
        .ack = bpf_ntohl(tcph->ack_seq),
        .sport = bpf_ntohs(tcph->source),
        .dport = bpf_ntohs(tcph->dest),
        .prot_type = TCP
    };
    bpf_ringbuf_output(&log_map, &entry, sizeof(entry), 0);
    return 0;
}

SEC("kprobe/__udp_enqueue_schedule_skb")
int BPF_KPROBE(udp_v4_receiver, struct sock *sk, struct sk_buff *skb) {
    __u64 cur_time = bpf_ktime_get_ns();
    struct rcv_entry *rcv = bpf_map_lookup_elem(&rcv_map, &skb);
    if (!rcv) return 0;
    if (rcv->prot_type != UDP) return 0;
    __u64 diff_time = cur_time - rcv->time;
    if (diff_time > ONE_SECOND) return 0;
    struct iphdr *iph = (struct iphdr*)rcv->hdr;
    struct udphdr *udph = (struct udphdr*)(rcv->hdr + sizeof(struct iphdr));
    struct log_entry entry = {
        .time = diff_time,
        .sip = iph->saddr,
        .sport = bpf_ntohs(udph->source),
        .dport = bpf_ntohs(udph->dest),
        .prot_type = UDP
    };
    bpf_ringbuf_output(&log_map, &entry, sizeof(entry), 0);
    return 0;
}

SEC("kprobe/ip_rcv_core")
int BPF_KPROBE(skb_marker, struct sk_buff *skb, struct net *net) {
    __u64 cur_time = bpf_ktime_get_ns();
    void *data;

    if (bpf_probe_read_kernel(&data, sizeof(data), &skb->data) < 0) {
        return 0;
    }

    struct iphdr iph;
    if (bpf_probe_read_kernel(&iph, sizeof(iph), data) < 0) {
        return 0;
    }

    if (iph.saddr == 0x0100007F) {
        return 0;
    }

    struct rcv_entry rcv = {
        .time = cur_time    
    };

    if (iph.protocol == IPPROTO_TCP) {
        rcv.prot_type = TCP;
        if (bpf_probe_read_kernel(rcv.hdr, sizeof(struct iphdr) + sizeof(struct tcphdr), data) < 0) {
            return 0;
        }
        bpf_map_update_elem(&rcv_map, &skb, &rcv, BPF_ANY);
    }
    else if (iph.protocol == IPPROTO_UDP) {
        rcv.prot_type = UDP;
        if (bpf_probe_read_kernel(rcv.hdr, sizeof(struct iphdr) + sizeof(struct udphdr), data) < 0) {
            return 0;
        }
        bpf_map_update_elem(&rcv_map, &skb, &rcv, BPF_ANY);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
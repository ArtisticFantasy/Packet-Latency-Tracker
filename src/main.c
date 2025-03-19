#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include "common.h"

FILE *fp_tcp, *fp_udp;

int handle_event(void *ctx, void *data, size_t data_sz) {
    struct log_entry *entry = data;
    char sip_str[INET_ADDRSTRLEN];

    if (!inet_ntop(AF_INET, &entry->sip, sip_str, sizeof(sip_str))) {
        fprintf(stderr, "ERROR: converting source IP to string failed\n");
        return -1;
    }

    if (entry->prot_type == TCP) {
        fprintf(fp_tcp, "%s \t%-5u \t%-5u \t%-10u \t%-10u \t%llu\n", sip_str, entry->sport, entry->dport, entry->seq, entry->ack, entry->time);
        fflush(fp_tcp);
    } else if (entry->prot_type == UDP) {
        fprintf(fp_udp, "%s \t%-5u \t%-5u \t%llu\n", sip_str, entry->sport, entry->dport, entry->time);
        fflush(fp_udp);
    }
    return 0;
}

void cleanup() {
    if (fp_tcp) {
        fclose(fp_tcp);
        fp_tcp = NULL;
    }
    if (fp_udp) {
        fclose(fp_udp);
        fp_udp = NULL;
    }
    printf("Resources cleaned up.\n");
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *mark_prog, *tcp_prog, *udp_prog;
    struct bpf_link *link;
    int ret;

    obj = bpf_object__open_file("src/packet-latency-tracker.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    ret = bpf_object__load(obj);
    if (ret) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

    mark_prog = bpf_object__find_program_by_name(obj, "skb_marker");
    if (!mark_prog) {
        fprintf(stderr, "ERROR: finding skb_marker in BPF object file failed\n");
        bpf_object__close(obj);
        return 1;
    }

    tcp_prog = bpf_object__find_program_by_name(obj, "tcp_v4_receiver");
    if (!tcp_prog) {
        fprintf(stderr, "ERROR: finding tcp_v4_receiver in BPF object file failed\n");
        bpf_object__close(obj);
        return 1;
    }

    udp_prog = bpf_object__find_program_by_name(obj, "udp_v4_receiver");
    if (!udp_prog) {
        fprintf(stderr, "ERROR: finding udp_v4_receiver in BPF object file failed\n");
        bpf_object__close(obj);
        return 1;
    }

    int rcv_map_fd = bpf_object__find_map_fd_by_name(obj, "rcv_map");
    if (rcv_map_fd < 0) {
        fprintf(stderr, "ERROR: finding rcv_map in BPF object file failed\n");
        bpf_object__close(obj);
        return 1;
    } 

    int log_map_fd = bpf_object__find_map_fd_by_name(obj, "log_map");
    if (log_map_fd < 0) {
        fprintf(stderr, "ERROR: finding log_map in BPF object file failed\n");
        bpf_object__close(obj);
        return 1;
    }

    link = bpf_program__attach_kprobe(mark_prog, false, "ip_rcv_core");
    if (!link) {
        fprintf(stderr, "ERROR: attaching skb_marker to kprobe failed\n");
        bpf_object__close(obj);
        return 1;
    }

    link = bpf_program__attach_kprobe(tcp_prog, false, "tcp_queue_rcv");
    if (!link) {
        fprintf(stderr, "ERROR: attaching tcp_v4_receiver to kprobe failed\n");
        bpf_object__close(obj);
        return 1;
    }

    link = bpf_program__attach_kprobe(udp_prog, false, "__udp_enqueue_schedule_skb");
    if (!link) {
        fprintf(stderr, "ERROR: attaching udp_v4_receiver to kprobe failed\n");
        bpf_object__close(obj);
        return 1;
    }

    if (atexit(cleanup) != 0) {
        fprintf(stderr, "ERROR: registering cleanup function failed\n");
        bpf_object__close(obj);
        return 1;
    }

    fp_tcp = fopen("tcp_packets.log", "w");
    if (!fp_tcp) {
        fprintf(stderr, "ERROR: opening tcp_packets.log failed\n");
        bpf_object__close(obj);
        return 1;
    }

    fp_udp = fopen("udp_packets.log", "w");
    if (!fp_udp) {
        fprintf(stderr, "ERROR: opening udp_packets.log failed\n");
        bpf_object__close(obj);
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(log_map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "ERROR: creating ring buffer failed\n");
        bpf_object__close(obj);
        return 1;
    }

    printf("Start capturing packets...\n");

    fprintf(fp_tcp, "sip         \tsport \tdport \tseq        \tack        \tlatency\n");
    fflush(fp_tcp);

    fprintf(fp_udp, "sip         \tsport \tdport \tlatency\n");
    fflush(fp_udp);

    while (1) {
        int ret = ring_buffer__poll(rb, -1);
        if (ret < 0) {
            fprintf(stderr, "ERROR: polling ring buffer failed\n");
            break;
        }
    }

    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}
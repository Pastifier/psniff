#include "psniff.h"


static bool setup_pcap(t_context *cxt) {
    struct bpf_program fp;
    char filter_exp[] = "tcp or udp";

    if (pcap_compile(cxt->handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) < 0) {
        fprintf(stderr, "pcap_compile error: %s\n", pcap_geterr(cxt->handle));
        return false;
    }

    if (pcap_setfilter(cxt->handle, &fp) < 0) {
        fprintf(stderr, "pcap_setfilter error: %s\n", pcap_geterr(cxt->handle));
        pcap_freecode(&fp);
        return false;
    }

    pcap_freecode(&fp);
    return true;
}

// typedef void (*pcap_handler)(u_char *user, const struct pcap_pkthdr *h,
//           const u_char *bytes);

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    t_context* cxt = (t_context*)user;
    t_parsed_packet parsed = (t_parsed_packet){0};

    parsed.ts = h->ts;

    // The header contains different data at different offsets, so keep that in mind.

    //// 1. Parse ethernet
    // int offset = parse_ethernet(bytes, &parsed);
    
    //// 2. Parse IP
    // offset = parse_ip(bytes, offset, &parsed);

    //// 3. Parse TCP/UDP
    if (parsed.protocol == IPPROTO_TCP) {
        // offset = parse_tcp(bytes, offset, &parsed);
    } else if (parsed.protocol == IPPROTO_UDP) {
        // offset = parse_udp(bytes, offset, &parsed);
    }

    //// 4. Parse HTTP GET/POST if TCP
    if (parsed.protocol == IPPROTO_TCP) {
        // parse_http(bytes, offset, &parsed);
    }

    //// 5. Track connection
    // int conn_index = find_or_create_connection(cxt, &parsed);
    // if (conn_index >= 0) {
    //     update_connection(cxt, conn_index, &parsed);
    // }

    //// 6. Add packet to queue
    // if (!ps_queue_enqueue(&cxt->queue, &parsed)) {
    //     return;
    // }
}

void *ps_producer_routine(void *arg) {
(void)arg;
    t_context* cxt = (t_context*)arg;

    printf("[+] Producer thread started\n");

    //// 1: Initialize pcap
    if (!setup_pcap(cxt)) {
        __atomic_store_n(&cxt->running, false, __ATOMIC_SEQ_CST); // REMEMBER
        return NULL;
    }

    //// 2: Start sniffing
    // int res = pcap_loop(cxt->handle, -1, packet_handler, (u_char*)cxt);

    //// 3: Check for errors or interruption
    // switch (res)
    // {
    // case -1:
    //     fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(cxt->handle));
    //     break;
    // case -2:
    //     fprintf(stderr, "pcap_loop interrupted\n");
    //     break;
    // default:
    //     printf("pcap_loop exited with code %d\n", res);
    //     break;
    // }

    return NULL;
}

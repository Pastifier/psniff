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

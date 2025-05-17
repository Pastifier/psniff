#include "psniff.h"

bool ps_threads_init(t_context* cxt) {
    if (pthread_create(&cxt->producer_tid, NULL, ps_producer_routine, cxt))
        return false;
    if (pthread_create(&cxt->consumer_tid, NULL, ps_consumer_routine, cxt))
        return false;
    return true;
}

void ps_threads_join(t_context* cxt) {
    pthread_join(cxt->producer_tid, NULL);
    ps_queue_close(&cxt->queue);
    pthread_join(cxt->consumer_tid, NULL);
}


void *ps_producer_routine(void *arg) {
(void)arg;
    // t_context* cxt = (t_context*)arg;

    printf("[+] Producer thread started\n");

    //// 1: Initialize pcap
    // if (!setup_pcap(cxt)) {
    //     __atomic_store_n(&cxt->running, false, __ATOMIC_SEQ_CST);
    //     return NULL;
    // }

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

void *ps_consumer_routine(void *arg) {
(void)arg;
    // t_context* cxt = (t_context*)arg;
    return NULL;
}
#include "psniff.h"
#include <unistd.h>

static void print_packet_info(FILE *f, const t_parsed_packet *parsed) {
    char src_mac_str[18], dst_mac_str[18];

    snprintf(src_mac_str, sizeof(src_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
            parsed->src_mac[0], parsed->src_mac[1], parsed->src_mac[2],
            parsed->src_mac[3], parsed->src_mac[4], parsed->src_mac[5]);

    snprintf(dst_mac_str, sizeof(dst_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
            parsed->dst_mac[0], parsed->dst_mac[1], parsed->dst_mac[2],
            parsed->dst_mac[3], parsed->dst_mac[4], parsed->dst_mac[5]);
    
    fprintf(f, "[%ld.%06ld] ", (long)parsed->ts.tv_sec, (long)parsed->ts.tv_usec);

    fprintf(f, "MAC %s -> %s | ", src_mac_str, dst_mac_str);

    
    char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(parsed->src_ip), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(parsed->dst_ip), dst_ip_str, INET_ADDRSTRLEN);
    fprintf(f, "IP %s -> %s | ", src_ip_str, dst_ip_str);
    // fprintf(f, "IP %s -> %s | ", inet_ntoa(parsed->src_ip), inet_ntoa(parsed->dst_ip)); // Convert Internet number in IN to ASCII representation. The return value
//                                                                                              is a pointer to an internal array containing the string.
    if (parsed->protocol == IPPROTO_TCP) {
        fprintf(f, "TCP %u -> %u", parsed->src_port, parsed->dst_port);
    } else if (parsed->protocol == IPPROTO_UDP) {
        fprintf(f, "UDP %u -> %u", parsed->src_port, parsed->dst_port);
    } else { // Just in case the task actually requires me to capture packets unfiltered
        fprintf(f, "PROTOCOL %u", parsed->protocol);
    }

    if (parsed->has_http) {
        fprintf(f, " | HTTP");

        if (parsed->host[0]) {
            fprintf(f, " Host: %s", parsed->host);
        }

        if (parsed->user_agent[0]) {
            fprintf(f, "%sUser-Agent: %s", (parsed->host[0] ? " , " : " "), parsed->user_agent);
        }
    }

    fprintf(f, "\n");
    fflush(f);
}

void *ps_consumer_routine(void *arg) {
    t_context* cxt = (t_context*)arg;
    t_parsed_packet parsed; // No need to initialize here, we're just dequeuing
    int counter = 0;

    printf("[+] Consumer thread started\n");

    while (__atomic_load_n(&cxt->running, __ATOMIC_SEQ_CST)) {
        if (ps_queue_dequeue(&cxt->queue, &parsed)) {
            print_packet_info(cxt->output_file, &parsed);

            ++counter;
        } else {
            if (!__atomic_load_n(&cxt->running, __ATOMIC_SEQ_CST)) break;

            usleep(10000);
        }
    }

    printf("[*] Consumer thread finished (%d packets)\n", counter);
    return NULL;
}

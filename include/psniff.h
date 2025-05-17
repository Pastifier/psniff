#ifndef PSNIFF_H
# define PSNIFF_H

/* ----- Includes ------ */
# include <pcap.h>
# include <stdbool.h>
# include "ps_queue.h"
# include "ps_threads.h"

/* ----- Defines ------ */

typedef struct s_context {
    t_packet_queue queue;
    pcap_t* pcap;
    struct {
        bool running;
        pthread_t producer;
        pthread_t consumer;
    } threads;
    // t_hashmap* map; // later
} t_context;

#endif // !PSNIFF_H

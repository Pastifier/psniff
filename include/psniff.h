#ifndef PSNIFF_H
# define PSNIFF_H

/* ----- Includes ------ */
# include <pcap.h>
# include <stdbool.h>
# include "ps_queue.h"
# include "ps_threads.h"

/* ----- Defines ------ */

/* ----- Typedefs & Structs ------ */

typedef struct s_tcp_conn {
    struct in_addr src_ip;
    struct in_addr dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    
    struct timeval start_time;
    struct timeval end_time;
    
    uint32_t packets_in;
    uint32_t packets_out;
    
    int is_active;
    uint8_t flags;        // Keep track of TCP flags seen: might be useful later...
} t_tcp_conn;

typedef struct s_context {
    pcap_t *handle;
    FILE *output_file;
    char *dev_name;
    
    t_packet_queue queue;
    
    pthread_t producer_tid;
    pthread_t consumer_tid;
    
    // t_tcp_conn *connections;  // TODO
    
    volatile bool running;
} t_context;

#endif // !PSNIFF_H

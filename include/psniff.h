#ifndef PSNIFF_H
# define PSNIFF_H

/* ----- Includes ------ */
# include <pcap.h>
# include <stdbool.h>
# include <stdatomic.h> // For _Atomic, __atomic_store_n()
# include "ps_queue.h"
# include "ps_threads.h"

/* ----- Defines ------ */

# define _PS_MAX_CONN 10000 // Realistically, if we get this many connections, something is wrong LOL...

/* ----- Typedefs & Structs ------ */

enum e_direction {
    FORWARD = 1,
    REVERSE
};

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
} t_tcp_conn;

typedef struct s_context {
    pcap_t *handle;
    FILE *output_file;
    char *dev_name;

    t_packet_queue queue;

    pthread_t producer_tid;
    pthread_t consumer_tid;

    t_tcp_conn *connections;

    volatile _Atomic bool running;
} t_context;

/* ----- Prototypes ------ */
int find_or_create_connection(t_context *ctx, t_parsed_packet *parsed);
void update_connection(t_context *ctx, int conn_idx, t_parsed_packet *parsed);

#endif // !PSNIFF_H

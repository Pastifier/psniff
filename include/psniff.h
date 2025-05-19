// Keywords
// RESOURCE: marks resources to be released.
// DECISION: marks decisions to be made.
// REMEMBER: marks things to be remembered in the future (e.g. cleanup in branching paths).


#ifndef PSNIFF_H
# define PSNIFF_H

/* ----- Includes ------ */
# include <pcap.h>
# include <stdbool.h>
# include <stdatomic.h> // For _Atomic, __atomic_store_n()
# include <stdlib.h>
# include "ps_queue.h"
# include "ps_threads.h"

/* ----- Defines ------ */

# define _PS_MAX_CONN 10000 // Realistically, if we get this many active connections, something is wrong LOL...
# define _PS_PACKET_CAPLEN 65535 // As per pcap(3PCAP), this number is sufficient. Truncated
# define _PS_PACKET_SNAPLEN 262144 // Full snapshot..?

/* ----- Typedefs & Structs ------ */

typedef uint8_t u_char;

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
    pcap_t *handle; // RESOURCE
    FILE *output_file; // RESOURCE
    // char *dev_name; // Might not need this, actually.

    t_packet_queue queue; // RESOURCE

    pthread_t producer_tid;
    pthread_t consumer_tid;

    t_tcp_conn *connections; // RESOURCE

    volatile _Atomic bool running;
} t_context;

/* ----- Prototypes ------ */
void print_connection_summary(t_context *ctx, int conn_idx);
int find_or_create_connection(t_context *ctx, t_parsed_packet *parsed);
void update_connection(t_context *ctx, int conn_idx, t_parsed_packet *parsed);

#endif // !PSNIFF_H

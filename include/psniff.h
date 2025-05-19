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
# include "ps_valgrind.h"

/* ----- Defines ------ */

# define _PS_MAX_CONN 10000 // Realistically, if we get this many active connections, something is wrong LOL...
# define _PS_PACKET_CAPLEN 65535 // As per pcap(3PCAP), this number is sufficient. Truncated
# define _PS_PACKET_SNAPLEN 262144 // Full snapshot..?
# define _PS_CONNECTION_TIMEOUT 120 // Connection timeout in seconds
# define _PS_MIN_PROBE_LENGTH 20   // Minimum probe length for hash table lookups
# define _PS_MAX_PROBE_LENGTH 1000 // Maximum probe length for hash table lookups
# define _PS_STATS_INTERVAL 1000   // Update stats every this many lookups

/* ----- Typedefs & Structs ------ */

typedef uint8_t u_char;

enum e_direction {
    FORWARD = 1,
    REVERSE
};

// TCP connection states
enum e_tcp_state {
    TCP_STATE_NONE = 0,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RECEIVED,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_CLOSED
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
    enum e_tcp_state state;   // Current TCP state
    time_t last_activity_time; // Last packet timestamp
    uint8_t fin_count;        // Count of FIN packets seen (need 2 for graceful close)
} t_tcp_conn;

typedef struct s_context {
    pcap_t *handle; // RESOURCE
    FILE *output_file; // RESOURCE
    // char *dev_name; // Might not need this, actually.

    t_packet_queue queue; // RESOURCE

    pthread_t producer_tid;
    pthread_t consumer_tid;
    pthread_t audit_tid;     // Connection audit thread

    t_tcp_conn *connections; // RESOURCE
    pthread_mutex_t conn_mutex; // Connection table mutex
    pthread_cond_t audit_cond;  // Condition variable for audit thread signaling
    time_t last_audit_time;     // Last time audit was performed

    int running;
    int verbose;            // Verbose logging flag
    
    // Hash table statistics
    int total_lookups;
    int total_probes;
    int max_probes_needed;
} t_context;

/* ----- Prototypes ------ */
void print_connection_summary(t_context *ctx, int conn_idx);
int find_or_create_connection(t_context *ctx, t_parsed_packet *parsed);
void update_connection(t_context *ctx, int conn_idx, t_parsed_packet *parsed);
void *ps_connection_audit_routine(void *arg);
uint32_t hash_connection(struct in_addr src_ip, struct in_addr dst_ip, uint16_t src_port, uint16_t dst_port);

#endif // !PSNIFF_H

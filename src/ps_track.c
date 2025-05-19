
// TODO: might need function that periodically checks for dormant "connections" that weren never closed

#include "psniff.h"

/* ----- TCP Flag constants ----- */
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_ACK 0x10

// static uint32_t hash_connection(struct in_addr src_ip, struct in_addr dst_ip,
//         uint16_t src_port, uint16_t dst_port) {
//     bool is_lower = false; // For bi-directional connections

//     if (ntohl(src_ip.s_addr) < ntohl(dst_ip.s_addr)) {
//         is_lower = true;
//     } else if (ntohl(src_ip.s_addr) == ntohl(dst_ip.s_addr)) {
//         if (src_port < dst_port) {
//             is_lower = true;
//         }
//     }

//     uint32_t hash;
//     switch (is_lower)
//     {
//     case true:
//         hash = src_ip.s_addr ^ (dst_ip.s_addr << 7) ^ src_port ^ (dst_port << 16);
//         break;
    
//     default:
//         hash = dst_ip.s_addr ^ (src_ip.s_addr << 7) ^ dst_port ^ (src_port << 16);
//         break;
//     }

//     return hash % _PS_MAX_CONN;
// }

static uint32_t hash_connection(struct in_addr src_ip, struct in_addr dst_ip,
        uint16_t src_port, uint16_t dst_port) {
    bool is_lower = false;

    if (ntohl(src_ip.s_addr) < ntohl(dst_ip.s_addr)) {
        is_lower = true;
    } else if (ntohl(src_ip.s_addr) == ntohl(dst_ip.s_addr)) {
        if (src_port < dst_port) {
            is_lower = true;
        }
    }

    uint32_t a, b, c, d;

    switch (is_lower)
    {
    case true:
        a = src_ip.s_addr;
        b = dst_ip.s_addr;
        c = src_port;
        d = dst_port;
        break;

    default:
        a = dst_ip.s_addr;
        b = src_ip.s_addr;
        c = dst_port;
        d = src_port;
        break;
    }

    // FNV-1a inspired mixing with better bit dispersion
    uint32_t hash = 2166136261u; // FNV offset basis

    hash = (hash ^ (a & 0xFF)) * 16777619;
    hash = (hash ^ ((a >> 8) & 0xFF)) * 16777619;
    hash = (hash ^ ((a >> 16) & 0xFF)) * 16777619;
    hash = (hash ^ ((a >> 24) & 0xFF)) * 16777619;

    hash = (hash ^ (b & 0xFF)) * 16777619;
    hash = (hash ^ ((b >> 8) & 0xFF)) * 16777619;
    hash = (hash ^ ((b >> 16) & 0xFF)) * 16777619;
    hash = (hash ^ ((b >> 24) & 0xFF)) * 16777619;

    hash = (hash ^ (c & 0xFF)) * 16777619;
    hash = (hash ^ ((c >> 8) & 0xFF)) * 16777619;

    hash = (hash ^ (d & 0xFF)) * 16777619;
    hash = (hash ^ ((d >> 8) & 0xFF)) * 16777619;

    return hash % _PS_MAX_CONN;
}

/**
 * Check if two connections are the same (in either direction)
 */
static int is_same_connection(const t_tcp_conn *conn, 
                             struct in_addr src_ip, struct in_addr dst_ip,
                             uint16_t src_port, uint16_t dst_port) {
    if (conn->src_ip.s_addr == src_ip.s_addr && 
        conn->dst_ip.s_addr == dst_ip.s_addr &&
        conn->src_port == src_port && 
        conn->dst_port == dst_port) {
        return FORWARD;
    }
    
    if (conn->src_ip.s_addr == dst_ip.s_addr && 
        conn->dst_ip.s_addr == src_ip.s_addr &&
        conn->src_port == dst_port && 
        conn->dst_port == src_port) {
        return REVERSE;
    }
    
    return 0;
}

void print_connection_summary(t_context *ctx, int conn_idx) {
    if (conn_idx < 0 || conn_idx >= _PS_MAX_CONN) { // Shouldn't happen if logic holds up.
        return;
    }
    
    t_tcp_conn *conn = &ctx->connections[conn_idx];
    
    long duration_ms = 
        (conn->end_time.tv_sec - conn->start_time.tv_sec) * 1000 +
        (conn->end_time.tv_usec - conn->start_time.tv_usec) / 1000;
    
    fprintf(stdout, "--- TCP Connection Summary ---\n");
    fprintf(stdout, "Source IP:Port: %s:%d\n", 
           inet_ntoa(conn->src_ip), conn->src_port);
    fprintf(stdout, "Destination IP:Port: %s:%d\n", 
           inet_ntoa(conn->dst_ip), conn->dst_port);
    fprintf(stdout, "Packets OUT: %u\n", conn->packets_out);
    fprintf(stdout, "Packets IN: %u\n", conn->packets_in);
    fprintf(stdout, "Duration: %ld ms\n", duration_ms);
    fprintf(stdout, "---------------------------\n\n");
}

/**
 * Find or create a connection in the tracking table
 * Returns the index of the connection or -1 if no slot is available (unlikely)
 */
int find_or_create_connection(t_context *ctx, t_parsed_packet *parsed) {
    // Only track TCP
    if (parsed->protocol != IPPROTO_TCP) {
        return -1;
    }
    
    uint32_t hash_idx = hash_connection(parsed->src_ip, parsed->dst_ip, 
                                       parsed->src_port, parsed->dst_port);
    int found_idx = -1;
    int empty_idx = -1;
    
    // pthread_mutex_lock(&ctx->conn_mutex);
    
    for (uint32_t i = hash_idx; i < _PS_MAX_CONN /* hash_idx  + _PS_MAX_CONN/10 */; i++) {  // DECISION: premature optimisation. Play with the percentage probed as you test.
        int idx = i /* % _PS_MAX_CONN */ ;
        
        int match = is_same_connection(&ctx->connections[idx], 
                                       parsed->src_ip, parsed->dst_ip,
                                       parsed->src_port, parsed->dst_port);
        // switch (match) // DECISION: should we update packet count and end time here?
        // {
        // case FORWARD:
        //     // update packet count and end time
        //     break;
        // case REVERSE:
        //     // update packet count and end time
        //     break;
        // default:
        //     break;
        // }
        if (match) {
            // maybe update packet count and end time here.
            found_idx = idx;
            break;
        }
        
        // Keep track of the first empty slot we find
        if (!ctx->connections[idx].is_active && empty_idx == -1) {
            empty_idx = idx;
        }
    }
    
    // If found, just return the index
    if (found_idx >= 0) {
        // pthread_mutex_unlock(&ctx->conn_mutex);
        return found_idx;
    }
    
    if (empty_idx >= 0) {
        t_tcp_conn *conn = &ctx->connections[empty_idx];
        
        conn->src_ip = parsed->src_ip;
        conn->dst_ip = parsed->dst_ip;
        conn->src_port = parsed->src_port;
        conn->dst_port = parsed->dst_port;
        conn->start_time = parsed->ts;
        conn->packets_in = 0;
        conn->packets_out = 0;
        conn->is_active = 1; // DECISION: need to check whether the connection is actually established.
        
        // pthread_mutex_unlock(&ctx->conn_mutex);
        return empty_idx;
    }

    // pthread_mutex_unlock(&ctx->conn_mutex);
    return -1;
}

/**
 * Update an existing connection with new packet data
 */
void update_connection(t_context *ctx, int conn_idx, t_parsed_packet *parsed) {
    if (conn_idx < 0 || conn_idx >= _PS_MAX_CONN) { // Hm.
        return;
    }
    
    t_tcp_conn *conn = &ctx->connections[conn_idx];
    
    // pthread_mutex_lock(&ctx->conn_mutex);
    
    if (!conn->is_active) {
        // pthread_mutex_unlock(&ctx->conn_mutex);
        return;
    }
    
    // Check TCP flags
    if (parsed->protocol == IPPROTO_TCP) {
        // FIN: graceful termination
        // RST: ungraceful termination?
        if ((parsed->flags & TCP_FIN) || (parsed->flags & TCP_RST)) {
            conn->is_active = 0;
            conn->end_time = parsed->ts;
            
            print_connection_summary(ctx, conn_idx);
        }
    }
    
    // Update packet counts based on direction
    int direction = is_same_connection(conn, parsed->src_ip, parsed->dst_ip,
                                      parsed->src_port, parsed->dst_port);
    switch (direction)
    {
    case FORWARD:
        conn->packets_out++;
        break;
    case REVERSE:
        conn->packets_in++;
    default:
        break;
    }
    // if (direction == FORWARD) {
    //     conn->packets_out++;
    // } else if (direction == REVERSE) {
    //     conn->packets_in++;
    // }
    
    // pthread_mutex_unlock(&ctx->conn_mutex);
}

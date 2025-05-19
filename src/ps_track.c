
// Implementation of connection tracking with proper state management and timeouts

#include "psniff.h"
#include <math.h>
#include <time.h>
#include <unistd.h>

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
uint32_t hash_connection(struct in_addr src_ip, struct in_addr dst_ip,
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

    // Order IPs and ports consistently for bidirectional connections
    if (is_lower) {
        a = src_ip.s_addr;
        b = dst_ip.s_addr;
        c = src_port;
        d = dst_port;
    } else {
        a = dst_ip.s_addr;
        b = src_ip.s_addr;
        c = dst_port;
        d = src_port;
    }
    
    // FNV-1a inspired mixing with better bit dispersion for network data
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
 * Find or create a connection in the tracking table with adaptive probing
 * Returns the index of the connection or -1 if no slot is available
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
    
    pthread_mutex_lock(&ctx->conn_mutex);
    
    // Start probing with adaptive probe length
    uint32_t probes_done = 0;
    uint32_t max_probes = ctx->max_probes_needed > 0 ? ctx->max_probes_needed : _PS_MIN_PROBE_LENGTH;
    
    for (uint32_t i = hash_idx; i < hash_idx + max_probes && probes_done < _PS_MAX_CONN; i++) {
        int idx = i % _PS_MAX_CONN;
        probes_done++;
        
        int match = is_same_connection(&ctx->connections[idx], 
                                      parsed->src_ip, parsed->dst_ip,
                                      parsed->src_port, parsed->dst_port);
        if (match) {
            found_idx = idx;
            break;
        }
        
        // Keep track of the first empty slot we find
        if (!ctx->connections[idx].is_active && empty_idx == -1) {
            empty_idx = idx;
            // We found an empty slot, but keep looking for a match
            // up to our probe limit
        }
    }
    
    // Update collision statistics
    ctx->total_lookups++;
    ctx->total_probes += probes_done;
    
    // Periodically update the max_probes_needed based on measured data
    if (ctx->total_lookups % _PS_STATS_INTERVAL == 0) {
        // Calculate average probe length
        double avg_probes = (double)ctx->total_probes / ctx->total_lookups;
        
        // Estimate required probe length based on measured collision rate
        // With a target failure probability of 0.0001
        
        // First, estimate collision rate from average probe length
        double collision_rate = 1.0 - (1.0 / avg_probes);
        if (collision_rate > 0.0 && collision_rate < 1.0) {
            // Calculate new probe length, clamped to reasonable values
            int new_max_probes = (int)(log(0.0001) / log(collision_rate));
            new_max_probes = (new_max_probes < _PS_MIN_PROBE_LENGTH) ? 
                             _PS_MIN_PROBE_LENGTH : new_max_probes;
            new_max_probes = (new_max_probes > _PS_MAX_PROBE_LENGTH) ? 
                             _PS_MAX_PROBE_LENGTH : new_max_probes;
            
            // Smooth adjustment (weighted average) to avoid oscillation
            ctx->max_probes_needed = (ctx->max_probes_needed * 3 + new_max_probes) / 4;
            
            // Log the adaptation if needed
            if (ctx->verbose) {
                fprintf(stderr, "Hash table stats: lookups=%d, avg_probes=%.2f, "
                        "collision_rate=%.4f, new_probe_length=%d\n",
                        ctx->total_lookups, avg_probes, collision_rate, ctx->max_probes_needed);
            }
        }
        
        // Reset statistics for next interval
        ctx->total_lookups = 0;
        ctx->total_probes = 0;
    }
    
    // If found, just return the index
    if (found_idx >= 0) {
        pthread_mutex_unlock(&ctx->conn_mutex);
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
        conn->is_active = 1;
        conn->state = TCP_STATE_NONE;
        conn->last_activity_time = time(NULL);
        conn->fin_count = 0;
        
        // Update state based on TCP flags
        if (parsed->protocol == IPPROTO_TCP) {
            if (parsed->flags & TCP_SYN) {
                conn->state = TCP_STATE_SYN_SENT;
            }
        }
        
        pthread_mutex_unlock(&ctx->conn_mutex);
        return empty_idx;
    }

    pthread_mutex_unlock(&ctx->conn_mutex);
    return -1;
}

/**
 * Update an existing connection with new packet data
 */
void update_connection(t_context *ctx, int conn_idx, t_parsed_packet *parsed) {
    if (conn_idx < 0 || conn_idx >= _PS_MAX_CONN) {
        return;
    }
    
    // Lock the connection table for thread-safe access
    pthread_mutex_lock(&ctx->conn_mutex);
    
    t_tcp_conn *conn = &ctx->connections[conn_idx];
    
    if (!conn->is_active) {
        pthread_mutex_unlock(&ctx->conn_mutex);
        return;
    }
    
    conn->last_activity_time = time(NULL);
    
    // Check TCP flags and update state machine
    if (parsed->protocol == IPPROTO_TCP) {
        // SYN: connection initialization
        if (parsed->flags & TCP_SYN) {
            if (parsed->flags & TCP_ACK) {
                conn->state = TCP_STATE_SYN_RECEIVED;
            } else {
                conn->state = TCP_STATE_SYN_SENT;
            }
        }
        // ACK without SYN: potential established connection
        else if (parsed->flags & TCP_ACK) {
            if (conn->state == TCP_STATE_SYN_RECEIVED || conn->state == TCP_STATE_SYN_SENT) {
                conn->state = TCP_STATE_ESTABLISHED;
            }
        }
        
        // FIN: graceful termination
        if (parsed->flags & TCP_FIN) {
            conn->state = TCP_STATE_FIN_WAIT;
            conn->fin_count++;
            
            // If both sides have sent FIN, connection is fully closed
            if (conn->fin_count >= 2) {
                conn->is_active = 0;
                conn->end_time = parsed->ts;
                print_connection_summary(ctx, conn_idx);
            }
        }
        // RST: abrupt termination
        else if (parsed->flags & TCP_RST) {
            conn->state = TCP_STATE_CLOSED;
            conn->is_active = 0;
            conn->end_time = parsed->ts;
            print_connection_summary(ctx, conn_idx);
        }
    }
    
    int direction = is_same_connection(conn, parsed->src_ip, parsed->dst_ip,
                                    parsed->src_port, parsed->dst_port);
    if (direction == FORWARD) {
        conn->packets_out++;
    } else if (direction == REVERSE) {
        conn->packets_in++;
    }
    
    pthread_mutex_unlock(&ctx->conn_mutex);
}

/**
 * Connection audit thread routine
 * Periodically checks for and closes inactive connections
 */
void *ps_connection_audit_routine(void *arg) {
    t_context* ctx = (t_context*)arg;
    struct timespec ts;
    
    printf("[+] Connection audit thread started\n");
    
    while (__atomic_load_n(&ctx->running, __ATOMIC_SEQ_CST)) {
        // Valgrind annotation - audit thread observes running flag
        ANNOTATE_HAPPENS_AFTER(&ctx->running);
        // Wait for signal from producer thread or timeout
        pthread_mutex_lock(&ctx->conn_mutex);
        
        // Calculate absolute time for timed wait (current time + timeout period)
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += _PS_CONNECTION_TIMEOUT;
        
        // Wait on condition variable with timeout
        if (__atomic_load_n(&ctx->running, __ATOMIC_SEQ_CST)) {
            // Valgrind annotation - audit thread observes running flag
            ANNOTATE_HAPPENS_AFTER(&ctx->running);
            pthread_cond_timedwait(&ctx->audit_cond, &ctx->conn_mutex, &ts);
        }
        
        // Don't perform audit if we're shutting down and just got signaled to exit
        if (!__atomic_load_n(&ctx->running, __ATOMIC_SEQ_CST)) {
            // Valgrind annotation - audit thread observes running flag
            ANNOTATE_HAPPENS_AFTER(&ctx->running);
            pthread_mutex_unlock(&ctx->conn_mutex);
            break;
        }
        
        // Perform connection audit
        time_t current_time = time(NULL);
        int closed_count = 0;
        
        for (int i = 0; i < _PS_MAX_CONN; i++) {
            if (ctx->connections[i].is_active) {
                // Check if connection has timed out
                if (current_time - ctx->connections[i].last_activity_time > _PS_CONNECTION_TIMEOUT) {
                    // Connection timed out
                    ctx->connections[i].is_active = 0;
                    ctx->connections[i].end_time.tv_sec = current_time;
                    ctx->connections[i].end_time.tv_usec = 0;
                    ctx->connections[i].state = TCP_STATE_CLOSED;
                    
                    print_connection_summary(ctx, i);
                    closed_count++;
                }
            }
        }
        
        if (ctx->verbose && closed_count > 0) {
            fprintf(stderr, "[*] Connection audit: closed %d inactive connections\n", closed_count);
        }
        
        // Update last audit time
        ctx->last_audit_time = current_time;
        
        pthread_mutex_unlock(&ctx->conn_mutex);
    }
    
    printf("[*] Connection audit thread finished\n");
    return NULL;
}

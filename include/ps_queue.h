// Brief: This file contains the implementation of the packet queue.
// Uses a circular buffer to store parsed-packets, and is thread-safe.
// The specifics are self-explanatory.
// Author: Emran BinJamaan

#ifndef PS_QUEUE_H
# define PS_QUEUE_H

/* ----- Includes ------ */

# include <stdint.h>
# include <netinet/in.h>
# include <sys/time.h>
# include <pthread.h>

/* ----- Defines ------ */
# define _PS_QUEUE_CAP 1024

typedef struct s_parsed_packet {
    uint8_t src_mac[6];
    uint8_t dst_mac[6];

    struct in_addr src_ip;
    struct in_addr dst_ip;

    uint16_t src_port;
    uint16_t dst_port;

    // Protocol: 6 = TCP, 17 = UDP, etc.
    uint8_t protocol;

    struct timeval ts;

    char host[256];
    char user_agent[512];
    int has_http; // 1 if this contains HTTP info
} t_parsed_packet;

typedef struct s_packet_queue {
    t_parsed_packet buffer[_PS_QUEUE_CAP];
    int front;
    int rear;
    int size;

    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;

    int closed; // Optional: if set, writer stops
} t_packet_queue;

/* ----- Functions ------ */

void ps_queue_init(t_packet_queue* q);
void ps_queue_destroy(t_packet_queue* q);
int ps_queue_enqueue(t_packet_queue* q, const t_parsed_packet* pkt);
int ps_queue_dequeue(t_packet_queue* q, t_parsed_packet* out);
void ps_queue_close(t_packet_queue* q);

#endif // !PS_QUEUE_H

#include "ps_queue.h"

inline void ps_queue_init(t_packet_queue* q) {
    q->front = 0;
    q->rear = 0;
    q->size = 0;
    q->closed = 0;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);
}

void ps_queue_destroy(t_packet_queue* q) {
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->not_empty);
    pthread_cond_destroy(&q->not_full);
}

int ps_queue_enqueue(t_packet_queue* q, const t_parsed_packet* pkt) {
    pthread_mutex_lock(&q->mutex);
    while (q->size == _PS_QUEUE_CAP && !q->closed) {
        pthread_cond_wait(&q->not_full, &q->mutex);
    }
    if (q->closed) {
        pthread_mutex_unlock(&q->mutex);
        return 0;
    }

    q->buffer[q->rear] = *pkt;
    q->rear = (q->rear + 1) % _PS_QUEUE_CAP;
    q->size++;

    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->mutex);
    return 1;
}

int ps_queue_dequeue(t_packet_queue* q, t_parsed_packet* out) {
    pthread_mutex_lock(&q->mutex);
    while (q->size == 0 && !q->closed) {
        pthread_cond_wait(&q->not_empty, &q->mutex);
    }
    if (q->size == 0 && q->closed) {
        pthread_mutex_unlock(&q->mutex);
        return 0;
    }

    *out = q->buffer[q->front];
    q->front = (q->front + 1) % _PS_QUEUE_CAP;
    q->size--;

    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->mutex);
    return 1;
}

void ps_queue_close(t_packet_queue* q) {
    pthread_mutex_lock(&q->mutex);
    q->closed = 1;
    pthread_cond_broadcast(&q->not_empty);
    pthread_cond_broadcast(&q->not_full);
    pthread_mutex_unlock(&q->mutex);
}

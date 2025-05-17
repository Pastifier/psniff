#include "psniff.h"

bool ps_threads_init(t_context* cxt) {
    if (pthread_create(&cxt->threads.producer, NULL, ps_producer_routine, cxt))
        return false;
    if (pthread_create(&cxt->threads.consumer, NULL, ps_consumer_routine, cxt))
        return false;
    return true;
}

void ps_threads_join(t_context* cxt) {
    pthread_join(cxt->threads.producer, NULL);
    ps_queue_close(&cxt->queue);
    pthread_join(cxt->threads.consumer, NULL);
}


void *ps_producer_routine(void *arg) {
(void)arg;
    // t_context* cxt = (t_context*)arg;
    return NULL;
}

void *ps_consumer_routine(void *arg) {
(void)arg;
    // t_context* cxt = (t_context*)arg;
    return NULL;
}
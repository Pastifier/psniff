#include "psniff.h"

int ps_threads_init(t_context* cxt) {
    if (pthread_create(&cxt->threads.producer, NULL, ps_producer_routine, cxt))
        return 1;
    if (pthread_create(&cxt->threads.consumer, NULL, ps_consumer_routine, cxt))
        return 1;
    return 0;
}

void ps_threads_join(t_context* cxt) {
    pthread_join(cxt->threads.producer, NULL);
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
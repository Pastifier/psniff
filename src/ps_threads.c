#include "psniff.h"

bool ps_threads_init(t_context* cxt) {
    if (pthread_create(&cxt->producer_tid, NULL, ps_producer_routine, cxt))
        return false;
    if (pthread_create(&cxt->consumer_tid, NULL, ps_consumer_routine, cxt)) {
        pthread_cancel(cxt->producer_tid);
        return false;
    }
    return true;
}

void ps_threads_join(t_context* cxt) {
    ps_queue_close(&cxt->queue);

    printf("[*] Waiting for producer thread to finish...\n");
    pthread_join(cxt->producer_tid, NULL);

    printf("[*] Waiting for consumer thread to finish...\n");
    pthread_join(cxt->consumer_tid, NULL);
}

#include "psniff.h"

bool ps_threads_init(t_context* cxt) {
    if (pthread_mutex_init(&cxt->conn_mutex, NULL) != 0) {
        fprintf(stderr, "Failed to initialize connection table mutex\n");
        return false;
    }
    
    if (pthread_cond_init(&cxt->audit_cond, NULL) != 0) {
        fprintf(stderr, "Failed to initialize audit condition variable\n");
        pthread_mutex_destroy(&cxt->conn_mutex);
        return false;
    }
    
    // Initialize last audit time
    cxt->last_audit_time = time(NULL);
    
    cxt->total_lookups = 0;
    cxt->total_probes = 0;
    cxt->max_probes_needed = _PS_MIN_PROBE_LENGTH;
    
    if (pthread_create(&cxt->producer_tid, NULL, ps_producer_routine, cxt))
        return false;
    
    if (pthread_create(&cxt->consumer_tid, NULL, ps_consumer_routine, cxt)) {
        pthread_cancel(cxt->producer_tid);
        return false;
    }
    
    if (pthread_create(&cxt->audit_tid, NULL, ps_connection_audit_routine, cxt)) {
        pthread_cancel(cxt->producer_tid);
        pthread_cancel(cxt->consumer_tid);
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
    
    // Signal the audit thread to wake up before joining
    pthread_mutex_lock(&cxt->conn_mutex);
    pthread_cond_signal(&cxt->audit_cond);
    pthread_mutex_unlock(&cxt->conn_mutex);
    
    printf("[*] Waiting for audit thread to finish...\n");
    pthread_join(cxt->audit_tid, NULL);
    
    // Destroy connection table mutex and condition variable
    pthread_cond_destroy(&cxt->audit_cond);
    pthread_mutex_destroy(&cxt->conn_mutex);
}

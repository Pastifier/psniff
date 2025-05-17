#ifndef PS_THREADS_H
# define PS_THREADS_H

# include <pthread.h>

typedef struct s_context t_context;

int ps_threads_init(t_context* cxt);
void ps_threads_join(t_context* cxt);

void *ps_producer_routine(void *arg);
void *ps_consumer_routine(void *arg);

#endif // !PS_THREADS_H
#include "psniff.h"
#include <stdio.h>
#include <signal.h>

volatile t_context* g_cxt = NULL;

void signal_handler(int sig) {
	g_cxt->threads.running = false;
	ps_queue_close(&g_cxt->queue);
	// cleanup(g_cxt); // Remember: dynamically allocated: -- 
	// DECISION: cleanup here or after threads join in main?
	
	// Summary goes here (maybe?) 

}

int main(int argc, char *argv[]) {
	if (argc == 4) {
		// TODO pcap init logic
		// TODO hashmap create logic
		static t_context cxt;// = (t_context){0}; // whether this or memset is faster remains to be seen.

		ps_queue_init(&cxt.queue);

		if (!ps_threads_init(&cxt)) {
			fprintf(stderr, "Failed to initialize threads\n");
			ps_queue_destroy(&cxt.queue);
			return 1;
		}
		ps_threads_join(&cxt);

		// Cleanup
		ps_queue_destroy(&cxt.queue);
		return 0;
	}
	fprintf(stderr, "Usage: %s <interface|pcapfile> <\"live\"|\"file\"> <output_file>\n", argv[0]);
	return 1;
}

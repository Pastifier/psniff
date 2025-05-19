#include "psniff.h"
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdatomic.h>

t_context* g_cxt = NULL;

void signal_handler(int sig) {
	if (sig == SIGINT) {
		__atomic_store_n(&g_cxt->running, false, __ATOMIC_SEQ_CST);
		ps_queue_close(&g_cxt->queue);
		// cleanup(g_cxt); // Remember: dynamically allocated: -- 
		// DECISION: cleanup here or after threads join in main?
		
		// Summary goes here (maybe?) 
	}
}

static bool init_context(t_context* cxt, int argc, char* argv[]) {
	if (argc != 4) {
		fprintf(stderr, "Usage: %s <interface|pcapfile> <\"live\"|\"file\"> <output_file>\n", argv[0]);
		return false;
	}

	*cxt = (t_context){0};

	char* interface = argv[1];
	char* mode = argv[2];
	cxt->output_file = fopen(argv[3], "w");
	if (!cxt->output_file) {
		fprintf(stderr, "Failed to open output file %s\n", argv[3]);
		return false;
	}

	ps_queue_init(&cxt->queue);

	cxt->connections = calloc(_PS_MAX_CONN, sizeof(t_tcp_conn));
	if (!cxt->connections) {
		fprintf(stderr, "Failed to allocate memory for connections\n");
		fclose(cxt->output_file);
		ps_queue_destroy(&cxt->queue);
		return false;
	}
	// pthread_mutex_init(&cxt->conn_mutex, NULL); // We'll see.

	char errbuf[PCAP_ERRBUF_SIZE];
	if (strcmp(mode, "live") == 0) {
		cxt->handle = pcap_open_live(interface, _PS_PACKET_CAPLEN, 1, 1000, errbuf);
		if (!cxt->handle) {
			fprintf(stderr, "pcap_create error: %s\n", errbuf);
			free(cxt->connections);
			fclose(cxt->output_file);
			ps_queue_destroy(&cxt->queue);
			return false;
		}
	} else if (strcmp(mode, "file") == 0) {
		cxt->handle = pcap_open_offline(interface, errbuf);
		if (!cxt->handle) {
			fprintf(stderr, "pcap_create error: %s\n", errbuf);
			free(cxt->connections);
			fclose(cxt->output_file);
			ps_queue_destroy(&cxt->queue);
			return false;
		}
	} else {
		fprintf(stderr, "Invalid mode: %s\n", mode);
		free(cxt->connections);
		fclose(cxt->output_file);
		ps_queue_destroy(&cxt->queue);
		pcap_close(cxt->handle);
		return false;
	}

	return true;
}

static inline void cleanup(t_context* cxt) {
	// pthread_mutex_destroy(&cxt->conn_mutex);
	free(cxt->connections);
	fclose(cxt->output_file);
	ps_queue_destroy(&cxt->queue);
	pcap_close(cxt->handle);
}

int main(int argc, char *argv[]) {
	if (argc == 4) {
		signal(SIGINT, signal_handler);
		signal(SIGTERM, signal_handler);

		t_context cxt;
		if (!init_context(&cxt, argc, argv)) {
			return 2; // Fatal
		}
		g_cxt = &cxt;


		if (!ps_threads_init(&cxt)) {
			fprintf(stderr, "Failed to initialize threads\n");
			cleanup(&cxt);
			return 1;
		}
		ps_threads_join(&cxt);

		cleanup(&cxt);
		return 0;
	}
	return 1;
}

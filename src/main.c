#include "psniff.h"
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>

t_context* g_cxt = NULL;
sig_atomic_t g_termination_requested = false;

void signal_handler(int sig) {
	if (sig == SIGINT || sig == SIGTERM) {
		g_termination_requested = true;

		if (g_cxt) {
			printf("\n[*] Terminating...\n");

			__atomic_store_n(&g_cxt->running, false, __ATOMIC_SEQ_CST);
			// Valgrind annotation - signal to other threads that running has been changed
			ANNOTATE_HAPPENS_BEFORE(&g_cxt->running);
			ps_queue_close(&g_cxt->queue);

			if (g_cxt->handle) {
				pcap_breakloop(g_cxt->handle);
				// g_cxt->handle = NULL;
			}

			ps_queue_close(&g_cxt->queue);
		}
	} else {
		fprintf(stderr, "\n[!] Received unhandled signal: %d\n", sig);
		fprintf(stderr, "[*] How did you get here anyway, huh..?\n");
		// exit(128 + sig);
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
		fprintf(stderr, "[!] Failed to open output file %s\n", argv[3]);
		return false;
	}

	ps_queue_init(&cxt->queue);

	cxt->connections = calloc(_PS_MAX_CONN, sizeof(t_tcp_conn));
	if (!cxt->connections) {
		fprintf(stderr, "[!] Failed to allocate connections array\n");
		return false;
	}

	// Setup the atomic flag for threads
	__atomic_store_n(&cxt->running, true, __ATOMIC_SEQ_CST);
	// Valgrind annotation - initialize the happens-before relation for running flag
	ANNOTATE_HAPPENS_BEFORE(&cxt->running);

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
	if (cxt) {
		if (cxt->handle) pcap_close(cxt->handle);

		if (cxt->connections) {
			// pthread_mutex_lock(&cxt->conn_mutex);
			printf("[*] Active connections during termination:\n");
			for (int i = 0; i < _PS_MAX_CONN; i++) {
				if (cxt->connections[i].is_active) {
					gettimeofday(&cxt->connections[i].end_time, NULL);
					print_connection_summary(cxt, i);
				}
			}
			// pthread_mutex_unlock(&cxt->conn_mutex);
			free(cxt->connections);
		}
		if (cxt->output_file)
			fclose(cxt->output_file);

		ps_queue_destroy(&cxt->queue);
	}
}

int main(int argc, char *argv[]) {
	if (argc == 4) {
		t_context cxt;

		// signal(SIGINT, signal_handler); // DEPR
		// signal(SIGTERM, signal_handler);

		struct sigaction sa = (struct sigaction){0};
		sa.sa_handler = signal_handler;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;
		if (sigaction(SIGINT, &sa, NULL) < 0 || sigaction(SIGTERM, &sa, NULL) < 0) {
			fprintf(stderr, "[!] Failed to set signal handler\n");
			return 2;
		}

		if (!init_context(&cxt, argc, argv)) {
			return 2; // Fatal
		}
		g_cxt = &cxt;

		printf("[+] Packet sniffer starting...\n");
    	printf("[+] Source: %s\n", argv[1]);
		printf("[+] Mode: %s\n", argv[2]);
		printf("[+] Output: %s\n", argv[3]);


		if (!ps_threads_init(&cxt)) {
			fprintf(stderr, "[!] Failed to initialize threads\n");
			cleanup(&cxt);
			return 1;
		}

		while (!g_termination_requested && __atomic_load_n(&cxt.running, __ATOMIC_SEQ_CST)) {
			// Valgrind annotation - main thread observes running flag
			ANNOTATE_HAPPENS_AFTER(&cxt.running);
			usleep(100000);
		}

		if (g_termination_requested) {
			__atomic_store_n(&cxt.running, false, __ATOMIC_SEQ_CST);
			// Valgrind annotation - signal that running has been changed
			ANNOTATE_HAPPENS_BEFORE(&cxt.running);

			if (cxt.handle) {
				pcap_breakloop(cxt.handle);
			}
		}

		printf("[+] Stopping capture. Please wait...\n");

		ps_threads_join(&cxt);

		cleanup(&cxt);
		return 0;
	}
	return 1;
}

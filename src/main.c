#include "psniff.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
	if (argc == 4) {
		const char* source = argv[1];
		const char* mode = argv[2];
		const char* output = argv[3]; (void)output; //// TODO

		pcap_t* handle;
		char errbuf[PCAP_ERRBUF_SIZE];
	
		if (strcmp(mode, "live") == 0) {
			handle = pcap_create(source, errbuf);
		} else if (strcmp(mode, "file") == 0) {
			handle = pcap_open_offline(source, errbuf);
		} else {
			fprintf(stderr, "Unknown mode: %s\n", mode);
			return 1;
		}

		if (handle == NULL) {
			fprintf(stderr, "Error opening %s: %s\n", source, errbuf);
			return 1;
		}

		// TODO: Read packets from file and write to output
		printf("[+] Reading packets from %s\n", source);

		pcap_close(handle);
		return 0;
	}
	fprintf(stderr, "Usage: %s <interface|pcapfile> <\"live\"|\"file\"> <output_file>\n", argv[0]);
	return 1;
}

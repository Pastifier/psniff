#include "psniff.h"
#include <stdio.h>

int main(int argc, char *argv[]) {
	if (argc == 3) {
	
		return 0;
	}
	fprintf(stderr, "%s <interface/pcap> <output_file>\n", argv[0]);
	return 1;
}

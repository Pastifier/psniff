#include "psniff.h"
#include <netinet/if_ether.h>
#include <netinet/ip.h>

// #define __USE_MISC // check the tcp.h file, it's there to give access to the tcphdr struct
// #include <features.h>
#define __DEFAULT_SOURCE 1
#include <netinet/tcp.h>

#define HTTP_PORT 80

/*
typedef	uint32_t tcp_seq;

 * TCP header.
 * Per RFC 793, September, 1981.

struct tcphdr
  {
    __extension__ union
    {
      struct
      {
	uint16_t th_sport;	 source port 
	uint16_t th_dport;	 destination port 
	tcp_seq th_seq;		 sequence number 
	tcp_seq th_ack;		 acknowledgement number 
# if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t th_x2:4;	 (unused) 
	uint8_t th_off:4;	 data offset 
# endif
# if __BYTE_ORDER == __BIG_ENDIAN
	uint8_t th_off:4;	 data offset 
	uint8_t th_x2:4;	 (unused) 
# endif
	uint8_t th_flags; ///////// encapsulates the flags due to union
# define TH_FIN	0x01
# define TH_SYN	0x02
# define TH_RST	0x04
# define TH_PUSH	0x08
# define TH_ACK	0x10
# define TH_URG	0x20
	uint16_t th_win;	 window 
	uint16_t th_sum;	 checksum 
	uint16_t th_urp;	 urgent pointer 
      };
      struct
      {
	uint16_t source;
	uint16_t dest;
	uint32_t seq;
	uint32_t ack_seq;
# if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t res1:4;
	uint16_t doff:4;
	uint16_t fin:1;
	uint16_t syn:1;
	uint16_t rst:1;
	uint16_t psh:1;
	uint16_t ack:1;
	uint16_t urg:1;
	uint16_t res2:2;
# elif __BYTE_ORDER == __BIG_ENDIAN
	uint16_t doff:4;
	uint16_t res1:4;
	uint16_t res2:2;
	uint16_t urg:1;
	uint16_t ack:1;
	uint16_t psh:1;
	uint16_t rst:1;
	uint16_t syn:1;
	uint16_t fin:1;
# else
#  error "Adjust your <bits/endian.h> defines"
# endif
	uint16_t window;
	uint16_t check;
	uint16_t urg_ptr;
      };
    };
};
*/

#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string.h>


static bool setup_pcap(t_context *cxt) {
    struct bpf_program fp;
    char filter_exp[] = "tcp or udp";

    if (pcap_compile(cxt->handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) < 0) {
        fprintf(stderr, "pcap_compile error: %s\n", pcap_geterr(cxt->handle));
        return false;
    }

    if (pcap_setfilter(cxt->handle, &fp) < 0) {
        fprintf(stderr, "pcap_setfilter error: %s\n", pcap_geterr(cxt->handle));
        pcap_freecode(&fp);
        return false;
    }

    pcap_freecode(&fp);
    return true;
}

static int parse_ethernet(const u_char *bytes, t_parsed_packet *parsed) {
    const struct ethhdr *eth = (const struct ethhdr *)bytes;

    memcpy(parsed->src_mac, eth, 6);
    memcpy(parsed->dst_mac, eth + (sizeof(uint8_t) * 6), 6);

    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return -1;
    }

    return sizeof(struct ethhdr);
}

static int parse_ip(const u_char *bytes, int offset, t_parsed_packet *parsed) {
    const struct iphdr *ip = (const struct iphdr *)(bytes + offset);

/*
    typedef in_addr_t uint32_t;
    struct in_addr {
        in_addr_t s_addr;
    }
    
    It seems as though the definition of the in_addr struct is there to make 
    the code more portable.
*/
    parsed->src_ip.s_addr = ip->saddr;
    parsed->dst_ip.s_addr = ip->daddr;

    parsed->protocol = ip->protocol;

    int ip_header_len = ip->ihl * sizeof(uint32_t); // ihl stores the number of 32-bit words in the header


    return offset + ip_header_len;
}

static int parse_tcp(const u_char *bytes, int offset, t_parsed_packet *parsed) {
    const struct tcphdr *tcp = (const struct tcphdr *)(bytes + offset);

    parsed->src_port = ntohs(tcp->th_sport);
    parsed->dst_port = ntohs(tcp->th_dport);

    parsed->flags = tcp->th_flags;

    int tcp_header_len = tcp->th_off * sizeof(uint32_t);

    return offset + tcp_header_len;
}

static int parse_udp(const u_char *bytes, int offset, t_parsed_packet *parsed) {
    const struct udphdr *udp = (const struct udphdr *)(bytes + offset);

    parsed->src_port = ntohs(udp->uh_sport);
    parsed->dst_port = ntohs(udp->uh_dport);

    return offset + sizeof(struct udphdr);
}

static int parse_http(const u_char *bytes, int offset, int total_len, t_parsed_packet *parsed) {
    // REMEMBER: Perhaps make string handling terminate at caplen.
    // if (parsed->protocol != IPPROTO_TCP) { // Already checked for outside
    //     return 0;
    // }

    if ((parsed->src_port != HTTP_PORT && parsed->dst_port != HTTP_PORT) // HTTP:80, HTTPS:443
        || offset >= total_len) { // Someone is trying to be sneaky.
        return 0;
    }

    const char *payload = (const char *)(bytes + offset);
    int payload_len = total_len - offset;
    if (payload_len < 4) return 0;

    if (strncmp(payload, "GET ", 4) != 0
        && strncmp(payload, "POST ", 5) != 0) {
        return 0;
    }

    parsed->has_http = true;

    const char *host = strstr(payload, "Host: ");
    if (host) {
        host += 6;
        size_t i = 0;
        while (host[i] && host[i] != '\r' && host[i] != '\n'
            && i < sizeof(parsed->host) - 1) {
            parsed->host[i] = host[i];
            ++i;
        }
        parsed->host[i] = '\0'; // Not necessary cuz I'm zeroing the struct, but eh.
    }

    const char *user_agent = strstr(payload, "User-Agent: ");
    if (user_agent) {
        user_agent += 12;
        size_t i = 0;
        while (user_agent[i] && user_agent[i] != '\r' && user_agent[i] != '\n'
            && i < sizeof(parsed->user_agent) - 1) {
            parsed->user_agent[i] = user_agent[i];
            ++i;
        }
        parsed->user_agent[i] = '\0';
    }
    return 1;
}

// typedef void (*pcap_handler)(u_char *user, const struct pcap_pkthdr *h,
//           const u_char *bytes);

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    t_context* cxt = (t_context*)user;
    t_parsed_packet parsed = (t_parsed_packet){0};

    parsed.ts = h->ts;

    // The header contains different data at different offsets, so keep that in mind.

    //// 1. Parse ethernet
    int offset = parse_ethernet(bytes, &parsed);
    
    //// 2. Parse IP
    offset = parse_ip(bytes, offset, &parsed);

    //// 3. Parse TCP/UDP
    if (parsed.protocol == IPPROTO_TCP) {
        offset = parse_tcp(bytes, offset, &parsed);
    } else if (parsed.protocol == IPPROTO_UDP) {
        offset = parse_udp(bytes, offset, &parsed);
    }

    //// 4. Parse HTTP GET/POST if TCP
    if (parsed.protocol == IPPROTO_TCP) {
        parse_http(bytes, offset, h->caplen, &parsed);
    }

    //// 5. Track connection
    int conn_index = find_or_create_connection(cxt, &parsed);
    if (conn_index >= 0) {
        update_connection(cxt, conn_index, &parsed);
    }

    //// 6. Add packet to queue
    if (!ps_queue_enqueue(&cxt->queue, &parsed)) {
        return;
    }
}

void *ps_producer_routine(void *arg) {
    t_context* cxt = (t_context*)arg;

    printf("[+] Producer thread started\n");

    //// 1: Initialize pcap
    if (!setup_pcap(cxt)) {
        __atomic_store_n(&cxt->running, false, __ATOMIC_SEQ_CST); // REMEMBER
        return NULL;
    }

    //// 2: Start sniffing
    int res = pcap_loop(cxt->handle, -1, packet_handler, (u_char*)cxt);

    //// 3: Check for errors or interruption
    switch (res)
    {
    case -1:
        fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(cxt->handle));
        break;
    case -2:
        fprintf(stderr, "pcap_loop interrupted\n");
        break;
    default:
        printf("pcap_loop exited with code %d\n", res);
        break;
    }

    return NULL;
}

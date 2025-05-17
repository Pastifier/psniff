#include "psniff.h"

/* ----- TCP Flag constants ----- */
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_ACK 0x10

static uint32_t hash_connection(struct in_addr src_ip, struct in_addr dst_ip,
        uint16_t src_port, uint16_t dst_port) {
    bool is_lower = false; // For bi-directional connections

    if (ntohl(src_ip.s_addr) < ntohl(dst_ip.s_addr)) {
        is_lower = true;
    } else if (ntohl(src_ip.s_addr) == ntohl(dst_ip.s_addr)) {
        if (src_port < dst_port) {
            is_lower = true;
        }
    }

    uint32_t hash;
    switch (is_lower)
    {
    case true:
        hash = src_ip.s_addr ^ (dst_ip.s_addr << 7) ^ src_port ^ (dst_port << 16);
        break;
    
    default:
        hash = dst_ip.s_addr ^ (src_ip.s_addr << 7) ^ dst_port ^ (src_port << 16);
        break;
    }

    return hash % _PS_MAX_CONN;
}

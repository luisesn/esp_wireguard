/* Minimal stand-in for lwIP's lwip/ip_addr.h -- see arch.h in this same
 * directory for why this is safe for fuzzing src/wireguard.c. */
#ifndef LWIP_IP_ADDR_H
#define LWIP_IP_ADDR_H

#include <stdint.h>

typedef struct {
    uint32_t addr[4]; /* big enough for an IPv4 or IPv6 address; wireguard.c
                        * never reads these bytes, only copies the struct */
} ip_addr_t;

#endif

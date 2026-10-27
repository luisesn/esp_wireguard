/* Minimal stand-in for lwIP's lwip/udp.h -- see arch.h in this same
 * directory for why this is safe for fuzzing src/wireguard.c. Only an
 * opaque forward declaration is needed: struct wireguard_device carries
 * a `struct udp_pcb *` but src/wireguard.c never dereferences it. */
#ifndef LWIP_UDP_H
#define LWIP_UDP_H

struct udp_pcb;

#endif

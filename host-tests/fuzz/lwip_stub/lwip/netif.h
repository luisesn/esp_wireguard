/* Minimal stand-in for lwIP's lwip/netif.h -- see arch.h in this same
 * directory for why this is safe for fuzzing src/wireguard.c. Only an
 * opaque forward declaration is needed: struct wireguard_device carries
 * `struct netif *` pointers but src/wireguard.c never dereferences them. */
#ifndef LWIP_NETIF_H
#define LWIP_NETIF_H

struct netif;

#endif

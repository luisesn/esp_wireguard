/* Minimal stand-in for lwIP's lwip/arch.h, for host-side fuzzing of
 * src/wireguard.c only (see host-tests/fuzz/README.md).
 *
 * src/wireguard.c and src/wireguard.h never read or write through real
 * lwIP state -- struct netif / struct udp_pcb are only ever carried as
 * opaque pointers in struct wireguard_device, and ip_addr_t fields in
 * struct wireguard_peer are only copied around, never interpreted. So
 * this only needs to provide the integer typedefs lwIP normally
 * supplies, not any real networking behavior. Do not reuse this stub
 * for anything that actually needs lwIP (e.g. fuzzing wireguardif.c,
 * which does touch pbuf/udp_pcb contents).
 */
#ifndef LWIP_ARCH_H
#define LWIP_ARCH_H

#include <stdint.h>

typedef uint8_t  u8_t;
typedef int8_t   s8_t;
typedef uint16_t u16_t;
typedef int16_t  s16_t;
typedef uint32_t u32_t;
typedef int32_t  s32_t;
typedef uintptr_t mem_ptr_t;

typedef int8_t err_t;

#endif

/* Stand-in for src/wireguard-platform.c, for host-side fuzzing only (see
 * README.md in this directory). The real wireguard-platform.c pulls in
 * PSA Crypto / esp-idf headers that don't exist on the host; wireguard.c
 * only needs these four functions to exist and behave plausibly, not to
 * be cryptographically strong -- determinism actually helps reproduce a
 * fuzzer-found crash. */
#include "wireguard-platform.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

uint32_t wireguard_sys_now(void) {
    return (uint32_t)time(NULL);
}

void wireguard_tai64n_now(uint8_t *output) {
    memset(output, 0, 12);
}

void wireguard_random_bytes(void *bytes, size_t size) {
    /* rand() is not cryptographically secure, which is fine here: this
     * is only ever used to fill nonces/keys in harness setup code, never
     * to evaluate anything security-relevant about randomness itself. */
    uint8_t *p = (uint8_t *)bytes;
    for (size_t i = 0; i < size; i++) {
        p[i] = (uint8_t)rand();
    }
}

bool wireguard_is_under_load(void) {
    return false;
}

bool wireguard_platform_time_is_synced(void) {
    return true;
}

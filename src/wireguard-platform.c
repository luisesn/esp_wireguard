#include "wireguard-platform.h"

#include <stdlib.h>
#include <time.h>
#include <inttypes.h>
#include <lwip/sys.h>
#include <psa/crypto.h>
#include <esp_system.h>
#include <esp_err.h>
#include <esp_log.h>

#include "crypto.h"

#define TAG "wireguard-platform"

/* esp-idf >= 6.0 ships mbedtls 4 / TF-PSA-Crypto, which removed the legacy
 * mbedtls_entropy_ and mbedtls_ctr_drbg_ API from its public headers (they
 * are now internal driver plumbing under tf-psa-crypto/drivers/builtin).
 * PSA Crypto's psa_generate_random() is the supported replacement and
 * maintains its own global RNG, seeded from hardware entropy by esp-idf's
 * mbedtls port -- no need to wire up esp_fill_random() as a custom entropy
 * source here, unlike the upstream (pre-mbedtls-4) version of this file. */
esp_err_t wireguard_platform_init() {
	psa_status_t status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		ESP_LOGE(TAG, "psa_crypto_init: %i", (int)status);
		return ESP_FAIL;
	}
	return ESP_OK;
}

void wireguard_random_bytes(void *bytes, size_t size) {
	psa_status_t status = psa_generate_random((uint8_t *)bytes, size);
	if (status != PSA_SUCCESS) {
		/* wireguard_random_bytes() has no error return; this is used for
		 * key material, so abort rather than silently hand back
		 * unmodified (and possibly predictable) buffer contents. */
		ESP_LOGE(TAG, "psa_generate_random: %i", (int)status);
		abort();
	}
}

uint32_t wireguard_sys_now() {
	// Default to the LwIP system time
	return sys_now();
}

void wireguard_tai64n_now(uint8_t *output) {
	// See https://cr.yp.to/libtai/tai64.html
	// 64 bit seconds from 1970 = 8 bytes
	// 32 bit nano seconds from current second

	struct timeval tv;
	gettimeofday(&tv, NULL);

	uint64_t seconds = 0x400000000000000aULL + tv.tv_sec;
	uint32_t nanos = tv.tv_usec * 1000;
	U64TO8_BIG(output + 0, seconds);
	U32TO8_BIG(output + 8, nanos);
}

/* Always "not under load": the cookie-reply DoS mitigation (RFC-style
 * MAC2/cookie challenge in wireguard_process_initiation_message(), see
 * src/wireguard.c) never engages. For this fork's scope -- a
 * single-peer, point-to-point tunnel, not a multi-peer VPN gateway
 * exposed to arbitrary initiators -- that's an acceptable trade-off: the
 * only thing that could flood this endpoint with initiation attempts is
 * whoever already has (or is guessing at) the one peer's keys, and the
 * existing per-peer MAX_INITIATIONS_PER_SECOND rate limit (see issue #4
 * in CHANGES-fork.md) already bounds how often a bad actor can make us
 * do the expensive part (the Noise handshake crypto) regardless of
 * whether a cookie challenge is also in play. If this library is ever
 * used for a multi-peer or internet-facing responder role, this should
 * return true once some real signal (CPU load, concurrent handshake
 * count, a request-rate counter) exceeds a threshold, so the cookie path
 * actually exercises. Untested as a result: this fork's hardware
 * verification has never exercised wireguard_handle_cookie_reply() /
 * the cookie half of wireguard_process_initiation_message(). */
bool wireguard_is_under_load() {
	return false;
}
// vim: noexpandtab

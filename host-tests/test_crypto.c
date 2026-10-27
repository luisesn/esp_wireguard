/*
 * Host-side test harness for src/crypto/refc (Task #6 in CHANGES-fork.md).
 *
 * Compiles the actual library source files for a native gcc build (no
 * ESP-IDF, no hardware) and checks their output against an independent
 * reference: Python's hashlib.blake2s() for BLAKE2s, and the
 * `cryptography` package (OpenSSL-backed X25519 and ChaCha20-Poly1305)
 * for X25519 and the AEAD construction -- see host-tests/gen_vectors.py,
 * which produced vectors.h.
 *
 * This only tests the primitives in isolation (not the full WireGuard
 * handshake state machine, which still needs the Phase 3 audit items
 * noted as open in CHANGES-fork.md -- TAI64N source, cookie-under-load,
 * fuzzing). It answers a narrower but still useful question: does this
 * codebase's crypto math agree with a trusted independent implementation.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "../src/crypto/refc/blake2s.h"
#include "../src/crypto/refc/x25519.h"
#include "../src/crypto/refc/chacha20.h"
#include "../src/crypto/refc/chacha20poly1305.h"

#include "vectors.h"

static int g_failures = 0;

static void check(const char *name, int ok) {
    if (ok) {
        printf("  [PASS] %s\n", name);
    } else {
        printf("  [FAIL] %s\n", name);
        g_failures++;
    }
}

static int bytes_eq(const uint8_t *a, const uint8_t *b, size_t len) {
    return memcmp(a, b, len) == 0;
}

static void test_blake2s(void) {
    printf("-- BLAKE2s (vs Python hashlib.blake2s) --\n");
    char label[64];
    for (int i = 0; i < BLAKE2S_NUM_CASES; i++) {
        uint8_t out[32];
        const struct blake2s_case *c = &blake2s_cases[i];
        int rc = blake2s(out, sizeof(out), NULL, 0, c->msg, c->msg_len);
        snprintf(label, sizeof(label), "unkeyed case %d (msg_len=%zu)", i, c->msg_len);
        check(label, rc == 0 && bytes_eq(out, c->expect, 32));
    }

    {
        uint8_t out[32];
        int rc = blake2s(out, sizeof(out), blake2s_keyed_key, sizeof(blake2s_keyed_key),
                          blake2s_keyed_msg, sizeof(blake2s_keyed_msg));
        check("keyed case", rc == 0 && bytes_eq(out, blake2s_keyed_expect, 32));
    }

    /* also exercise the streaming (init/update/final) API, not just the
     * all-in-one convenience function, since wireguard.c itself only ever
     * uses the streaming API (incremental handshake-hash chaining) */
    {
        blake2s_ctx ctx;
        uint8_t out[32];
        const struct blake2s_case *c = &blake2s_cases[2]; /* "quick brown fox" */
        blake2s_init(&ctx, 32, NULL, 0);
        /* feed it in three uneven chunks to exercise the internal buffer
         * logic across block boundaries, not just one shot */
        size_t n = c->msg_len;
        size_t a = n / 3, b = n / 3;
        blake2s_update(&ctx, c->msg, a);
        blake2s_update(&ctx, c->msg + a, b);
        blake2s_update(&ctx, c->msg + a + b, n - a - b);
        blake2s_final(&ctx, out);
        check("streaming API, chunked, matches all-in-one", bytes_eq(out, c->expect, 32));
    }
}

static void test_x25519(void) {
    printf("-- X25519 (vs Python `cryptography` package) --\n");
    char label[64];

    for (int i = 0; i < X25519_NUM_BASEMULT_CASES; i++) {
        uint8_t out[32];
        const struct x25519_case *c = &x25519_basemult_cases[i];
        int rc = x25519(out, c->scalar, X25519_BASE_POINT, 1);
        snprintf(label, sizeof(label), "scalar*basepoint case %d", i);
        check(label, rc == 0 && bytes_eq(out, c->expect, 32));
    }

    for (int i = 0; i < X25519_NUM_DH_CASES; i++) {
        uint8_t pub_a[32], pub_b[32], shared_a[32], shared_b[32];
        const struct x25519_dh_case *c = &x25519_dh_cases[i];

        x25519(pub_a, c->a, X25519_BASE_POINT, 1);
        x25519(pub_b, c->b, X25519_BASE_POINT, 1);
        snprintf(label, sizeof(label), "DH case %d: derived pub_a matches", i);
        check(label, bytes_eq(pub_a, c->pub_a, 32));
        snprintf(label, sizeof(label), "DH case %d: derived pub_b matches", i);
        check(label, bytes_eq(pub_b, c->pub_b, 32));

        /* the actual DH: both sides must arrive at the same shared secret,
         * and it must match the independent reference's shared secret */
        x25519(shared_a, c->a, pub_b, 1);
        x25519(shared_b, c->b, pub_a, 1);
        snprintf(label, sizeof(label), "DH case %d: a's view == b's view", i);
        check(label, bytes_eq(shared_a, shared_b, 32));
        snprintf(label, sizeof(label), "DH case %d: shared secret matches reference", i);
        check(label, bytes_eq(shared_a, c->shared, 32));
    }
}

static void test_aead(void) {
    printf("-- ChaCha20-Poly1305 AEAD, WireGuard nonce convention (vs Python `cryptography`) --\n");
    char label[80];

    for (int i = 0; i < AEAD_NUM_CASES; i++) {
        const struct aead_case *c = &aead_cases[i];
        uint8_t *dst = malloc(c->pt_len + 16);
        uint8_t *recovered = malloc(c->pt_len ? c->pt_len : 1);

        chacha20poly1305_encrypt(dst, c->pt, c->pt_len, c->ad, c->ad_len, c->nonce, c->key);
        snprintf(label, sizeof(label), "encrypt case %d (pt_len=%zu ad_len=%zu) matches reference",
                 i, c->pt_len, c->ad_len);
        check(label, bytes_eq(dst, c->expect, c->pt_len + 16));

        bool ok = chacha20poly1305_decrypt(recovered, dst, c->pt_len + 16, c->ad, c->ad_len, c->nonce, c->key);
        snprintf(label, sizeof(label), "decrypt case %d: tag verifies and plaintext round-trips", i);
        check(label, ok && (c->pt_len == 0 || bytes_eq(recovered, c->pt, c->pt_len)));

        /* tamper with one ciphertext/tag byte and confirm decrypt rejects it --
         * this is the actual security property the AEAD exists for */
        if (c->pt_len + 16 > 0) {
            dst[0] ^= 0x01;
            bool should_fail = chacha20poly1305_decrypt(recovered, dst, c->pt_len + 16, c->ad, c->ad_len, c->nonce, c->key);
            snprintf(label, sizeof(label), "decrypt case %d: tampered ciphertext is rejected", i);
            check(label, !should_fail);
        }

        free(dst);
        free(recovered);
    }
}

int main(void) {
    test_blake2s();
    test_x25519();
    test_aead();

    printf("\n");
    if (g_failures == 0) {
        printf("All host-side crypto checks passed.\n");
        return 0;
    } else {
        printf("%d check(s) FAILED.\n", g_failures);
        return 1;
    }
}

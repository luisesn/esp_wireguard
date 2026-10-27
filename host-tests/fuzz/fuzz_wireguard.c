/*
 * libFuzzer harness for src/wireguard.c's incoming-packet parsers --
 * Phase 3's last open item in CHANGES-fork.md ("fuzzing of the packet
 * parser"). See README.md in this directory for scope, build/run
 * instructions, and what this does and doesn't cover.
 *
 * Approach: build one real two-party handshake (device A = responder
 * under test, device B = a simulated peer) using the library's own
 * wireguard_create_*() functions, so we have *valid* template messages
 * of each type. Each fuzz iteration then overlays the fuzzer's raw bytes
 * onto a fresh copy of one of those templates (byte 0 of the input picks
 * which message type and which template copy) before calling the real
 * parser. Overlaying onto a valid template, rather than fuzzing from an
 * all-random buffer, is what lets the coverage-guided fuzzer actually
 * reach past the MAC1/AEAD authentication checks into the deeper parsing
 * and state-update logic most of the time, instead of bouncing off
 * "authentication failed" on nearly every run.
 */
#include <stdint.h>
#include <string.h>

#include "wireguard.h"

/* CONFIG_WIREGUARD_x25519_IMPLEMENTATION_DEFAULT must be defined for
 * every translation unit that includes crypto.h (src/wireguard.c,
 * src/crypto.c) -- the Makefile passes it as a compiler flag so it
 * applies uniformly, rather than defining it here where it would only
 * affect this file. */

static struct wireguard_device device_a; /* responder -- the one under test */
static struct wireguard_device device_b; /* simulated remote peer */
static struct wireguard_peer *peer_b_at_a; /* how A sees B */
static struct wireguard_peer *peer_a_at_b; /* how B sees A */

static struct message_handshake_initiation initiation_template;
static struct message_handshake_response response_template;
static struct message_cookie_reply cookie_template;

static const uint8_t private_key_a[WIREGUARD_PRIVATE_KEY_LEN] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
};
static const uint8_t private_key_b[WIREGUARD_PRIVATE_KEY_LEN] = {
    32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
    16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
};

/* Overlay up to sizeof(*tmpl) bytes from (data, size) onto a copy of a
 * valid template message, returning the copy in *out. Mutating only
 * from byte 0 rather than resizing keeps every message at its correct,
 * fixed on-wire length -- wireguard_get_message_type()'s length check
 * already has its own dedicated exercise (fuzz_get_message_type below),
 * so these targets focus on content, not length, validation. */
static void overlay(void *out, const void *tmpl, size_t tmpl_len, const uint8_t *data, size_t size) {
    memcpy(out, tmpl, tmpl_len);
    size_t n = size < tmpl_len ? size : tmpl_len;
    memcpy(out, data, n);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;

    memset(&device_a, 0, sizeof(device_a));
    memset(&device_b, 0, sizeof(device_b));

    if (!wireguard_device_init(&device_a, private_key_a)) {
        return 1;
    }
    if (!wireguard_device_init(&device_b, private_key_b)) {
        return 1;
    }

    static struct wireguard_peer peer_storage_a, peer_storage_b;
    if (!wireguard_peer_init(&device_a, &peer_storage_a, device_b.public_key, NULL)) {
        return 1;
    }
    if (!wireguard_peer_init(&device_b, &peer_storage_b, device_a.public_key, NULL)) {
        return 1;
    }
    peer_b_at_a = &peer_storage_a;
    peer_a_at_b = &peer_storage_b;

    /* B -> A: a real, validly-authenticated initiation. */
    if (!wireguard_create_handshake_initiation(&device_b, peer_a_at_b, &initiation_template)) {
        return 1;
    }
    /* wireguardif.c normally stashes the mac1 we *sent* on the peer
     * record before handing the packet to the network, so that a later
     * cookie reply from the far end can be decrypted against it. Mirror
     * that bookkeeping here since this harness bypasses wireguardif.c
     * entirely. */
    memcpy(peer_a_at_b->handshake_mac1, initiation_template.mac1, WIREGUARD_COOKIE_LEN);
    peer_a_at_b->handshake_mac1_valid = true;

    /* A processes it for real, and replies -- this is also how A learns
     * about peer_b_at_a's handshake state for the response template
     * below. */
    struct message_handshake_initiation initiation_copy = initiation_template;
    struct wireguard_peer *responder_view = wireguard_process_initiation_message(&device_a, &initiation_copy);
    if (responder_view == NULL) {
        return 1;
    }
    if (!wireguard_create_handshake_response(&device_a, responder_view, &response_template)) {
        return 1;
    }

    /* A simulated cookie reply from A back to B, as if A were under
     * load. Not actually gated on wireguard_is_under_load() here --
     * wireguard_create_cookie_reply() just builds the message; we want
     * a structurally valid reply to fuzz regardless. */
    wireguard_create_cookie_reply(&device_a, &cookie_template, initiation_template.mac1,
                                   peer_a_at_b->handshake.local_index, NULL, 0);

    return 0;
}

static void fuzz_get_message_type(const uint8_t *data, size_t size) {
    (void)wireguard_get_message_type(data, size);
}

static void fuzz_process_initiation(const uint8_t *data, size_t size) {
    struct message_handshake_initiation msg;
    overlay(&msg, &initiation_template, sizeof(msg), data, size);
    (void)wireguard_process_initiation_message(&device_a, &msg);
}

static void fuzz_process_response(const uint8_t *data, size_t size) {
    struct message_handshake_response msg;
    overlay(&msg, &response_template, sizeof(msg), data, size);
    (void)wireguard_process_handshake_response(&device_b, peer_a_at_b, &msg);
}

static void fuzz_process_cookie(const uint8_t *data, size_t size) {
    struct message_cookie_reply msg;
    overlay(&msg, &cookie_template, sizeof(msg), data, size);
    /* wireguard_process_cookie_message() requires handshake_mac1_valid;
     * LLVMFuzzerInitialize sets it once, but a successful decrypt clears
     * it again (see src/wireguard.c), so put it back before each call --
     * otherwise only the very first corpus entry would ever reach the
     * decrypt path. */
    peer_a_at_b->handshake_mac1_valid = true;
    (void)wireguard_process_cookie_message(&device_b, peer_a_at_b, &msg);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    uint8_t selector = data[0];
    const uint8_t *rest = data + 1;
    size_t rest_size = size - 1;

    /* Every run also exercises the length/type dispatcher directly on
     * the raw, unmodified input -- this is the function CHANGES-fork.md
     * specifically called out (issue review of wireguard_get_message_type()'s
     * length bounds). */
    fuzz_get_message_type(data, size);

    switch (selector % 3) {
        case 0:
            fuzz_process_initiation(rest, rest_size);
            break;
        case 1:
            fuzz_process_response(rest, rest_size);
            break;
        case 2:
            fuzz_process_cookie(rest, rest_size);
            break;
    }

    return 0;
}

# Fork changes

This file tracks how `luisesn/esp_wireguard` diverges from
[trombik/esp_wireguard](https://github.com/trombik/esp_wireguard), and
progress against the implementation plan below. It is not a changelog in
the conventional sense (no version numbers per entry); it exists so future
work — by Luis or by Claude in a later session — has context without
re-deriving it from the commit history.

## Goal

A WireGuard library for ESP-IDF native (no Arduino), scoped to:

- Point-to-point tunnel to a single WireGuard peer (not a full VPN gateway
  with routing/NAT).
- TCP and UDP over the tunnel (so the lwIP `netif` approach is kept, not a
  from-scratch minimal UDP-only implementation).
- `esp-idf >= 6.0` only.
- `esp32` chip family only (`esp32`, `esp32s2`, `esp32s3`, `esp32c3`).
  Since the crypto core has no hardware dependency, other targets should
  build with little extra work, but are untested and not a goal for now.

## Why fork instead of using upstream directly

Upstream's most recent tagged release only supports `esp-idf` up to
`4.4.x`, and does not support `esp-idf 5.x`/`6.x` without changes (see
`netif_add` crash below, and the upstream issue tracker:
[trombik/esp_wireguard#33](https://github.com/trombik/esp_wireguard/issues/33),
closed upstream
([espressif/esp-idf#9643](https://github.com/espressif/esp-idf/issues/9643))
as "Won't Do" — Espressif does not consider it something ESP-IDF itself
should fix, so it is on library authors to work around.

## Known issues to fix (not yet fixed)

### 1. `netif_add()` crash on `esp-idf >= 5.x`

`esp_wireguard_netif_create()` in `src/esp_wireguard.c` calls lwIP's
`netif_add()` directly with a raw `struct netif`, bypassing `esp_netif`.
On `esp-idf >= 5.x`, `esp_netif` registers a global lwIP extended
callback that fires for every `netif` added to lwIP — not just the ones it
created itself — and assumes it can map the raw `netif` back to an
`esp_netif_t`. For the WireGuard `netif`, which was never registered with
`esp_netif`, this assumption breaks, and the chain `netif_add` →
`netif_set_addr` → esp_netif's callback → `esp_netif_internal_dhcpc_cb`
crashes.

This has not yet been reproduced on `esp-idf 6.0.2` in this fork (that is
the next step — see Phase 1 below), but the code path is unchanged from
upstream and the root cause (bypassing `esp_netif`) is still present, so
it is expected to still crash.

Two possible fixes, in order of preference:

1. Register the WireGuard `netif` as a proper `esp_netif_t` with a custom
   driver (the mechanism PPP and Ethernet drivers use), so `esp_netif`'s
   bookkeeping is consistent for every `netif` in the system.
2. If (1) turns out to be too invasive, keep the raw `netif_add()` but
   make the WireGuard device data available via lwIP's `netif` client-data
   slots instead of (ab)using `netif->state`, and confirm whether that
   alone avoids tripping `esp_netif`'s callback. This is a narrower fix,
   but a point fix rather than a structural one; worth trying first since
   it's cheap to test, but router 1 above is the one to land on if this
   doesn't hold up.

### 2. No `tcpip_core` locking

Calls into lwIP's `netif` API (`netif_add`, `netif_remove`, timers) are
made without `LOCK_TCPIP_CORE()` / `UNLOCK_TCPIP_CORE()` or
`esp_netif_tcpip_exec()`. With `CONFIG_LWIP_TCPIP_CORE_LOCKING` enabled
(the esp-idf default), this trips an assert. Needs auditing across
`src/esp_wireguard.c` and the connect/disconnect/reconnect paths.

### 3. Cryptokey routing direction — CONFIRMED and FIXED

This codebase had the same bug as the `wireguard-lwip` fork mentioned
above. In `wireguardif_process_data_message()` (`src/wireguardif.c`),
after decrypting an inbound transport-data packet, the code copied
`iphdr->dest` (the decrypted inner packet's *destination* address) into
the variable it then checked against `peer->allowed_source_ips` —
despite the code's own inline comment, carried over from upstream,
literally saying "checks to see if the **source** IP address of the
plaintext inner-packet routes correspondingly in the cryptokey routing
table". Confirmed against lwIP's `struct ip_hdr` (`components/lwip` in
esp-idf 6.0.2): `src` and `dest` are distinct, correctly-named fields;
this was not a naming ambiguity, the wrong field was read.

Effect: a connected peer could send decrypted packets claiming to
originate from any source address, as long as the packet's
*destination* fell inside that peer's own allowed-ips range, which
defeats cryptokey routing as an ingress filter (its entire purpose per
the WireGuard whitepaper). For a single-peer point-to-point tunnel with
a narrow `allowed_ip`, the practical exposure is limited — there's only
one peer to begin with — but it's still a straightforwardly wrong
security check, worth fixing regardless of this fork's scope, and
matters more if/when the library is used with more than one peer.

Fixed: renamed the local variable from `dest`/`dest_ok` to
`pkt_src`/`src_ok`, and changed `iphdr->dest` to `iphdr->src`. The IPv6
branch was already a no-op TODO (`dest_ok = true` unconditionally, no
filtering) — left as-is but the comment now says explicitly that IPv6
ingress filtering is unimplemented, so it doesn't read as "same check,
different code path" by a future reader.

### 4. Handshake-initiation rate limit was inverted — CONFIRMED and FIXED

Found during the same audit pass, not previously tracked as an issue.
In `wireguard_process_initiation_message()` (`src/wireguard.c`), the
per-peer rate limit on accepting handshake initiations was:

    rate_limit = (peer->last_initiation_rx - now) < (1000 / MAX_INITIATIONS_PER_SECOND);

Both operands are `uint32_t` millisecond timestamps, and in the normal
case `now >= peer->last_initiation_rx` (time moves forward), so
`last_initiation_rx - now` underflows and wraps to a value near
`UINT32_MAX` — essentially never less than the threshold (500ms at the
default `MAX_INITIATIONS_PER_SECOND=2`). The operands were reversed:
it should be `now - peer->last_initiation_rx`. As written, the rate
limit was silently a no-op in the normal case (every initiation that
passed the timestamp-replay check was accepted, however frequent),
except for one tick right at a ~49.7-day uint32 ms wraparound, where it
would spuriously fire. Fixed by swapping the subtraction order.

### 5. TAI64N timestamp has no persistence across reboots — design decision needed, not yet fixed

`wireguard_tai64n_now()` (`src/wireguard-platform.c`) builds the
handshake-initiation timestamp from `gettimeofday()`, i.e. the libc wall
clock. The ESP32 has no battery-backed RTC, so this clock resets to
(effectively) the epoch on every reboot and only becomes meaningful again
once `examples/demo`'s `obtain_time()` (SNTP) completes.

This matters because of the anti-replay check on the *responder* side of
a handshake initiation — `wireguard_process_initiation_message()` in
`src/wireguard.c` (line ~621): `replay = memcmp(t, peer->greatest_timestamp,
...) <= 0`. A new initiation's timestamp must be strictly greater than the
highest one previously seen from that peer, or it's rejected as a replay.
When this fork's ESP32 is the *initiator* (the normal case here), that
check runs on the remote hub, not on the ESP32 — but the hub's
`greatest_timestamp` high-water-mark for this peer only ever moves
forward, while the ESP32's clock resets on every reboot. If the ESP32
reconnects before `obtain_time()` has actually synced (SNTP failed, no
network yet, or the application just doesn't call it), it will send a
timestamp *lower* than the hub's high-water mark, and the hub will
silently reject the handshake — a confusing failure that looks identical
to "wrong keys" or "no connectivity" unless you know to suspect the clock.
(The same class of problem also exists in the other direction, for
`greatest_timestamp` tracked *inside* this codebase's own `peer` struct,
should the remote end ever initiate a handshake to the ESP32 instead of
the reverse — same root cause, same fix.)

This is a known gap in the upstream code too, not something introduced by
this fork: there's a `// TODO: Need to notify if the higher layers want to
persist latest timestamp/nonce somewhere` immediately after the
`greatest_timestamp` update in `wireguard_process_initiation_message()`.

Candidate fixes, roughly in order of effort:

1. **Do nothing to the clock; make the failure visible instead.** Have
   the application (or a small helper this library exposes) refuse to
   call `esp_wireguard_connect()` — or at least log a clear warning —
   until SNTP has actually reported success, rather than silently
   proceeding with an unsynced clock as `examples/demo/main/main.c`
   currently does. Cheapest, but doesn't fix reconnects where SNTP is
   briefly unavailable right after a reboot (e.g. WiFi not up yet).
2. **Persist a high-water-mark wall-clock value in NVS.** On each
   successful handshake (or periodically), save the current `time()` to
   NVS. On boot, before any connection attempt, seed the clock
   (`settimeofday()`) to at least that persisted value — this guarantees
   monotonicity across reboots without needing a real RTC or even a
   successful SNTP sync, since TAI64N only needs to be non-decreasing and
   roughly plausible, not exactly correct to the second. Layer SNTP on
   top as normal once/if the network comes up, since real NTP time will
   always be >= the persisted floor anyway. This is the fix I'd actually
   recommend; it's a moderate change (needs `nvs_flash` as a dependency
   of this component, not just the example) but directly closes the gap
   rather than papering over it.
3. **A battery-backed or supercap RTC module** (e.g. DS3231) wired to the
   ESP32, read at boot before anything else. Solves it at the hardware
   level instead of software, but is a hardware BOM change, not something
   this library can do on its own, and is overkill if (2) is acceptable.

Leaning towards (2) as the one worth implementing, with (1) as a cheap
complementary safety net regardless (surfacing the failure clearly is
good practice even once (2) exists, for the case where NVS itself is
freshly erased). Not implemented yet — flagging here for a decision
before touching `wireguard-platform.c`, since it adds a dependency
(`nvs_flash`) this component doesn't currently have, and changing it
while hardware testing is in progress on the exact connect/disconnect
path this touches would make that test's results harder to attribute.

## What's been done

- Removed ESP8266 RTOS SDK and the pre-4.1 "TCP/IP Adapter" code paths
  from `src/wireguardif.c`, `Kconfig`, `examples/demo/main/main.c`, and
  deleted `component.mk` (GNU Make build, used only by the ESP8266 RTOS
  SDK toolchain; the CMake build is the only one this fork supports).
  `ESP-NETIF` is now the only adapter; `CONFIG_WIREGUARD_ESP_NETIF` is
  kept (hardcoded `y`) so the existing `#if defined(...)` guards in the
  C code don't need touching everywhere at once.
- `CMakeLists.txt`: added a `FATAL_ERROR` guard if built against
  `esp-idf < 6`, and kept the `x25519.c` `-Wno-error=stringop-overread`
  suppression unconditionally rather than gated to `IDF_VERSION_MAJOR
  STREQUAL 5` (it's a known false positive from GCC's pointer-arithmetic
  analysis in that file, not something specific to one esp-idf version).
- `idf_component.yml`: declared `idf: ">=6.0"` and the four supported
  targets; bumped `version` to `0.1.0` to mark this as a fork with a
  different scope, not a continuation of upstream's `0.9.0` line; `url`
  points at this fork.
- README rewritten to describe the fork's scope and point at this file
  instead of claiming upstream's broader support matrix.
- Installed `esp-idf 6.0.2` and built `examples/demo` for `esp32` end to
  end (`idf.py build`, clean rebuild from `fullclean`): it now produces
  `demo.bin` with no compiler warnings and no errors. This surfaced, and
  this commit fixes, three things specific to `esp-idf 6.0`/mbedtls 4
  that are independent of the `netif_add` crash (issue #1), which is a
  *runtime* crash on real hardware and so could not be reproduced by a
  build alone:
  - `src/wireguard.c`: the four fixed-length protocol byte constants
    (`CONSTRUCTION`, `IDENTIFIER`, `LABEL_MAC1`, `LABEL_COOKIE`) are
    declared as `uint8_t[N]` initialized from a string literal exactly
    `N` bytes long, i.e. with no room for a NUL terminator — intentional,
    since they're used with `sizeof()`, never as C strings. The 6.0
    toolchain's GCC treats that as an error
    (`-Werror=unterminated-string-initialization`, new upstream in
    GCC 13). Marked `__attribute__((nonstring))` on all four.
  - `src/wireguard-platform.c`: rewritten to use PSA Crypto
    (`psa_crypto_init()` / `psa_generate_random()`) instead of the
    legacy `mbedtls_entropy_*`/`mbedtls_ctr_drbg_*` API, which `esp-idf
    6.0`'s mbedtls 4 / TF-PSA-Crypto no longer exposes as public headers
    (`mbedtls/entropy.h` now lives under
    `tf-psa-crypto/drivers/builtin/include/mbedtls/private/`, i.e. it's
    internal driver plumbing now). This is the mbedtls-4/PSA migration
    anticipated during planning; it only touches this file; the
    WireGuard crypto primitives themselves
    (`src/crypto/refc/*`, `src/nacl/*`) are self-contained and untouched.
  - `examples/demo/main/main.c`: `ESP_IF_WIFI_STA` was removed in
    `esp-idf 6.0`; replaced with `WIFI_IF_STA` per the toolchain's own
    hint.
  - `examples/demo/main/sync_time.c`: switched from the deprecated
    `sntp_*` function names to their `esp_sntp_*` replacements (the
    header, `esp_sntp.h`, was already correct; only the four call sites
    were on the deprecated names, which are warnings here, not build
    failures, but worth cleaning up since Phase 1 explicitly names this).

Not yet touched: `.github/workflows/*` (still targets the old version
matrix; will be rewritten in Phase 6).

## Implementation plan

- [x] **Phase 0 — Preparation.** Fork cloned, compared against upstream
      (no divergence at fork time). Licensing: BSD-3-Clause, kept as-is;
      `WireGuard` is a registered trademark — the brand notice in the
      README (inherited from upstream) stays.
- [x] **Phase 1 — Baseline on 6.0.2.** `examples/demo` builds clean
      (zero warnings, zero errors) for `esp32` on `esp-idf 6.0.2`. The
      `netif_add` crash (issue #1) is a *runtime* crash — it was not,
      and could not be, reproduced by this build-only verification; it
      still needs to be checked on real hardware (or in Phase 2, once
      the fix is in and can be tested against it directly).
- [ ] **Phase 2 — Network interface and locking (blocking).** Fix issue
      #1 (netif/esp_netif registration) and #2 (tcpip_core locking)
      above. Exit criterion: 100 connect/disconnect cycles with no
      crash, no assert, no leak.
- [~] **Phase 3 — Core audit.** Done so far, by manual review (not yet
      hardware-tested, but all of it builds clean — see commit):
      cryptokey routing direction (issue #3, confirmed + fixed),
      handshake-initiation rate limit (found + fixed, see issue #4),
      packet-parsing length bounds (`wireguard_get_message_type()`
      validates every message type's exact or minimum length before
      the caller casts the buffer — correct), constant-time comparison
      (`crypto_equal()` in `src/crypto.c` is branch-free XOR-accumulate,
      used correctly for MAC1/MAC2 verification — correct), key erasure
      (`crypto_zero()` uses a `volatile` pointer so the compiler can't
      optimize the wipe away; `keypair_destroy()` zeroes the whole
      keypair struct — correct). Noted but not changed: the replay
      window is 32 bits wide (`uint32_t replay_bitmap` in
      `wireguard.h`), narrower than reference WireGuard implementations
      typically use; this isn't a security hole (it can't let a replay
      through), only a reliability one (packets reordered by more than
      32 sequence numbers get spuriously dropped as "too old") — left
      alone since fixing it means widening the bitmap type and isn't
      cheap to verify without hardware to generate real reordering.
      Still open: TAI64N timestamp source/monotonicity across reboots
      (issue #5 above — root-caused, candidate fixes written up, waiting
      on a decision before touching `wireguard-platform.c`), cookie
      reply handling under load (now explicitly documented, still
      untested — `wireguard_is_under_load()` in `wireguard-platform.c`
      always returns `false`, so the DoS-mitigation cookie path is never
      exercised; a comment at the function now spells out why this is
      an acceptable trade-off for a single-peer point-to-point tunnel
      per the original scope, and what would need to change if this
      library is ever used in a multi-peer/internet-facing responder
      role). Host-side test vectors for
      ChaCha20-Poly1305 / X25519 / BLAKE2s: **done** — see
      `host-tests/` (native `gcc` build, no ESP-IDF/hardware needed;
      `make check`). All three primitives cross-checked against
      independent reference implementations (Python's `hashlib.blake2s`,
      and the `cryptography` package for X25519 and the AEAD
      construction in this codebase's actual 64-bit-counter nonce
      convention) rather than hand-copied published constants — see
      `host-tests/README.md` for why. 34/34 checks pass, including
      tamper-rejection of the AEAD tag, and a clean run under
      ASan+UBSan (`make asan`). Still open: fuzzing of the packet
      parser (not started).
- [ ] **Phase 4 — TCP and performance.** MTU/MSS tuning, `iperf`/HTTP/TCP
      echo testing, 24h soak test across rekeys and WiFi drops,
      measurement-driven optimization only (no speculative tuning).
- [ ] **Phase 5 — Public API.** `esp_event` events (handshake done, peer
      down, session expired) instead of polling; auto-reconnect on IP
      recovery; endpoint re-resolution on reconnect (currently only
      resolved once, at connect time); document the synced-time
      requirement and WiFi power-save implications.
- [ ] **Phase 6 — Tests and CI.** Rewrite `.github/workflows/build.yml`
      for `esp-idf 6.0.x` only, across `esp32`/`esp32s2`/`esp32s3`/
      `esp32c3`; host-side unit tests in CI; hardware-in-the-loop tests
      against a real peer (needs a self-hosted runner — not available
      yet).
- [ ] **Phase 7 — Publish.** Minimal point-to-point TCP client example,
      changelog, semver, component registry listing.

### Definition of "MVP done"

The ESP32 establishes a tunnel to a Linux peer, holds a TCP connection for
24h across rekeys and WiFi drops, and everything builds clean (no
warnings) on `esp-idf 6.0.x`.

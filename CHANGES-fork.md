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

### 3. Cryptokey routing direction (upstream bug, unverified in this fork)

A known fork of `wireguard-lwip` fixed a bug where cryptokey routing
checked the destination IP instead of the source IP of incoming packets.
Not yet confirmed whether this codebase (derived from the same upstream)
has the same bug — needs auditing in `src/wireguardif.c` /
`src/wireguard.c` as part of Phase 3 below.

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

Not yet touched: `.github/workflows/*` (still targets the old version
matrix; will be rewritten in Phase 6), `examples/demo/main/sync_time.c`
(SNTP time sync — untouched, still relevant since the protocol still
needs synced time).

## Implementation plan

- [x] **Phase 0 — Preparation.** Fork cloned, compared against upstream
      (no divergence at fork time). Licensing: BSD-3-Clause, kept as-is;
      `WireGuard` is a registered trademark — the brand notice in the
      README (inherited from upstream) stays.
- [~] **Phase 1 — Baseline on 6.0.2.** Legacy code removed (this commit).
      Still to do: install `esp-idf 6.0.2`, build `examples/demo`,
      confirm it now fails *only* on the known `netif_add` crash (issue
      #1 above), with no other warnings-as-errors breakage from the 6.0
      toolchain (e.g. the `sntp.h` → `esp_sntp.h` rename).
- [ ] **Phase 2 — Network interface and locking (blocking).** Fix issue
      #1 (netif/esp_netif registration) and #2 (tcpip_core locking)
      above. Exit criterion: 100 connect/disconnect cycles with no
      crash, no assert, no leak.
- [ ] **Phase 3 — Core audit.** Cryptokey routing direction (issue #3),
      packet-parsing bounds, replay window, constant-time comparisons,
      key erasure, MAC1 verification, cookie replies, protocol timers,
      TAI64N timestamp source/monotonicity across reboots. Host-side
      tests: known ChaCha20-Poly1305 / X25519 / BLAKE2s test vectors,
      fuzzing of the packet parser.
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

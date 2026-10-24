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

## Known issues

### 1. `netif_add()` crash on `esp-idf >= 5.x` — root cause confirmed, fix drafted (Phase 2 branch)

Confirmed by reading the `esp-idf 6.0.2` source
(`components/esp_netif/lwip/esp_netif_lwip.c`,
`components/lwip/port/include/lwipopts.h`,
`components/lwip/lwip/src/core/netif.c`), not just inferred from the
upstream report:

`esp_wireguard_netif_create()` calls lwIP's `netif_add()` directly with a
raw `struct netif` whose `state` field is, at that point, a
`struct wireguardif_init_data *` living on the caller's stack (it is only
replaced with the real `struct wireguard_device *` later, inside
`wireguardif_init()`, which `netif_add()` calls as its very last step).

`netif_add()`, before calling that `init()` callback, calls
`netif_set_addr()` to install the real static IP/netmask/gateway this
component always passes in. `netif_set_addr()` fires lwIP's ext-callback
chain with a `LWIP_NSC_IPV4_*_CHANGED` reason whenever the address
actually changes — which it does here, from `0.0.0.0` to the configured
address. `esp_netif` registers exactly one such ext callback,
`netif_callback_fn()`, **globally, for every lwIP netif**, not only the
ones it created — so it runs for the WireGuard netif too, before
`wireguardif_init()` has had a chance to run.

`netif_callback_fn()` calls `lwip_get_esp_netif(netif)` to get back the
`esp_netif_t*` it assumes every netif has. With
`LWIP_ESP_NETIF_DATA == 0` (the esp-idf default — it's conditioned on
`CONFIG_ESP_NETIF_BRIDGE_EN`/`CONFIG_LWIP_PPP_SUPPORT`, both off by
default), `lwip_get_esp_netif()` is simply `(esp_netif_t*)netif->state`.
At this exact moment `netif->state` is still the
`wireguardif_init_data*` described above — never an `esp_netif_t*`, since
this netif is never registered with `esp_netif` at all — so
`esp_netif`'s callback dereferences `esp_netif->ip_info`,
`esp_netif->last_status_up`, etc. on a completely unrelated struct. This
is the crash reported upstream.

**Fix (drafted, build-verified, not yet hardware-verified — see Phase 2
branch `phase2-netif-locking-fix`):** of the two options previously
listed here, option 2 (narrower, not the "proper" esp_netif-driver
route) turned out to have a clean, minimal form: `Kconfig` now has
`WIREGUARD_WORKAROUND_ESP_NETIF_TYPE_CONFUSION`, which `select`s
`ESP_NETIF_BRIDGE_EN` purely for its side effect of forcing
`LWIP_ESP_NETIF_DATA=1`. With that, `lwip_get_esp_netif()` reads the
esp-netif pointer from lwIP's `netif->client_data[]` array instead of
`netif->state`; since the WireGuard netif was never registered with
`esp_netif`, its client-data slot is simply `NULL`, so
`netif_callback_fn()` safely no-ops (it already checks
`if (esp_netif) { ... }`) instead of misinterpreting `netif->state`. This
costs one extra `esp_netif` source file
(`lwip/esp_netif_br_glue.c`) in the build, not the full PPP stack that
the other candidate flag (`LWIP_PPP_SUPPORT`) would have pulled in.

The "proper" fix — registering the WireGuard netif as a real `esp_netif_t`
via a custom driver, the mechanism PPP/Ethernet drivers use — is still
the architecturally cleaner option and remains a possible future
improvement; it was not needed to resolve the crash and is considerably
more invasive, so it was not attempted for this first landing.

### 2. No `tcpip_thread` marshaling — fixed (Phase 2 branch)

Every public `esp_wireguard_*()` entry point in `src/esp_wireguard.c`
called lwIP's `netif`/`wireguardif` API (`netif_add`, `netif_remove`,
`netif_set_default`, `netif_set_ipaddr`, `wireguardif_add_peer`,
`wireguardif_connect`, `wireguardif_disconnect`,
`wireguardif_remove_peer`, `wireguardif_shutdown`, `wireguardif_fini`,
`wireguardif_peer_is_up`) directly from whatever task the calling
application runs in, racing `tcpip_thread` — the only thread from which
lwIP's netif list, and the wireguardif/wireguard_device state hanging off
a netif, are otherwise ever touched (packet RX, handshake/keepalive
timers).

Correcting an earlier assumption made during planning:
`CONFIG_LWIP_TCPIP_CORE_LOCKING` is **not** enabled by default in
`esp-idf` (`components/lwip/Kconfig` default is `n`), and
`LWIP_ASSERT_CORE_LOCKED()` only does anything at all when
`CONFIG_LWIP_CHECK_THREAD_SAFETY` is separately turned on (also `n` by
default; with it off, the macro expands to nothing per lwIP's own
`opt.h`). So this was not, by default, an assertion that aborts on
every boot — it was a silent, unsynchronized race against `tcpip_thread`
that could corrupt lwIP's internal state intermittently (e.g. a
`connect()`/`disconnect()` racing an in-flight packet), rather than the
`netif_add` crash in issue #1, which reproduces unconditionally.

**Fix:** every call that touches netif/wireguardif state is now marshaled
onto `tcpip_thread` via lwIP's own `tcpip_api_call()` (`lwip/priv/
tcpip_priv.h`) — the same primitive lwIP's own `netifapi.c` and the
socket/netconn API use for exactly this purpose, so it works correctly
whether or not `LWIP_TCPIP_CORE_LOCKING` is enabled. DNS resolution
(`getaddrinfo()` in `esp_wireguard_peer_init()`) deliberately stays on
the caller's task: it already goes through the thread-safe BSD sockets
API, and blocking `tcpip_thread` on a network round-trip inside a
`tcpip_api_call()` would risk starving the very packet processing the
lookup depends on.

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

### Phase 2 (branch `phase2-netif-locking-fix`, off `idf6-baseline`)

- `Kconfig`: added `WIREGUARD_WORKAROUND_ESP_NETIF_TYPE_CONFUSION`
  (`select ESP_NETIF_BRIDGE_EN`), fixing issue #1 — see write-up above.
- `src/esp_wireguard.c`: every call that touches lwIP `netif`/wireguardif
  state (`netif_add`, `netif_set_up`, `netif_set_default`,
  `netif_set_ipaddr`, `netif_remove`, `wireguardif_add_peer`,
  `wireguardif_connect`, `wireguardif_disconnect`,
  `wireguardif_remove_peer`, `wireguardif_shutdown`, `wireguardif_fini`,
  `wireguardif_peer_is_up`) is now marshaled onto `tcpip_thread` via
  `tcpip_api_call()`, fixing issue #2. `esp_wireguard_peer_init()`
  (DNS resolution) is unchanged and still runs on the caller's task.
  Public API signatures (`esp_wireguard.h`) are unchanged; this is
  internal-only.
- Rebuilt `examples/demo` from `fullclean`: still builds with no
  warnings, no errors, on `esp-idf 6.0.2` for `esp32`.

**This branch is build-verified only.** Nothing here has been run on
real ESP32 hardware yet. In particular: issue #1's fix is reasoned from
reading the `esp-idf` source (cited above) for exactly the fields and
call order involved, but a crash that occurs through an ext-callback
side effect is the kind of thing that is easy to get subtly wrong in
ways a clean compile can't catch; issue #2's fix removes a race whose
absence can't be proven by a short test run, only made overwhelmingly
less likely. Before trusting or merging this branch: flash
`examples/demo`, run repeated connect/disconnect cycles (the Phase 2
exit criterion below), and ideally also traffic concurrently with
connect/disconnect to exercise the race that issue #2 addresses.

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
- [~] **Phase 2 — Network interface and locking (blocking).** Issue #1
      (netif/esp_netif type confusion) and #2 (no tcpip_thread
      marshaling) both root-caused against the `esp-idf 6.0.2` source and
      fixed in branch `phase2-netif-locking-fix` (see above); build
      clean. **Not yet merged — needs hardware verification first.**
      Exit criterion (unchanged, still open): 100 connect/disconnect
      cycles on real hardware with no crash, no assert, no leak.
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

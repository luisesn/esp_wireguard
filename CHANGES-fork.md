# Fork changes

This file tracks how `luisesn/esp_wireguard` diverges from
[trombik/esp_wireguard](https://github.com/trombik/esp_wireguard), and
progress against the implementation plan below. It is not a changelog in
the conventional sense (no version numbers per entry); it exists so future
work — by Luis or by Claude in a later session — has context without
re-deriving it from the commit history.

> **Branch note:** `hwtest-phase2-phase3` merges `phase2-netif-locking-fix`
> (the netif/esp_netif crash fix + tcpip_thread marshaling) and
> `phase3-cryptokey-routing-audit` (the cryptokey-routing and
> handshake-rate-limit fixes) for first hardware testing — both land
> together so the exit criterion below can be checked once instead of
> twice. Once hardware testing confirms this branch, it should be the one
> merged into `idf6-baseline`/`main`, not the two source branches
> separately.

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

### 1. `netif_add()` crash on `esp-idf >= 5.x` — root cause confirmed, fix verified on real hardware

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

**Fix (verified on real hardware — see "Hardware verification" below):**
of the two options previously listed here, option 2 (narrower, not the
"proper" esp_netif-driver route) turned out to have a clean, minimal
form: `Kconfig` now has
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

### 2. No `tcpip_thread` marshaling — fixed, hardware-exercised (see below)

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

### 5. TAI64N timestamp has no persistence across reboots — FIXED (wait for clock sync)

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

**Fixed, on branch `phase3-wait-for-time-sync` (off `idf6-baseline`,
merged into `hwtest-phase2-phase3`), by the user's explicit choice: a
stricter variant of option 1 above — block until the clock is actually
synced, rather than just log a warning and proceed.**

Rather than (2) (persisting a high-water-mark in NVS), which was my own
recommendation above, the user chose the simpler option: make
`esp_wireguard_connect()` wait for SNTP (or whatever sets the clock) to
finish before doing anything else. This is less work (no new `nvs_flash`
dependency) and fixes the actual precondition — an unset clock — rather
than working around it with a persisted floor.

Implementation:

- `wireguard_platform_time_is_synced()` (new, in `wireguard-platform.c`/`.h`)
  — a coarse sanity check: `time(NULL)` is past a hardcoded floor
  (`2024-01-01T00:00:00Z`). Not a freshness or correctness check, just
  rules out "obviously never set".
- `esp_wireguard_connect()` now polls this function right after its
  initial `!ctx` check — before any `netif`/`wireguardif` setup — and
  blocks in `CONFIG_WIREGUARD_TIME_SYNC_POLL_INTERVAL_MS` (default
  500 ms) steps for up to `CONFIG_WIREGUARD_TIME_SYNC_TIMEOUT_MS`
  (default 30 s) before giving up with `ESP_ERR_TIMEOUT`. This runs on
  every call, not just the first connect, since a reconnect after a
  reboot hits the same unset-clock window.
- The library still does not start SNTP itself; the application remains
  responsible for that (see `examples/demo/main/sync_time.c`).

Does not change the responder-side gap for the reverse direction (remote
end initiating to the ESP32) noted above, since that's not this fork's
normal use case; the same fix would apply there too if it's ever needed.

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

### Hardware verification (branch `hwtest-phase2-phase3`, merges Phase 2 + Phase 3)

Tested by Luis on real ESP32 hardware, 2026-10-27, `esp-idf 6.1` (newer
than the `6.0.2` this was built against, confirming it also holds on a
newer `6.x`), against his own WireGuard hub at `norsip.com`:

- `netif_add()` did **not** crash — issue #1's fix holds. The boot log
  goes straight through `esp_wireguard_netif_create()` →
  `wireguardif_add_peer()` → `wireguardif_connect()` with no fault.
- First attempt still showed the peer never completing a handshake
  (`wg show` on the server had no `endpoint`/`latest handshake`/
  `transfer` at all for this peer), traced to a misconfigured
  `WG_PEER_PUBLIC_KEY` in the example's `menuconfig` (the ESP32's own
  keypair was correct; the server's public key entered on the ESP32
  side was not). Not a bug in this fork — a reminder that the demo's
  `menuconfig` defaults are placeholders and every `WG_*` value must be
  filled in for the actual peer.
- After correcting that: handshake completed (`demo: Peer is up`),
  ping over the tunnel succeeded 10/10 (`ping 10.252.1.1`, ~33ms), and
  the demo's own disconnect/reconnect loop ran `esp_wireguard_disconnect()`
  (which also goes through the new `tcpip_api_call()` marshaling) with
  no crash.
- Follow-up log confirms two full reconnect cycles (disconnect → 10s
  idle, pings timing out as expected → connect → handshake →
  "Peer is up" → pings succeeding again at ~33ms), each clean, no
  crash, no leak symptom. The two issues this branch set out to fix are
  now confirmed fixed on real hardware, not just reasoned from source.
  Still open: the Phase 2 exit criterion's full 100 connect/disconnect
  cycles (only 2 observed so far) — worth a longer unattended soak run
  before calling Phase 2 done and merging into `idf6-baseline`/`main`.

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
      marshaling) both root-caused against the `esp-idf` source, fixed in
      branch `phase2-netif-locking-fix`, and **confirmed fixed on real
      ESP32 hardware** (`esp-idf 6.1`, see "Hardware verification"
      above): no `netif_add` crash, handshake completes, ping over the
      tunnel works, disconnect ran without crash. Not yet merged into
      `idf6-baseline`/`main` — still want the exit criterion below met
      first. Exit criterion (still open): 100 connect/disconnect cycles
      on real hardware with no crash, no assert, no leak.
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
      TAI64N timestamp source/monotonicity across reboots: **fixed** —
      see issue #5 above (`esp_wireguard_connect()` now waits for the
      clock to sync, the user's chosen design, merged into
      `hwtest-phase2-phase3`). Cookie reply handling under load (now
      explicitly documented, still untested — `wireguard_is_under_load()`
      in `wireguard-platform.c` always returns `false`, so the
      DoS-mitigation cookie path is never exercised; a comment at the
      function now spells out why this is an acceptable trade-off for a
      single-peer point-to-point tunnel per the original scope, and what
      would need to change if this library is ever used in a
      multi-peer/internet-facing responder role). Host-side test vectors for
      ChaCha20-Poly1305 / X25519 / BLAKE2s: **done** — see
      `host-tests/` (native `gcc` build, no ESP-IDF/hardware needed;
      `make check`). All three primitives cross-checked against
      independent reference implementations (Python's `hashlib.blake2s`,
      and the `cryptography` package for X25519 and the AEAD
      construction in this codebase's actual 64-bit-counter nonce
      convention) rather than hand-copied published constants — see
      `host-tests/README.md` for why. 34/34 checks pass, including
      tamper-rejection of the AEAD tag, and a clean run under
      ASan+UBSan (`make asan`). Fuzzing of the packet parser: **done** —
      see `host-tests/fuzz/` (libFuzzer, needs `clang`; `make run`).
      Covers `wireguard_get_message_type()` and the three real
      incoming-message parsers in `src/wireguard.c`
      (`wireguard_process_initiation_message()`,
      `wireguard_process_handshake_response()`,
      `wireguard_process_cookie_message()`), overlaying fuzzer bytes onto
      a validly-authenticated template of each message type so the
      search gets past MAC1/AEAD checks instead of bouncing off them —
      see `host-tests/fuzz/README.md` for the full rationale and for what
      this does *not* cover (`wireguardif.c`'s lwIP/pbuf integration
      layer, multi-packet stateful sequences). A 2-minute local smoke run
      (ASan+UBSan) reached ~20,600 executions with no crashes; that's a
      smoke-level result confirming the harness works end-to-end, not a
      substitute for a longer run.

  With this, every item originally listed under Phase 3 has either been
  fixed or has a documented, deliberate reason it's out of scope for this
  fork (replay-window width, cookie-reply-under-load). Phase 3 itself
  isn't marked `[x]` yet below since none of it has been exercised on
  real hardware — only by manual review, host-side tests, and fuzzing.
- [ ] **Phase 4 — TCP and performance.** MTU/MSS tuning, `iperf`/HTTP/TCP
      echo testing, 24h soak test across rekeys and WiFi drops,
      measurement-driven optimization only (no speculative tuning).
      Groundwork done: the WireGuard interface MTU (`WIREGUARDIF_MTU`,
      previously hardcoded to 1420) is now `CONFIG_WIREGUARD_MTU`, still
      defaulting to 1420 -- a knob to turn, not a tuning result; see
      Kconfig's help text for how to actually pick a value from a
      measurement of the real path, rather than guessing. A TCP
      throughput test tool is also now in `examples/demo` (see the test
      plan below) for the throughput/soak testing this phase needs.
      Still open, and blocked on real hardware + a real network path
      rather than something that can be done from this environment
      alone: MTU/MSS measurement against the actual deployment (home
      connection vs. cellular, etc.), running the throughput test for
      real, and the 24h soak test itself.

  Test plan: the ESP32 has no shell, so some test tooling has to run in
  `examples/demo` regardless of what's on the hub. Originally planned to
  use esp-idf's `iperf` managed component on the ESP32 side (classic
  iperf2 protocol) paired with `iperf2` on the hub, but the component
  registry (`components-file.espressif.com`) isn't reachable from this
  sandbox's network, so that choice couldn't be build-verified here and
  was dropped in favor of something this environment can actually
  compile and check end-to-end: a small custom TCP byte-pump, **done**
  -- see `examples/demo/main/tcp_throughput_test.{c,h}` and the new
  "TCP throughput test (Phase 4)" Kconfig menu (off by default:
  `CONFIG_EXAMPLE_TCP_TEST_ENABLE`). It just moves bytes as fast as it
  can in one configured direction (RX: this device listens; TX: it
  connects out and sends) and logs the measured rate, so the hub only
  needs a plain TCP listener/sender (`nc` is enough) rather than a tool
  whose wire protocol has to match. A duration of 0 keeps it running
  (and reconnecting across drops) indefinitely, for the soak test below.
  Build-verified in all three configurations (disabled, RX, TX); not yet
  run against real hardware.

  1. **Path MTU check.** From the hub, `ping -M do -s <size>
     <esp32-tunnel-ip>` (over the tunnel), sweeping `<size>` down from
     ~1452 (1420 configured WG MTU - 28 bytes of ICMP+IPv4 header) until
     it stops needing fragmentation, to confirm the default 1420 doesn't
     already need lowering for this specific network path (home
     WiFi/broadband, not cellular, so likely fine, but worth confirming
     rather than assuming).
  2. **Throughput.** RX mode on the ESP32 with e.g.
     `dd if=/dev/zero bs=65536 | nc <esp32-tunnel-ip> <port>` from the
     hub, and separately TX mode on the ESP32 with
     `nc -l <port> > /dev/null` (or `| pv > /dev/null` for a live rate)
     on the hub, to measure both directions.
  3. **24h soak.** The same test in either mode, with duration set to 0,
     left running across at least one WireGuard rekey (`REKEY_AFTER_TIME`
     = 120s, so trivial to hit) and at least one real WiFi drop/reconnect
     -- this demo's `app_main()` already cycles disconnect/connect every
     20s on its own, which doubles as part of this -- watching for the
     TCP connection surviving, stalling, or needing a device reset.
- [x] **Phase 5 — Public API.** Done (`phase5-events-api`, merged into
      `hwtest-phase2-phase3`), build-verified but not yet exercised on
      real hardware:
      - `esp_wireguard_start_monitor()` / `esp_wireguard_stop_monitor()`
        start/stop a background task that polls
        `esp_wireguardif_peer_is_up()` internally (the
        wireguardif/wireguard.c library still has no up/down callback of
        its own -- that didn't change) and posts
        `WIREGUARD_EVENT_PEER_UP` / `WIREGUARD_EVENT_PEER_DOWN` on the
        default event loop. The application subscribes to those instead
        of running its own poll loop; `examples/demo/main.c` was
        switched over as a worked example (an `EventGroupHandle_t` bit
        set/cleared by the two events, waited on with
        `xEventGroupWaitBits()`, replacing the old
        `while (esp_wireguardif_peer_is_up(...) != ESP_OK) vTaskDelay(...)`
        loops in two places).
      - **Auto-reconnect on IP recovery**: the monitor also subscribes to
        `IP_EVENT_STA_GOT_IP` / `IP_EVENT_ETH_GOT_IP`; if the peer is down
        when one fires, it calls `esp_wireguard_connect()` again. This
        needs a default event loop to already exist and an underlying
        network interface that actually posts IP events -- the WireGuard
        pseudo-netif itself doesn't (see the
        `WIREGUARD_WORKAROUND_ESP_NETIF_TYPE_CONFUSION` Kconfig comment),
        but the real WiFi/Ethernet netif underneath it does, which is
        what matters here.
      - **Endpoint re-resolution on reconnect**: `esp_wireguard_connect()`
        itself now re-runs `getaddrinfo()` and calls
        `wireguardif_update_endpoint()` on every call to an
        already-created interface, not only the very first connect. The
        original code resolved the peer's address exactly once and reused
        it forever, which silently stopped working for a peer behind
        dynamic DNS or a renumbered IP.
      - A new `CONFIG_WIREGUARD_MONITOR_POLL_INTERVAL_MS` Kconfig knob
        controls the monitor's poll interval (default 1000ms).
      - The synced-time requirement was already documented on
        `esp_wireguard_connect()` from Phase 3 (issue #5); the WiFi
        power-save caveat (modem-sleep delaying inbound UDP enough to
        look like handshake/keepalive flakiness, recommending
        `esp_wifi_set_ps(WIFI_PS_NONE)`) is now documented alongside it
        and on `esp_wireguard_start_monitor()`.
      - **What this does NOT cover**: a separate "session expired" event
        distinct from "peer down" -- the underlying library doesn't
        report *why* a peer went down (planned disconnect vs. a rekey
        that failed to complete in time), so both surface as the same
        `WIREGUARD_EVENT_PEER_DOWN`; an application that needs to tell
        them apart has to track whether it called
        `esp_wireguard_disconnect()` itself. Also untested: whether the
        IP-recovery reconnect and the demo's own manual
        disconnect/reconnect cycle (already in `app_main()`'s loop,
        originally for Phase 2/4 soak testing) can race each other if a
        real WiFi drop happens to land in the 20s window the demo is
        already mid-cycle -- plausible in theory, not something this
        cloud session can reproduce without a real WiFi radio to drop.
      - Build-verified: `examples/demo`, esp32 target, full clean
        rebuild, both with the Phase 4 TCP test disabled and with it
        enabled (RX mode) alongside the new event-based code, to confirm
        the two phases' changes coexist. The esp32s2/s3/c3 cross-targets
        from Phase 6's planned build matrix could not be verified here --
        this sandbox only has the xtensa (esp32) toolchain installed, not
        the RISC-V one the other three targets need.
- [x] **Phase 6 — Tests and CI.** Done except hardware-in-the-loop
      (`phase6-ci-rewrite`, merged into `hwtest-phase2-phase3`):
      - `.github/workflows/build.yml` rewritten from scratch. The old
        matrix (esp-idf 4.0.x-4.4.x, `master`, and ESP8266 RTOS SDK, each
        with its own manual toolchain install/cache steps) is gone; this
        fork doesn't support any of those. The new `idf-build` job builds
        `examples/demo` for `esp32`/`esp32s2`/`esp32s3`/`esp32c3` using
        Espressif's official `espressif/idf:v6.0.2` Docker image (matching
        this fork's exact target esp-idf version), which needs no manual
        toolchain setup at all.
      - A new `host-tests` job runs the host-side crypto known-answer
        tests (`host-tests/Makefile`'s `check` and `asan` targets) and a
        bounded (120s) smoke run of the Phase 3 libFuzzer packet-parser
        harness (`host-tests/fuzz/`), uploading the corpus/any crash
        artifacts on every run.
      - Hardware-in-the-loop tests against a real peer are **not**
        implemented: they need a self-hosted runner with real ESP32
        hardware attached and a reachable peer, which doesn't exist yet.
        Left as a comment in the workflow pointing at where that job would
        go, not as a stub job.
      - **Caveat**: this cloud sandbox has no Docker and no network access
        to Docker Hub or GitHub's own hosted runners, so the `idf-build`
        job itself (and the workflow as a whole, as a GitHub Actions
        workflow) could not actually be executed before being committed
        -- only reviewed, and cross-checked against the local esp-idf
        6.0.2 build this session already verified directly (Phase 5). The
        `host-tests` job's commands (`make check`, `make asan`, the fuzz
        `fuzz`/`run` targets) *were* run locally here and pass clean (5018
        fuzzer executions in the 30s test run, no crashes). Treat the
        first real run of this workflow on GitHub as the actual
        verification of the `idf-build` job and the Docker image pin.
- [ ] **Phase 7 — Publish.** Minimal point-to-point TCP client example,
      changelog, semver, component registry listing.

### Definition of "MVP done"

The ESP32 establishes a tunnel to a Linux peer, holds a TCP connection for
24h across rekeys and WiFi drops, and everything builds clean (no
warnings) on `esp-idf 6.0.x`.

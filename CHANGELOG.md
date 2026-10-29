# Changelog

All notable changes to this fork are documented in this file. Format is
loosely based on [Keep a Changelog](https://keepachangelog.com/), and this
project uses [Semantic Versioning](https://semver.org/) once it reaches a
1.0.0 release (see "Versioning" below for why it hasn't yet).

For the full rationale behind each change, see [CHANGES-fork.md](CHANGES-fork.md),
which tracks the fork's phased work plan and stays more detailed than this
file.

## [Unreleased]

Everything below has been build-verified (locally, and from Phase 6
onward in CI); items marked "not yet hardware-verified" have not been run
against a real ESP32 and a real WireGuard peer.

### Added

- Scoped this fork to `esp-idf >= 6.0` and the `esp32` chip family
  (`esp32`/`esp32s2`/`esp32s3`/`esp32c3`); dropped `esp-idf` 4.x/5.x and
  ESP8266 RTOS SDK support.
- Fixed esp-idf 6.0.2 / mbedtls 4 build breakage.
- Fixed a `netif`/`tcpip_thread` locking race: every `esp_wireguard_*()`
  call that touches `netif`/`wireguardif` state is now marshaled onto
  `tcpip_thread` via lwIP's `tcpip_api_call()` (hardware-verified over 157
  connect/disconnect cycles).
- Fixed a type-confusion crash between this component's raw lwIP netif and
  `esp_netif`'s global callback (`WIREGUARD_WORKAROUND_ESP_NETIF_TYPE_CONFUSION`
  Kconfig option).
- Fixed handshakes being silently rejected as replays on a cold boot
  (ESP32 has no RTC): `esp_wireguard_connect()` now waits for a plausible
  clock (`CONFIG_WIREGUARD_TIME_SYNC_TIMEOUT_MS`/`..._POLL_INTERVAL_MS`)
  before sending anything.
- Added a host-side libFuzzer harness for the incoming-packet parsers
  (`host-tests/fuzz/`), and host-side crypto known-answer-vector tests
  (`host-tests/`).
- Added `CONFIG_WIREGUARD_MTU` to make the tunnel MTU configurable instead
  of a hardcoded `1420`.
- Added a custom TCP throughput test tool to `examples/demo`
  (`CONFIG_EXAMPLE_TCP_TEST_ENABLE`, RX/TX modes) for Phase 4 MTU/
  throughput measurement (hardware-verified, see CHANGES-fork.md).
- Added `esp_wireguard_start_monitor()` / `esp_wireguard_stop_monitor()`:
  a background task that posts `WIREGUARD_EVENT_PEER_UP` /
  `WIREGUARD_EVENT_PEER_DOWN` on the default event loop instead of the
  application polling `esp_wireguardif_peer_is_up()` itself. Also
  auto-reconnects on IP recovery (`IP_EVENT_STA_GOT_IP`/`..._ETH_GOT_IP`)
  and re-resolves the peer's endpoint on every reconnect, not just the
  first connect (not yet hardware-verified).
- Rewrote `.github/workflows/build.yml` for `esp-idf 6.0.x` only, across
  `esp32`/`esp32s2`/`esp32s3`/`esp32c3`, using Espressif's official Docker
  image; added a `host-tests` CI job running the crypto tests and a
  bounded fuzz smoke run.
- Added `examples/tcp_client`: a minimal point-to-point TCP client
  example, smaller than `examples/demo`, demonstrating just what this
  fork is for -- a tunnel to one peer carrying ordinary TCP traffic (not
  yet hardware-verified).

### Changed

- `README.md` rewritten to describe this fork's scope, current status,
  and the Phase 5 events API, instead of upstream's general-purpose
  description.

## Versioning

This fork has not reached 1.0.0: several changes above are build-verified
but not yet confirmed against real hardware (a real ESP32 talking to a
real WireGuard peer over real WiFi) -- see CHANGES-fork.md's "Definition
of 'MVP done'" for the exit criteria. Once those pass, this will
become `1.0.0`; until then, expect `0.x.y` releases where a minor bump may
still include behavior changes, not just new features.

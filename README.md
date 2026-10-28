# `esp_wireguard`, WireGuard Implementation for ESP-IDF

This is a fork of
[trombik/esp_wireguard](https://github.com/trombik/esp_wireguard), itself
an implementation of the [WireGuard&reg;](https://www.wireguard.com/)
protocol for ESP-IDF, based on
[WireGuard Implementation for lwIP](https://github.com/smartalock/wireguard-lwip).

This fork narrows the scope to `esp-idf` `>= 6.0` and the `esp32` chip
family (`esp32`, `esp32s2`, `esp32s3`, `esp32c3`), in exchange for dropping
support for `esp-idf` `4.x`/`5.x` and the ESP8266 RTOS SDK. See
[CHANGES-fork.md](CHANGES-fork.md) for what has changed and why, and the
upstream project above for the general-purpose version.

## Status

The code is alpha, but actively built and tested: every change in this
fork is build-verified (CI: `esp32`/`esp32s2`/`esp32s3`/`esp32c3`, plus a
host-side crypto test suite and packet-parser fuzzer — see
[.github/workflows/build.yml](.github/workflows/build.yml)), and the core
netif-locking fix has been confirmed against real hardware. Several newer
changes (the TCP throughput test, the Phase 5 events/auto-reconnect API)
are build-verified but not yet exercised against real hardware. See
[CHANGES-fork.md](CHANGES-fork.md) for exactly what has and hasn't been
hardware-tested, and [CHANGELOG.md](CHANGELOG.md) for a chronological
summary.

A single tunnel to a WireGuard peer has been working in upstream.

## Supported ESP-IDF versions and targets

The following ESP-IDF versions are supported:

* `esp-idf` `>= 6.0`

The following targets are supported:

* `esp32`
* `esp32s2`
* `esp32s3`
* `esp32c3`

## Usage

`ESP-NETIF` is the only TCP/IP adapter; there is nothing to choose in
`menuconfig`.

Both peers must have synced time. The library does not sync time.

A working network interface is required.

Create WireGuard configuration, `wireguard_config_t`. Use
`ESP_WIREGUARD_CONFIG_DEFAULT` to initialize `wireguard_config_t` variable.
Create `wireguard_ctx_t`.  Pass the variables to `esp_wireguard_init()`. Then,
call `esp_wireguard_connect()`. Call `esp_wireguard_disconnect()` to
disconnect from the peer (and destroy the WireGuard interface).

```c
#include <esp_wireguard.h>

esp_err_t err = ESP_FAIL;

wireguard_config_t wg_config = ESP_WIREGUARD_CONFIG_DEFAULT();

wg_config.private_key = CONFIG_WG_PRIVATE_KEY;
wg_config.listen_port = CONFIG_WG_LOCAL_PORT;
wg_config.public_key = CONFIG_WG_PEER_PUBLIC_KEY;
wg_config.allowed_ip = CONFIG_WG_LOCAL_IP_ADDRESS;
wg_config.allowed_ip_mask = CONFIG_WG_LOCAL_IP_NETMASK;
wg_config.endpoint = CONFIG_WG_PEER_ADDRESS;
wg_config.port = CONFIG_WG_PEER_PORT;

/* If the device is behind NAT or stateful firewall, set persistent_keepalive.
   persistent_keepalive is disabled by default */
// wg_config.persistent_keepalive = 10;

wireguard_ctx_t ctx = {0};
err = esp_wireguard_init(&wg_config, &ctx);

/* start establishing the link. after this call, esp_wireguard start
   establishing connection. */
err = esp_wireguard_connect(&ctx);

/* after some time, see if the link is up. note that it takes some time to
   establish the link */
err = esp_wireguardif_peer_is_up(&ctx);
if (err == ESP_OK) {
    /* the link is up */
else {
    /* the link is not up */
}

/* do something */

err = esp_wireguard_disconnect(&ctx);
```

See examples at [examples](examples): [examples/demo](examples/demo) is a
fuller worked example (also exercising ICMP, a throughput test, and a
disconnect/reconnect soak loop); [examples/tcp_client](examples/tcp_client)
is a minimal point-to-point TCP client, closer to what a real
single-purpose deployment of this fork looks like.

## Events instead of polling

Rather than polling `esp_wireguardif_peer_is_up()` in a loop, call
`esp_wireguard_start_monitor()` after `esp_wireguard_connect()` and
subscribe to `WIREGUARD_EVENT` on the default event loop:

```c
static void wg_event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data)
{
    if (event_base != WIREGUARD_EVENT) {
        return;
    }
    if (event_id == WIREGUARD_EVENT_PEER_UP) {
        /* the link is up */
    } else if (event_id == WIREGUARD_EVENT_PEER_DOWN) {
        /* the link is down */
    }
}

esp_event_handler_instance_register(WIREGUARD_EVENT, ESP_EVENT_ANY_ID,
        &wg_event_handler, NULL, NULL);
esp_wireguard_start_monitor(&ctx);
```

This also gets you two things a manual poll loop doesn't: the tunnel
automatically reconnects when the underlying network interface regains an
IP address (e.g. after a WiFi drop/reconnect), and the peer's endpoint
hostname is re-resolved on every reconnect rather than only once at the
very first connect (useful behind dynamic DNS or a peer that gets
renumbered). See `esp_wireguard_start_monitor()`'s doc comment in
[include/esp_wireguard.h](include/esp_wireguard.h) for the details and
caveats (notably WiFi power-save).

## IPv6 support

Enable `CONFIG_LWIP_IPV6` under `lwip` component in `menuconfig`.

IPv6 support is alpha and probably broken. See also Known issues.

## Driver configuration

The driver configuration is under `[Component config]` -> `[WireGuard]`.

Under `WIREGUARD_x25519_IMPLEMENTATION`, you may choose an implementation of
scalar multiplication. The default is
`WIREGUARD_x25519_IMPLEMENTATION_DEFAULT`, which is derived from
[WireGuard Implementation for lwIP](https://github.com/smartalock/wireguard-lwip).
`WIREGUARD_x25519_IMPLEMENTATION_NACL` uses
[crypto_scalarmult()](https://nacl.cr.yp.to/scalarmult.html) from NaCL. Note
that, with `WIREGUARD_x25519_IMPLEMENTATION_NACL`,
some stack sizes must be increased.  In my test, 5KB for both
`CONFIG_LWIP_TCPIP_TASK_STACK_SIZE`, and `CONFIG_MAIN_TASK_STACK_SIZE` is
known to work on `ESP32-D0WD-V3`.

## Known issues

The implementation uses `LwIP` as TCP/IP protocol stack.

IPv6 support is not tested.  Dual stack (IPv4 and IPv6) is not supported (see
Issue #5). The first address of `endpoint` is used to choose IPv4 or IPv6 as a
transport. The chosen transport must be available and usable.

The library assumes the interface is WiFi interface. Ethernet is not
supported.

## License

BSD 3-Clause "New" or "Revised" License (SPDX ID: BSD-3-Clause).
See [LICENSE](LICENSE) for details.

[src/nacl/crypto_scalarmult/curve25519/ref/smult.c] is Public domain.

## Authors

* Daniel Hope (daniel.hope@smartalock.com)
* Kenta Ida (fuga@fugafuga.org)
* Matthew Dempsky
* D. J. Bernstein

/*
 * Copyright (c) 2022 Tomoyuki Sakurai <y@trombik.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *  list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 * 3. Neither the name of "Floorsense Ltd", "Agile Workspace Ltd" nor the names of
 *  its contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <lwip/ip.h>
#include <lwip/netdb.h>
#include <lwip/err.h>
#include <lwip/priv/tcpip_priv.h>
#include <esp_err.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_netif.h>
#include <esp_wireguard.h>
#include <mbedtls/base64.h>

#include "wireguard-platform.h"
#include "wireguardif.h"

ESP_EVENT_DEFINE_BASE(WIREGUARD_EVENT);

#define TAG "esp_wireguard"
#define WG_KEY_LEN  (32)
#define WG_B64_KEY_LEN (4 * ((WG_KEY_LEN + 2) / 3))
#if defined(CONFIG_LWIP_IPV6)
#define WG_ADDRSTRLEN  INET6_ADDRSTRLEN
#else
#define WG_ADDRSTRLEN  INET_ADDRSTRLEN
#endif

static struct netif wg_netif_struct = {0};
static struct netif *wg_netif = NULL;
static struct wireguardif_peer peer = {0};
static uint8_t wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;
static uint8_t preshared_key_decoded[WG_KEY_LEN];

static esp_err_t esp_wireguard_peer_init(const wireguard_config_t *config, struct wireguardif_peer *peer)
{
    esp_err_t err;
    char addr_str[WG_ADDRSTRLEN];
    struct addrinfo *res = NULL;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;

    if (!config || !peer) {
        err = ESP_ERR_INVALID_ARG;
        goto fail;
    }

    peer->public_key = config->public_key;
    if (config->preshared_key != NULL) {
        size_t len;
        int res;

        ESP_LOGI(TAG, "using preshared_key");
        ESP_LOGD(TAG, "preshared_key: %s", config->preshared_key);
#if defined(CONFIG_WIREGUARD_x25519_IMPLEMENTATION_DEFAULT)
        ESP_LOGI(TAG, "X25519: default");
#elif defined(CONFIG_WIREGUARD_x25519_IMPLEMENTATION_NACL)
        ESP_LOGI(TAG, "X25519: NaCL");
#endif
        res = mbedtls_base64_decode(preshared_key_decoded, WG_KEY_LEN, &len, (unsigned char *)config->preshared_key, WG_B64_KEY_LEN);
        if (res != 0 || len != WG_KEY_LEN) {
            err = ESP_FAIL;
            ESP_LOGE(TAG, "base64_decode: %i", res);
            if (len != WG_KEY_LEN) {
                ESP_LOGE(TAG, "invalid decoded length, len: %u, should be %u", len, WG_KEY_LEN);
            }
            goto fail;
        }
        peer->preshared_key = preshared_key_decoded;
    } else {
        peer->preshared_key = NULL;
    }
    peer->keep_alive = config->persistent_keepalive;

    /* Allow all IPs through tunnel */
    {
        ip_addr_t allowed_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
        peer->allowed_ip = allowed_ip;
        ip_addr_t allowed_mask = IPADDR4_INIT_BYTES(0, 0, 0, 0);
        peer->allowed_mask = allowed_mask;
    }

    /* resolve peer name or IP address */
    {
        ip_addr_t endpoint_ip;
        memset(&endpoint_ip, 0, sizeof(endpoint_ip));

        /* XXX lwip_getaddrinfo returns only the first address of a host at the moment */
        if (getaddrinfo(config->endpoint, NULL, &hints, &res) != 0) {
            err = ESP_FAIL;

            /* XXX gai_strerror() is not implemented */
            ESP_LOGE(TAG, "getaddrinfo: unable to resolve `%s`", config->endpoint);
            goto fail;
        }

        if (res->ai_family == AF_INET) {
            struct in_addr addr4 = ((struct sockaddr_in *) (res->ai_addr))->sin_addr;
            inet_addr_to_ip4addr(ip_2_ip4(&endpoint_ip), &addr4);
        } else {
#if defined(CONFIG_LWIP_IPV6)
            struct in6_addr addr6 = ((struct sockaddr_in6 *) (res->ai_addr))->sin6_addr;
            inet6_addr_to_ip6addr(ip_2_ip6(&endpoint_ip), &addr6);
#endif
        }
        peer->endpoint_ip = endpoint_ip;

        if (inet_ntop(res->ai_family, &(peer->endpoint_ip), addr_str, WG_ADDRSTRLEN) == NULL) {
            ESP_LOGW(TAG, "inet_ntop: %i", errno);
        } else {
            ESP_LOGI(TAG, "Peer: %s (%s:%i)",
                                            config->endpoint,
                                            addr_str,
                                            config->port);
        }
    }
    peer->endport_port = config->port;
    peer->keep_alive = config->persistent_keepalive;
    err = ESP_OK;
fail:
    freeaddrinfo(res);
    return err;
}

/*
 * ---------------------------------------------------------------------
 * tcpip_thread marshaling
 * ---------------------------------------------------------------------
 *
 * lwIP's netif list, and the wireguardif/wireguard_device state hanging
 * off a netif, are only safe to mutate from tcpip_thread: every netif
 * input callback (wireguardif_input(), called from the UDP/TCP receive
 * path) and timer (wireguardif's own keepalive/handshake timeouts) run
 * there, with no additional locking of their own. The public
 * esp_wireguard_*() API, however, is called by application code from
 * whatever task the application runs in, and the original code called
 * netif_add()/netif_remove()/wireguardif_*() directly from that task,
 * racing against tcpip_thread.
 *
 * By default esp-idf does not build with CONFIG_LWIP_CHECK_THREAD_SAFETY
 * (LWIP_ASSERT_CORE_LOCKED() is a no-op then), so this does not normally
 * abort -- it is a silent race that can corrupt lwIP's internal state
 * under the right timing (e.g. a connect()/disconnect() racing an
 * in-flight packet), rather than a crash that reproduces on every boot.
 * We fix it properly here by marshaling every call that touches the
 * netif or wireguardif state onto tcpip_thread via lwIP's own
 * tcpip_api_call() (the same primitive lwIP's netifapi.c and
 * socket/netconn API use for exactly this purpose), rather than relying
 * on CONFIG_LWIP_CHECK_THREAD_SAFETY to catch misuse.
 *
 * NOTE: DNS resolution (getaddrinfo(), in esp_wireguard_peer_init())
 * deliberately stays on the caller's task: it goes through the BSD
 * sockets API, which is already thread-safe on its own, and running a
 * blocking network round-trip from inside a tcpip_api_call() would risk
 * starving tcpip_thread of the very packet processing the lookup may be
 * waiting on.
 */

static err_t esp_wireguard_netif_create_tcpip(struct tcpip_api_call_data *call);

struct wg_netif_create_call {
    struct tcpip_api_call_data call;
    const wireguard_config_t *config;
    esp_err_t result;
};

static esp_err_t esp_wireguard_netif_create(const wireguard_config_t *config)
{
    struct wg_netif_create_call args = {0};

    if (!config) {
        return ESP_ERR_INVALID_ARG;
    }
    args.config = config;
    args.result = ESP_FAIL;
    tcpip_api_call(esp_wireguard_netif_create_tcpip, &args.call);
    return args.result;
}

/* Runs on tcpip_thread. See "tcpip_thread marshaling" above. */
static err_t esp_wireguard_netif_create_tcpip(struct tcpip_api_call_data *call)
{
    struct wg_netif_create_call *args = (struct wg_netif_create_call *)call;
    const wireguard_config_t *config = args->config;
    ip_addr_t ip_addr;
    ip_addr_t netmask;
    ip_addr_t gateway = IPADDR4_INIT_BYTES(0, 0, 0, 0);
    struct wireguardif_init_data wg = {0};

    /* Setup the WireGuard device structure */
    wg.private_key = config->private_key;
    wg.listen_port = config->listen_port;
    wg.bind_netif = NULL;

    ESP_LOGI(TAG, "allowed_ip: %s", config->allowed_ip);

    if (ipaddr_aton(config->allowed_ip, &ip_addr) != 1) {
        ESP_LOGE(TAG, "ipaddr_aton: invalid allowed_ip: `%s`", config->allowed_ip);
        args->result = ESP_ERR_INVALID_ARG;
        return ERR_ARG;
    }
    if (ipaddr_aton(config->allowed_ip_mask, &netmask) != 1) {
        ESP_LOGE(TAG, "ipaddr_aton: invalid allowed_ip_mask: `%s`", config->allowed_ip_mask);
        args->result = ESP_ERR_INVALID_ARG;
        return ERR_ARG;
    }

    /* Register the new WireGuard network interface with lwIP */
    wg_netif = netif_add(
            &wg_netif_struct,
            ip_2_ip4(&ip_addr),
            ip_2_ip4(&netmask),
            ip_2_ip4(&gateway),
            &wg, &wireguardif_init,
            &ip_input);
    if (wg_netif == NULL) {
        ESP_LOGE(TAG, "netif_add: failed");
        args->result = ESP_FAIL;
        return ERR_IF;
    }

    /* Mark the interface as administratively up, link up flag is set
     * automatically when peer connects */
    netif_set_up(wg_netif);
    args->result = ESP_OK;
    return ERR_OK;
}

esp_err_t esp_wireguard_init(wireguard_config_t *config, wireguard_ctx_t *ctx)
{
    esp_err_t err = ESP_FAIL;

    if (!config || !ctx) {
        err = ESP_ERR_INVALID_ARG;
        goto fail;
    }

    err = wireguard_platform_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "wireguard_platform_init: %s", esp_err_to_name(err));
        goto fail;
    }
    ctx->config = config;
    ctx->netif = NULL;
    ctx->netif_default = netif_default;

    err = ESP_OK;
fail:
    return err;
}

struct wg_add_peer_call {
    struct tcpip_api_call_data call;
    struct wireguardif_peer *peer;
    err_t lwip_err;
};

/* Runs on tcpip_thread. See "tcpip_thread marshaling" above. */
static err_t esp_wireguard_add_peer_tcpip(struct tcpip_api_call_data *call)
{
    struct wg_add_peer_call *args = (struct wg_add_peer_call *)call;

    args->lwip_err = wireguardif_add_peer(wg_netif, args->peer, &wireguard_peer_index);
    return args->lwip_err;
}

struct wg_connect_call {
    struct tcpip_api_call_data call;
    err_t lwip_err;
};

/* Runs on tcpip_thread. See "tcpip_thread marshaling" above. */
static err_t esp_wireguard_connect_tcpip(struct tcpip_api_call_data *call)
{
    struct wg_connect_call *args = (struct wg_connect_call *)call;

    args->lwip_err = wireguardif_connect(wg_netif, wireguard_peer_index);
    return args->lwip_err;
}

struct wg_update_endpoint_call {
    struct tcpip_api_call_data call;
    struct netif *netif;
    const ip_addr_t *ip;
    uint16_t port;
    err_t lwip_err;
};

/* Runs on tcpip_thread. See "tcpip_thread marshaling" above. */
static err_t esp_wireguard_update_endpoint_tcpip(struct tcpip_api_call_data *call)
{
    struct wg_update_endpoint_call *args = (struct wg_update_endpoint_call *)call;

    args->lwip_err = wireguardif_update_endpoint(args->netif, wireguard_peer_index, args->ip, args->port);
    return args->lwip_err;
}

esp_err_t esp_wireguard_connect(wireguard_ctx_t *ctx)
{
    esp_err_t err = ESP_FAIL;

    if (!ctx) {
        err = ESP_ERR_INVALID_ARG;
        goto fail;
    }

    /* Wait for a plausible clock before sending anything. The ESP32 has no
     * RTC, so without this, a handshake sent right after boot (before
     * SNTP -- or whatever the application uses -- has set the clock) can
     * carry a TAI64N timestamp lower than one the peer has already seen
     * from an earlier boot, and get silently rejected as a replay. This
     * runs on every call (first connect and later reconnects alike),
     * since a reconnect after a reboot hits the same unset-clock window.
     * See CHANGES-fork.md, issue #5, for the full writeup. */
    {
        uint32_t waited_ms = 0;
        const uint32_t timeout_ms = CONFIG_WIREGUARD_TIME_SYNC_TIMEOUT_MS;
        const uint32_t poll_ms = CONFIG_WIREGUARD_TIME_SYNC_POLL_INTERVAL_MS;

        while (!wireguard_platform_time_is_synced()) {
            if (waited_ms >= timeout_ms) {
                ESP_LOGE(TAG, "esp_wireguard_connect: clock not synced after %" PRIu32 "ms, giving up", waited_ms);
                err = ESP_ERR_TIMEOUT;
                goto fail;
            }
            if (waited_ms == 0) {
                ESP_LOGI(TAG, "esp_wireguard_connect: waiting for the clock to sync before connecting");
            }
            vTaskDelay(pdMS_TO_TICKS(poll_ms));
            waited_ms += poll_ms;
        }
    }

    if (ctx->netif == NULL) {
        struct wg_add_peer_call add_peer_args = {0};

        err = esp_wireguard_netif_create(ctx->config);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "esp_wireguard_netif_create: %s", esp_err_to_name(err));
            goto fail;
        }

        /* Initialize the first WireGuard peer structure. This resolves
         * the peer endpoint via getaddrinfo(), which is why it stays on
         * the caller's task (see "tcpip_thread marshaling" above). */
        err = esp_wireguard_peer_init(ctx->config, &peer);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "esp_wireguard_peer_init: %s", esp_err_to_name(err));
            goto fail;
        }

        /* Register the new WireGuard peer with the network interface */
        add_peer_args.peer = &peer;
        tcpip_api_call(esp_wireguard_add_peer_tcpip, &add_peer_args.call);
        if (add_peer_args.lwip_err != ERR_OK || wireguard_peer_index == WIREGUARDIF_INVALID_INDEX) {
            ESP_LOGE(TAG, "wireguardif_add_peer: %i", add_peer_args.lwip_err);
            err = ESP_FAIL;
            goto fail;
        }
        if (ip_addr_isany(&peer.endpoint_ip)) {
            err = ESP_FAIL;
            goto fail;
        }
        ctx->netif = wg_netif;
        ctx->netif_default = netif_default;
    } else {
        /* Reconnecting on an already-created interface: re-resolve the
         * peer's endpoint instead of reusing whatever address the very
         * first connect happened to resolve. esp_wireguard_peer_init()
         * re-does the (idempotent) key setup too, but the only thing that
         * can actually have changed is the resolved endpoint_ip/port, so
         * that's the only piece applied below. See CHANGES-fork.md, Phase
         * 5, "endpoint re-resolution on reconnect". */
        esp_err_t resolve_err = esp_wireguard_peer_init(ctx->config, &peer);

        if (resolve_err != ESP_OK) {
            ESP_LOGW(TAG, "esp_wireguard_peer_init (re-resolve on reconnect): %s, keeping previous endpoint", esp_err_to_name(resolve_err));
        } else {
            struct wg_update_endpoint_call update_args = {0};

            update_args.netif = ctx->netif;
            update_args.ip = &peer.endpoint_ip;
            update_args.port = peer.endport_port;
            tcpip_api_call(esp_wireguard_update_endpoint_tcpip, &update_args.call);
            if (update_args.lwip_err != ERR_OK) {
                ESP_LOGW(TAG, "wireguardif_update_endpoint: %i, keeping previous endpoint", update_args.lwip_err);
            }
        }
    }

    {
        struct wg_connect_call connect_args = {0};

        ESP_LOGI(TAG, "Connecting to %s:%i", ctx->config->endpoint, ctx->config->port);
        tcpip_api_call(esp_wireguard_connect_tcpip, &connect_args.call);
        if (connect_args.lwip_err != ERR_OK) {
            ESP_LOGE(TAG, "wireguardif_connect: %i", connect_args.lwip_err);
            err = ESP_FAIL;
            goto fail;
        }
    }
    err = ESP_OK;
fail:
    return err;
}

struct wg_set_default_call {
    struct tcpip_api_call_data call;
    struct netif *netif;
};

/* Runs on tcpip_thread. See "tcpip_thread marshaling" above. */
static err_t esp_wireguard_set_default_tcpip(struct tcpip_api_call_data *call)
{
    struct wg_set_default_call *args = (struct wg_set_default_call *)call;

    netif_set_default(args->netif);
    return ERR_OK;
}

esp_err_t esp_wireguard_set_default(wireguard_ctx_t *ctx)
{
    esp_err_t err;
    struct wg_set_default_call args = {0};

    if (!ctx) {
        err = ESP_ERR_INVALID_ARG;
        goto fail;
    }
    args.netif = ctx->netif;
    tcpip_api_call(esp_wireguard_set_default_tcpip, &args.call);
    err = ESP_OK;
fail:
    return err;
}

struct wg_disconnect_call {
    struct tcpip_api_call_data call;
    struct netif *netif;
    struct netif *netif_default;
};

/* Runs on tcpip_thread. See "tcpip_thread marshaling" above. Mirrors the
 * original sequential teardown, just performed atomically with respect
 * to tcpip_thread instead of racing it. */
static err_t esp_wireguard_disconnect_tcpip(struct tcpip_api_call_data *call)
{
    struct wg_disconnect_call *args = (struct wg_disconnect_call *)call;
    err_t lwip_err;

    // Clear the IP address to gracefully disconnect any clients while the
    // peers are still valid
    netif_set_ipaddr(args->netif, IP4_ADDR_ANY4);

    lwip_err = wireguardif_disconnect(args->netif, wireguard_peer_index);
    if (lwip_err != ERR_OK) {
        ESP_LOGW(TAG, "wireguardif_disconnect: peer_index: %" PRIu8 " err: %i", wireguard_peer_index, lwip_err);
    }

    lwip_err = wireguardif_remove_peer(args->netif, wireguard_peer_index);
    if (lwip_err != ERR_OK) {
        ESP_LOGW(TAG, "wireguardif_remove_peer: peer_index: %" PRIu8 " err: %i", wireguard_peer_index, lwip_err);
    }

    wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;
    wireguardif_shutdown(args->netif);
    netif_remove(args->netif);
    wireguardif_fini(args->netif);
    netif_set_default(args->netif_default);

    return ERR_OK;
}

esp_err_t esp_wireguard_disconnect(wireguard_ctx_t *ctx)
{
    esp_err_t err;
    struct wg_disconnect_call args = {0};

    if (!ctx) {
        err = ESP_ERR_INVALID_ARG;
        goto fail;
    }

    args.netif = ctx->netif;
    args.netif_default = ctx->netif_default;
    tcpip_api_call(esp_wireguard_disconnect_tcpip, &args.call);
    ctx->netif = NULL;

    err = ESP_OK;
fail:
    return err;
}

struct wg_peer_is_up_call {
    struct tcpip_api_call_data call;
    struct netif *netif;
    err_t lwip_err;
};

/* Runs on tcpip_thread. See "tcpip_thread marshaling" above. */
static err_t esp_wireguardif_peer_is_up_tcpip(struct tcpip_api_call_data *call)
{
    struct wg_peer_is_up_call *args = (struct wg_peer_is_up_call *)call;

    args->lwip_err = wireguardif_peer_is_up(
            args->netif,
            wireguard_peer_index,
            &peer.endpoint_ip,
            &peer.endport_port);
    return args->lwip_err;
}

esp_err_t esp_wireguardif_peer_is_up(wireguard_ctx_t *ctx)
{
    esp_err_t err;
    struct wg_peer_is_up_call args = {0};

    if (!ctx) {
        err = ESP_ERR_INVALID_ARG;
        goto fail;
    }

    args.netif = ctx->netif;
    tcpip_api_call(esp_wireguardif_peer_is_up_tcpip, &args.call);

    if (args.lwip_err != ERR_OK) {
        err = ESP_FAIL;
        goto fail;
    }
    err = ESP_OK;
fail:
    return err;
}

/*
 * ---------------------------------------------------------------------
 * Monitor task (Phase 5: events instead of polling, auto-reconnect)
 * ---------------------------------------------------------------------
 *
 * See esp_wireguard_start_monitor()'s doc comment in esp_wireguard.h for
 * what this does and why. Only one monitor is supported at a time, same
 * as the rest of this component's single-peer design (wireguard_peer_index
 * and friends are static singletons too).
 */

static TaskHandle_t monitor_task_handle = NULL;
static esp_event_handler_instance_t monitor_ip_event_instance = NULL;

/* Registered for IP_EVENT, any event ID. Only IP_EVENT_STA_GOT_IP and
 * IP_EVENT_ETH_GOT_IP (whichever this build has) mean anything here; any
 * other IP_EVENT id (e.g. IP_EVENT_STA_LOST_IP) is ignored. Runs on the
 * default event loop task, not tcpip_thread -- it only wakes the monitor
 * task via a notification, it does not touch netif/wireguardif state
 * itself, so no marshaling is needed here. */
static void wg_monitor_ip_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    (void)arg;
    (void)event_data;

    if (event_base != IP_EVENT) {
        return;
    }
    if (event_id != IP_EVENT_STA_GOT_IP
#if defined(IP_EVENT_ETH_GOT_IP)
            && event_id != IP_EVENT_ETH_GOT_IP
#endif
       ) {
        return;
    }
    if (monitor_task_handle != NULL) {
        xTaskNotifyGive(monitor_task_handle);
    }
}

static void wg_monitor_task(void *arg)
{
    wireguard_ctx_t *ctx = (wireguard_ctx_t *)arg;
    bool was_up = false;

    for (;;) {
        /* Block for one poll interval, but wake early (ulTaskNotifyTake
         * returning non-zero) if the IP-event handler above notified us.
         * Either way, re-check peer_is_up() right after. */
        uint32_t ip_recovered = ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(CONFIG_WIREGUARD_MONITOR_POLL_INTERVAL_MS));
        bool is_up = (esp_wireguardif_peer_is_up(ctx) == ESP_OK);

        if (is_up && !was_up) {
            ESP_LOGI(TAG, "wg_monitor: peer up");
            esp_event_post(WIREGUARD_EVENT, WIREGUARD_EVENT_PEER_UP, NULL, 0, 0);
        } else if (!is_up && was_up) {
            ESP_LOGI(TAG, "wg_monitor: peer down");
            esp_event_post(WIREGUARD_EVENT, WIREGUARD_EVENT_PEER_DOWN, NULL, 0, 0);
        }
        was_up = is_up;

        if (ip_recovered && !is_up && ctx->netif != NULL) {
            /* The underlying network interface just got an IP again while
             * the peer was down: most likely WiFi dropped and reconnected.
             * esp_wireguard_connect() re-resolves the endpoint and is safe
             * to call again on an already-created interface. */
            esp_err_t err;

            ESP_LOGI(TAG, "wg_monitor: IP recovered while peer is down, attempting reconnect");
            err = esp_wireguard_connect(ctx);
            if (err != ESP_OK) {
                ESP_LOGW(TAG, "wg_monitor: reconnect attempt failed: %s", esp_err_to_name(err));
            }
        }
    }
}

esp_err_t esp_wireguard_start_monitor(wireguard_ctx_t *ctx)
{
    esp_err_t err;

    if (!ctx) {
        return ESP_ERR_INVALID_ARG;
    }
    if (monitor_task_handle != NULL) {
        ESP_LOGW(TAG, "esp_wireguard_start_monitor: a monitor is already running");
        return ESP_ERR_INVALID_STATE;
    }

    /* Registering for IP_EVENT with ESP_EVENT_ANY_ID requires a default
     * event loop to already exist (examples/demo creates one for its own
     * WiFi event handling via esp_event_loop_create_default()). If none
     * exists yet, this fails with ESP_ERR_INVALID_STATE, which we just
     * pass up rather than creating one ourselves -- owning the default
     * event loop's lifetime is the application's job, not this
     * component's. */
    err = esp_event_handler_instance_register(IP_EVENT, ESP_EVENT_ANY_ID,
            &wg_monitor_ip_event_handler, NULL, &monitor_ip_event_instance);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wireguard_start_monitor: esp_event_handler_instance_register: %s", esp_err_to_name(err));
        return err;
    }

    if (xTaskCreate(wg_monitor_task, "wg_monitor", 4096, ctx, tskIDLE_PRIORITY + 1, &monitor_task_handle) != pdPASS) {
        ESP_LOGE(TAG, "esp_wireguard_start_monitor: xTaskCreate failed");
        esp_event_handler_instance_unregister(IP_EVENT, ESP_EVENT_ANY_ID, monitor_ip_event_instance);
        monitor_ip_event_instance = NULL;
        return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t esp_wireguard_stop_monitor(void)
{
    if (monitor_task_handle == NULL) {
        return ESP_OK;
    }

    vTaskDelete(monitor_task_handle);
    monitor_task_handle = NULL;

    if (monitor_ip_event_instance != NULL) {
        esp_event_handler_instance_unregister(IP_EVENT, ESP_EVENT_ANY_ID, monitor_ip_event_instance);
        monitor_ip_event_instance = NULL;
    }

    return ESP_OK;
}

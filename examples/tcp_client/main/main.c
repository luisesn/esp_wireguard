/* Minimal point-to-point TCP client example (CHANGES-fork.md, Phase 7).

   Connects to WiFi, brings up a single WireGuard tunnel to one peer, and
   repeatedly opens a plain TCP connection *to that peer* over the tunnel,
   sends one message, logs whatever comes back, and closes it again. This
   is deliberately the smallest useful demonstration of what this fork is
   actually for -- a point-to-point tunnel carrying ordinary TCP traffic to
   a single known peer -- not a full VPN gateway example. See
   examples/demo for a larger example that also exercises ICMP, a
   configurable-duration throughput test, events/auto-reconnect, and a
   disconnect/reconnect loop.

   This example code is in the Public Domain (or CC0 licensed, at your
   option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/event_groups.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_system.h>
#include <esp_wifi.h>
#include <esp_netif.h>
#include <nvs_flash.h>
#include <lwip/sockets.h>
#include <lwip/netdb.h>

#include <esp_wireguard.h>
#include "sync_time.h"

#define EXAMPLE_ESP_WIFI_SSID      CONFIG_ESP_WIFI_SSID
#define EXAMPLE_ESP_WIFI_PASS      CONFIG_ESP_WIFI_PASSWORD
#define EXAMPLE_ESP_MAXIMUM_RETRY  CONFIG_ESP_MAXIMUM_RETRY

static const char *TAG = "tcp_client";
static int s_retry_num = 0;
static wireguard_config_t wg_config = ESP_WIREGUARD_CONFIG_DEFAULT();

static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

/* Set/cleared by wg_event_handler() in response to WIREGUARD_EVENT instead
 * of polling esp_wireguardif_peer_is_up() (CHANGES-fork.md, Phase 5). */
static EventGroupHandle_t s_wg_event_group;
#define WG_PEER_UP_BIT BIT0

static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < EXAMPLE_ESP_MAXIMUM_RETRY) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "retry to connect to the AP");
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
        ESP_LOGI(TAG, "connect to the AP fail");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wg_event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data)
{
    if (event_base != WIREGUARD_EVENT) {
        return;
    }
    switch (event_id) {
        case WIREGUARD_EVENT_PEER_UP:
            ESP_LOGI(TAG, "WIREGUARD_EVENT_PEER_UP");
            xEventGroupSetBits(s_wg_event_group, WG_PEER_UP_BIT);
            break;
        case WIREGUARD_EVENT_PEER_DOWN:
            ESP_LOGI(TAG, "WIREGUARD_EVENT_PEER_DOWN");
            xEventGroupClearBits(s_wg_event_group, WG_PEER_UP_BIT);
            break;
        default:
            break;
    }
}

static esp_err_t wifi_init_sta(void)
{
    esp_err_t err = ESP_FAIL;

    s_wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    assert(esp_netif_create_default_wifi_sta());

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = EXAMPLE_ESP_WIFI_SSID,
            .password = EXAMPLE_ESP_WIFI_PASS,
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
            .pmf_cfg = {
                .capable = true,
                .required = false
            },
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
            pdFALSE, pdFALSE, portMAX_DELAY);

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "Connected to ap SSID:%s", EXAMPLE_ESP_WIFI_SSID);
        err = ESP_OK;
    } else {
        ESP_LOGE(TAG, "Failed to connect to SSID:%s", EXAMPLE_ESP_WIFI_SSID);
        err = ESP_FAIL;
    }
    return err;
}

static esp_err_t wireguard_setup(wireguard_ctx_t* ctx)
{
    esp_err_t err;

    ESP_LOGI(TAG, "Initializing WireGuard.");
    wg_config.private_key = CONFIG_WG_PRIVATE_KEY;
    wg_config.listen_port = CONFIG_WG_LOCAL_PORT;
    wg_config.public_key = CONFIG_WG_PEER_PUBLIC_KEY;
    wg_config.preshared_key = (strcmp(CONFIG_WG_PRESHARED_KEY, "") != 0) ? CONFIG_WG_PRESHARED_KEY : NULL;
    wg_config.allowed_ip = CONFIG_WG_LOCAL_IP_ADDRESS;
    wg_config.allowed_ip_mask = CONFIG_WG_LOCAL_IP_NETMASK;
    wg_config.endpoint = CONFIG_WG_PEER_ADDRESS;
    wg_config.port = CONFIG_WG_PEER_PORT;
    wg_config.persistent_keepalive = CONFIG_WG_PERSISTENT_KEEP_ALIVE;

    err = esp_wireguard_init(&wg_config, ctx);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wireguard_init: %s", esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "Connecting to the peer.");
    err = esp_wireguard_connect(ctx);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wireguard_connect: %s", esp_err_to_name(err));
        return err;
    }
    return ESP_OK;
}

/* The actual point-to-point TCP client: one short-lived connection per
 * call, over the tunnel, to the peer's tunnel IP. */
static void tcp_client_once(void)
{
    char rx_buf[128];
    struct sockaddr_in dest_addr = {0};
    int sock;
    int ret;

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(CONFIG_EXAMPLE_TCP_SERVER_PORT);
    if (inet_pton(AF_INET, CONFIG_EXAMPLE_TCP_SERVER_ADDRESS, &dest_addr.sin_addr) != 1) {
        ESP_LOGE(TAG, "inet_pton: invalid CONFIG_EXAMPLE_TCP_SERVER_ADDRESS: %s", CONFIG_EXAMPLE_TCP_SERVER_ADDRESS);
        return;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        ESP_LOGE(TAG, "socket: errno %d", errno);
        return;
    }

    ESP_LOGI(TAG, "Connecting to %s:%d over the tunnel...",
            CONFIG_EXAMPLE_TCP_SERVER_ADDRESS, CONFIG_EXAMPLE_TCP_SERVER_PORT);
    if (connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) != 0) {
        ESP_LOGW(TAG, "connect: errno %d, will retry in %ds", errno, CONFIG_EXAMPLE_TCP_RETRY_INTERVAL_SEC);
        close(sock);
        return;
    }
    ESP_LOGI(TAG, "Connected.");

    ret = send(sock, CONFIG_EXAMPLE_TCP_MESSAGE, strlen(CONFIG_EXAMPLE_TCP_MESSAGE), 0);
    if (ret < 0) {
        ESP_LOGW(TAG, "send: errno %d", errno);
        close(sock);
        return;
    }

    /* Give the peer a moment to respond, then read whatever's there (if
     * anything -- a plain `nc -l` echoes nothing back on its own unless
     * told to, which is fine, this is just a connectivity demonstration). */
    struct timeval timeout = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ret = recv(sock, rx_buf, sizeof(rx_buf) - 1, 0);
    if (ret > 0) {
        rx_buf[ret] = '\0';
        ESP_LOGI(TAG, "Received %d bytes: %s", ret, rx_buf);
    } else if (ret == 0) {
        ESP_LOGI(TAG, "Peer closed the connection.");
    } else {
        ESP_LOGI(TAG, "recv: errno %d (no reply within timeout is normal for a plain `nc -l`)", errno);
    }

    close(sock);
}

void app_main(void)
{
    esp_err_t err;
    time_t now;
    struct tm timeinfo;
    char strftime_buf[64];
    wireguard_ctx_t ctx = {0};

    err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    ESP_ERROR_CHECK(wifi_init_sta());

    /* Both peers need synced time: WireGuard's handshake replay
     * protection rejects a timestamp lower than one already seen, and the
     * ESP32 has no RTC, so it reads near the Unix epoch after every
     * reboot until SNTP sets it. esp_wireguard_connect() itself also
     * waits (CONFIG_WIREGUARD_TIME_SYNC_TIMEOUT_MS) for a plausible clock
     * before sending anything, but starting SNTP is still this
     * application's job, not the library's -- see CHANGES-fork.md,
     * issue #5. */
    obtain_time();
    time(&now);
    localtime_r(&now, &timeinfo);
    strftime(strftime_buf, sizeof(strftime_buf), "%c", &timeinfo);
    ESP_LOGI(TAG, "Current time: %s", strftime_buf);

    ESP_ERROR_CHECK(wireguard_setup(&ctx));

    /* Events instead of polling for peer up (CHANGES-fork.md, Phase 5).
     * esp_wireguard_start_monitor() also handles auto-reconnect on IP
     * recovery and endpoint re-resolution on its own -- nothing else to
     * do here for those. A real deployment behind flaky power/WiFi may
     * also want esp_wifi_set_ps(WIFI_PS_NONE); see that function's doc
     * comment in esp_wireguard.h for why. */
    s_wg_event_group = xEventGroupCreate();
    {
        esp_event_handler_instance_t instance_wg_event;

        ESP_ERROR_CHECK(esp_event_handler_instance_register(WIREGUARD_EVENT,
                                                            ESP_EVENT_ANY_ID,
                                                            &wg_event_handler,
                                                            NULL,
                                                            &instance_wg_event));
    }
    ESP_ERROR_CHECK(esp_wireguard_start_monitor(&ctx));

    ESP_LOGI(TAG, "Waiting for the WireGuard peer to come up...");
    xEventGroupWaitBits(s_wg_event_group, WG_PEER_UP_BIT, pdFALSE, pdFALSE, portMAX_DELAY);
    ESP_LOGI(TAG, "Peer is up.");

    while (1) {
        /* Only attempt a connection while the tunnel is actually up --
         * otherwise just wait for the monitor to bring it back (it
         * auto-reconnects on IP recovery; see above). */
        if (xEventGroupGetBits(s_wg_event_group) & WG_PEER_UP_BIT) {
            tcp_client_once();
        } else {
            ESP_LOGI(TAG, "Peer is down, waiting...");
        }
        vTaskDelay(pdMS_TO_TICKS(CONFIG_EXAMPLE_TCP_RETRY_INTERVAL_SEC * 1000));
    }
}

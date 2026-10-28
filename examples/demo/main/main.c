/* WireGuard demo example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <sys/time.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/event_groups.h>
#include <esp_event.h>
#include <esp_idf_version.h>
#include <esp_log.h>
#include <esp_system.h>
#include <esp_wifi.h>
#include <nvs_flash.h>
#include <lwip/netdb.h>
#include <ping/ping_sock.h>

#include <esp_wireguard.h>
#include "sync_time.h"
#include "tcp_throughput_test.h"

#define EXAMPLE_ESP_WIFI_SSID      CONFIG_ESP_WIFI_SSID
#define EXAMPLE_ESP_WIFI_PASS      CONFIG_ESP_WIFI_PASSWORD
#define EXAMPLE_ESP_MAXIMUM_RETRY  CONFIG_ESP_MAXIMUM_RETRY

#include <esp_netif.h>

/* FreeRTOS event group to signal when we are connected*/
static EventGroupHandle_t s_wifi_event_group;

/* The event group allows multiple bits for each event, but we only care about two events:
 * - we are connected to the AP with an IP
 * - we failed to connect after the maximum amount of retries */
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static const char *TAG = "demo";
static int s_retry_num = 0;
static wireguard_config_t wg_config = ESP_WIREGUARD_CONFIG_DEFAULT();

/* Set/cleared by wg_event_handler() below in response to WIREGUARD_EVENT,
 * instead of app_main() polling esp_wireguardif_peer_is_up() itself. See
 * CHANGES-fork.md, Phase 5. */
static EventGroupHandle_t s_wg_event_group;
#define WG_PEER_UP_BIT BIT0

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

static esp_err_t wireguard_setup(wireguard_ctx_t* ctx)
{
    esp_err_t err = ESP_FAIL;

    ESP_LOGI(TAG, "Initializing WireGuard.");
    wg_config.private_key = CONFIG_WG_PRIVATE_KEY;
    wg_config.listen_port = CONFIG_WG_LOCAL_PORT;
    wg_config.public_key = CONFIG_WG_PEER_PUBLIC_KEY;
    if (strcmp(CONFIG_WG_PRESHARED_KEY, "") != 0) {
        wg_config.preshared_key = CONFIG_WG_PRESHARED_KEY;
    } else {
        wg_config.preshared_key = NULL;
    }
    wg_config.allowed_ip = CONFIG_WG_LOCAL_IP_ADDRESS;
    wg_config.allowed_ip_mask = CONFIG_WG_LOCAL_IP_NETMASK;
    wg_config.endpoint = CONFIG_WG_PEER_ADDRESS;
    wg_config.port = CONFIG_WG_PEER_PORT;
    wg_config.persistent_keepalive = CONFIG_WG_PERSISTENT_KEEP_ALIVE;

    err = esp_wireguard_init(&wg_config, ctx);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wireguard_init: %s", esp_err_to_name(err));
        goto fail;
    }

    ESP_LOGI(TAG, "Connecting to the peer.");
    err = esp_wireguard_connect(ctx);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wireguard_connect: %s", esp_err_to_name(err));
        goto fail;
    }

    err = ESP_OK;
fail:
    return err;
}

static void event_handler(void* arg, esp_event_base_t event_base,
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
        ESP_LOGI(TAG,"connect to the AP fail");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static esp_err_t wifi_init_netif(void)
{
    esp_err_t err = ESP_FAIL;
    esp_netif_t *sta_netif;

    s_wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());

    ESP_ERROR_CHECK(esp_event_loop_create_default());
    sta_netif = esp_netif_create_default_wifi_sta();
    assert(sta_netif);

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = EXAMPLE_ESP_WIFI_SSID,
            .password = EXAMPLE_ESP_WIFI_PASS,
            /* Setting a password implies station will connect to all security modes including WEP/WPA.
             * However these modes are deprecated and not advisable to be used. Incase your Access point
             * doesn't support WPA2, these mode can be enabled by commenting below line */
         .threshold.authmode = WIFI_AUTH_WPA2_PSK,

            .pmf_cfg = {
                .capable = true,
                .required = false
            },
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config) );
    ESP_ERROR_CHECK(esp_wifi_start() );

    /* Waiting until either the connection is established (WIFI_CONNECTED_BIT) or connection failed for the maximum
     * number of re-tries (WIFI_FAIL_BIT). The bits are set by event_handler() (see above) */
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
            pdFALSE,
            pdFALSE,
            portMAX_DELAY);

    /* xEventGroupWaitBits() returns the bits before the call returned, hence we can test which event actually
     * happened. */
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "Connected to ap SSID:%s", EXAMPLE_ESP_WIFI_SSID);
    } else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGI(TAG, "Failed to connect to SSID:%s", EXAMPLE_ESP_WIFI_SSID);
        err = ESP_FAIL;
        goto fail;
    } else {
        ESP_LOGE(TAG, "Unknown event");
        err = ESP_FAIL;
        goto fail;
    }

    err = esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, instance_got_ip);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_event_handler_instance_unregister: %s", esp_err_to_name(err));
        goto fail;
    }
    err = esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, instance_any_id);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_event_handler_instance_unregister: %s", esp_err_to_name(err));
        goto fail;
    }
    vEventGroupDelete(s_wifi_event_group);

    err = ESP_OK;
fail:
    return err;
}

static esp_err_t wifi_init_sta(void)
{
    return wifi_init_netif();
}
static void test_on_ping_success(esp_ping_handle_t hdl, void *args)
{
    uint8_t ttl;
    uint16_t seqno;
    uint32_t elapsed_time, recv_len;
    ip_addr_t target_addr;
    esp_ping_get_profile(hdl, ESP_PING_PROF_SEQNO, &seqno, sizeof(seqno));
    esp_ping_get_profile(hdl, ESP_PING_PROF_TTL, &ttl, sizeof(ttl));
    esp_ping_get_profile(hdl, ESP_PING_PROF_IPADDR, &target_addr, sizeof(target_addr));
    esp_ping_get_profile(hdl, ESP_PING_PROF_SIZE, &recv_len, sizeof(recv_len));
    esp_ping_get_profile(hdl, ESP_PING_PROF_TIMEGAP, &elapsed_time, sizeof(elapsed_time));
    ESP_LOGI(TAG, "%" PRIu32 " bytes from %s icmp_seq=%" PRIu16 " ttl=%" PRIi8 " time=%" PRIu32 " ms",
           recv_len, ipaddr_ntoa(&target_addr), seqno, ttl, elapsed_time);
}

static void test_on_ping_timeout(esp_ping_handle_t hdl, void *args)
{
    uint16_t seqno;
    ip_addr_t target_addr;
    esp_ping_get_profile(hdl, ESP_PING_PROF_SEQNO, &seqno, sizeof(seqno));
    esp_ping_get_profile(hdl, ESP_PING_PROF_IPADDR, &target_addr, sizeof(target_addr));
    ESP_LOGI(TAG, "From %s icmp_seq=%" PRIu16 " timeout", ipaddr_ntoa(&target_addr), seqno);
}

static void test_on_ping_end(esp_ping_handle_t hdl, void *args)
{
    uint32_t transmitted;
    uint32_t received;
    uint32_t total_time_ms;

    esp_ping_get_profile(hdl, ESP_PING_PROF_REQUEST, &transmitted, sizeof(transmitted));
    esp_ping_get_profile(hdl, ESP_PING_PROF_REPLY, &received, sizeof(received));
    esp_ping_get_profile(hdl, ESP_PING_PROF_DURATION, &total_time_ms, sizeof(total_time_ms));
    ESP_LOGI(TAG, "%" PRIu32 " packets transmitted, %" PRIu32 " received, time %" PRIu32 "ms", transmitted, received, total_time_ms);
}

void start_ping()
{
    ESP_LOGI(TAG, "Initializing ping...");
    /* convert URL to IP address */
    ip_addr_t target_addr;
    struct addrinfo *res = NULL;
    struct addrinfo hint;
    memset(&hint, 0, sizeof(hint));
    memset(&target_addr, 0, sizeof(target_addr));
    ESP_ERROR_CHECK(lwip_getaddrinfo(CONFIG_EXAMPLE_PING_ADDRESS, NULL, &hint, &res) == 0 ? ESP_OK : ESP_FAIL);
    struct in_addr addr4 = ((struct sockaddr_in *) (res->ai_addr))->sin_addr;
    inet_addr_to_ip4addr(ip_2_ip4(&target_addr), &addr4);
    lwip_freeaddrinfo(res);
    ESP_LOGI(TAG, "ICMP echo target: %s", CONFIG_EXAMPLE_PING_ADDRESS);
    esp_ping_config_t ping_config = ESP_PING_DEFAULT_CONFIG();
    ping_config.target_addr = target_addr;          // target IP address
    ping_config.count = ESP_PING_COUNT_INFINITE;    // ping in infinite mode, esp_ping_stop can stop it

    /* set callback functions */
    esp_ping_callbacks_t cbs;
    cbs.on_ping_success = test_on_ping_success;
    cbs.on_ping_timeout = test_on_ping_timeout;
    cbs.on_ping_end = test_on_ping_end;
    cbs.cb_args = NULL;

    esp_ping_handle_t ping;
    ESP_ERROR_CHECK(esp_ping_new_session(&ping_config, &cbs, &ping));
    esp_ping_start(ping);
}

#if CONFIG_EXAMPLE_TEST_CLOCK_WAIT
static void delayed_sntp_task(void *arg)
{
    (void)arg;
    ESP_LOGI(TAG, "clock-wait test: starting SNTP in 8 s");
    vTaskDelay(pdMS_TO_TICKS(8000));
    obtain_time();
    vTaskDelete(NULL);
}
#endif

void app_main(void)
{
    esp_err_t err;
    time_t now;
    struct tm timeinfo;
    char strftime_buf[64];
    wireguard_ctx_t ctx = {0};

    esp_log_level_set("esp_wireguard", ESP_LOG_DEBUG);
    esp_log_level_set("wireguardif", ESP_LOG_DEBUG);
    esp_log_level_set("wireguard", ESP_LOG_DEBUG);
    err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    err = wifi_init_sta();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "wifi_init_sta: %s", esp_err_to_name(err));
        goto fail;
    }

#if CONFIG_EXAMPLE_TEST_CLOCK_WAIT
    xTaskCreate(delayed_sntp_task, "delayed_sntp", 4096, NULL, 5, NULL);
#else
    obtain_time();
#endif
    time(&now);

    setenv("TZ", "EST5EDT,M3.2.0/2,M11.1.0", 1);
    tzset();
    localtime_r(&now, &timeinfo);
    strftime(strftime_buf, sizeof(strftime_buf), "%c", &timeinfo);
    ESP_LOGI(TAG, "The current date/time in New York is: %s", strftime_buf);

    err = wireguard_setup(&ctx);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "wireguard_setup: %s", esp_err_to_name(err));
        goto fail;
    }

    /* Phase 5: events instead of polling, plus auto-reconnect on IP
     * recovery and endpoint re-resolution (both handled inside
     * esp_wireguard_connect()/the monitor task itself -- nothing extra to
     * do here for those two). See esp_wireguard_start_monitor()'s doc
     * comment in esp_wireguard.h. */
    s_wg_event_group = xEventGroupCreate();
    {
        esp_event_handler_instance_t instance_wg_event;

        ESP_ERROR_CHECK(esp_event_handler_instance_register(WIREGUARD_EVENT,
                                                            ESP_EVENT_ANY_ID,
                                                            &wg_event_handler,
                                                            NULL,
                                                            &instance_wg_event));
    }
    err = esp_wireguard_start_monitor(&ctx);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wireguard_start_monitor: %s", esp_err_to_name(err));
        goto fail;
    }

    xEventGroupWaitBits(s_wg_event_group, WG_PEER_UP_BIT, pdFALSE, pdFALSE, portMAX_DELAY);
    ESP_LOGI(TAG, "Peer is up");
    start_ping();
    tcp_throughput_test_start();

#if !CONFIG_EXAMPLE_RECONNECT_CYCLE
    while (1) {
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
#endif

    while (1) {
        vTaskDelay(1000 * 10 / portTICK_PERIOD_MS);
        ESP_LOGI(TAG, "Disconnecting.");
        esp_wireguard_disconnect(&ctx);
        ESP_LOGI(TAG, "Disconnected.");

        vTaskDelay(1000 * 10 / portTICK_PERIOD_MS);
        ESP_LOGI(TAG, "Connecting.");
        err = esp_wireguard_connect(&ctx);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "esp_wireguard_connect: %s", esp_err_to_name(err));
            goto fail;
        }
        xEventGroupWaitBits(s_wg_event_group, WG_PEER_UP_BIT, pdFALSE, pdFALSE, portMAX_DELAY);
        ESP_LOGI(TAG, "Peer is up");
        esp_wireguard_set_default(&ctx);
    }

fail:
    ESP_LOGE(TAG, "Halting due to error");
    while (1) {
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
}

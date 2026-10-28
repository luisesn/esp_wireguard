/* TCP throughput test for CHANGES-fork.md's Phase 4 (MTU/MSS tuning,
 * throughput testing, 24h soak). See tcp_throughput_test.h and
 * Kconfig.projbuild ("TCP throughput test (Phase 4)") for the rationale:
 * this is deliberately a plain byte-pump, not an iperf reimplementation,
 * so the far end only needs a generic TCP listener/sender (`nc` is
 * enough), not a specific tool whose wire protocol has to match.
 *
 * This example code is in the Public Domain (or CC0 licensed, at your
 * option), matching the rest of examples/demo.
 */
#include "tcp_throughput_test.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_log.h>
#include <esp_timer.h>

#if CONFIG_EXAMPLE_TCP_TEST_ENABLE

static const char *TAG = "tcp_throughput_test";

#define BUF_SIZE 4096
#define LOG_INTERVAL_US (2 * 1000 * 1000)

static void log_rate(const char *label, uint64_t bytes, int64_t elapsed_us)
{
    if (elapsed_us <= 0) {
        return;
    }
    double seconds = elapsed_us / 1e6;
    double kbytes_per_sec = (double)bytes / 1024.0 / seconds;
    double mbit_per_sec = (double)bytes * 8.0 / 1e6 / seconds;
    ESP_LOGI(TAG, "%s: %llu bytes in %.1fs -> %.1f KB/s (%.2f Mbit/s)",
             label, (unsigned long long)bytes, seconds, kbytes_per_sec, mbit_per_sec);
}

/* Shared pump loop for one already-connected socket, in either direction.
 * Returns when the connection ends (peer closed, error) or, for a
 * bounded test (duration_sec > 0), when the duration elapses -- in which
 * case the caller is expected to stop entirely (a bounded run is a
 * one-shot test, not a stage of the soak loop). *stop_requested is set
 * to true in that case so the caller knows not to reconnect/re-accept. */
static void pump(int sock, bool is_tx, int duration_sec, bool *stop_requested)
{
    /* Heap, not stack: BUF_SIZE is as large as the whole task stack. */
    uint8_t *buf = malloc(BUF_SIZE);
    if (buf == NULL) {
        ESP_LOGE(TAG, "malloc(%d) failed", BUF_SIZE);
        return;
    }
    if (is_tx) {
        memset(buf, 0xA5, BUF_SIZE);
    }

    uint64_t total_bytes = 0;
    uint64_t bytes_since_log = 0;
    int64_t start_us = esp_timer_get_time();
    int64_t last_log_us = start_us;

    while (1) {
        ssize_t n = is_tx ? send(sock, buf, BUF_SIZE, 0)
                          : recv(sock, buf, BUF_SIZE, 0);
        if (n <= 0) {
            /* 0 = orderly close by the peer; <0 = error (ECONNRESET and
             * similar are routine here -- the whole point of the soak
             * test is to survive the tunnel dropping and reconnecting
             * underneath this socket, so this is not logged as an
             * error, just as the end of this connection). */
            break;
        }
        total_bytes += n;
        bytes_since_log += n;

        int64_t now_us = esp_timer_get_time();
        if (now_us - last_log_us >= LOG_INTERVAL_US) {
            log_rate(is_tx ? "TX (interval)" : "RX (interval)", bytes_since_log, now_us - last_log_us);
            bytes_since_log = 0;
            last_log_us = now_us;
        }

        if (duration_sec > 0 && (now_us - start_us) >= (int64_t)duration_sec * 1000 * 1000) {
            *stop_requested = true;
            break;
        }
    }

    log_rate(is_tx ? "TX (total)" : "RX (total)", total_bytes, esp_timer_get_time() - start_us);
    free(buf);
}

static void tcp_test_rx_task(void *arg)
{
    (void)arg;
    int duration_sec = CONFIG_EXAMPLE_TCP_TEST_DURATION_SEC;
    int listen_sock = -1;

    while (1) {
        listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listen_sock < 0) {
            ESP_LOGE(TAG, "socket() failed: errno %d", errno);
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }

        int opt = 1;
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(CONFIG_EXAMPLE_TCP_TEST_PORT);

        if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            ESP_LOGE(TAG, "bind() failed: errno %d", errno);
            close(listen_sock);
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }
        if (listen(listen_sock, 1) != 0) {
            ESP_LOGE(TAG, "listen() failed: errno %d", errno);
            close(listen_sock);
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }

        ESP_LOGI(TAG, "RX mode: listening on port %d", CONFIG_EXAMPLE_TCP_TEST_PORT);

        bool stop_requested = false;
        while (!stop_requested) {
            struct sockaddr_in peer_addr;
            socklen_t peer_addr_len = sizeof(peer_addr);
            int conn = accept(listen_sock, (struct sockaddr *)&peer_addr, &peer_addr_len);
            if (conn < 0) {
                ESP_LOGE(TAG, "accept() failed: errno %d", errno);
                break;
            }
            char addr_str[INET_ADDRSTRLEN];
            inet_ntoa_r(peer_addr.sin_addr, addr_str, sizeof(addr_str));
            ESP_LOGI(TAG, "RX mode: connection from %s", addr_str);

            pump(conn, false, duration_sec, &stop_requested);
            close(conn);
            ESP_LOGI(TAG, "RX mode: connection closed");
        }

        close(listen_sock);

        if (duration_sec > 0) {
            /* Bounded test: one run and done. */
            ESP_LOGI(TAG, "RX mode: test duration reached, stopping");
            break;
        }
        /* duration_sec == 0 (soak mode): the listening socket was closed
         * above only because the single connection we were pumping
         * ended -- go re-create it and accept again, so a WireGuard
         * rekey/reconnect (which doesn't itself touch this TCP
         * connection, but a real network drop that takes it down
         * alongside the tunnel will) doesn't require a device reset to
         * resume testing. */
    }

    vTaskDelete(NULL);
}

static void tcp_test_tx_task(void *arg)
{
    (void)arg;
    int duration_sec = CONFIG_EXAMPLE_TCP_TEST_DURATION_SEC;
    bool stop_requested = false;

    while (!stop_requested) {
        int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock < 0) {
            ESP_LOGE(TAG, "socket() failed: errno %d", errno);
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }

        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(CONFIG_EXAMPLE_TCP_TEST_PORT);
        if (inet_pton(AF_INET, CONFIG_EXAMPLE_TCP_TEST_PEER_ADDRESS, &addr.sin_addr) != 1) {
            ESP_LOGE(TAG, "invalid EXAMPLE_TCP_TEST_PEER_ADDRESS: %s", CONFIG_EXAMPLE_TCP_TEST_PEER_ADDRESS);
            close(sock);
            vTaskDelete(NULL);
            return;
        }

        ESP_LOGI(TAG, "TX mode: connecting to %s:%d", CONFIG_EXAMPLE_TCP_TEST_PEER_ADDRESS, CONFIG_EXAMPLE_TCP_TEST_PORT);
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            ESP_LOGW(TAG, "connect() failed: errno %d, retrying in 5s", errno);
            close(sock);
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }
        ESP_LOGI(TAG, "TX mode: connected, sending");

        pump(sock, true, duration_sec, &stop_requested);
        close(sock);
        ESP_LOGI(TAG, "TX mode: connection closed");

        if (duration_sec > 0) {
            ESP_LOGI(TAG, "TX mode: test duration reached, stopping");
            break;
        }
        /* duration_sec == 0 (soak mode): reconnect and keep sending, the
         * same way the RX side keeps re-accepting -- see the comment
         * there. */
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    vTaskDelete(NULL);
}

#endif /* CONFIG_EXAMPLE_TCP_TEST_ENABLE */

void tcp_throughput_test_start(void)
{
#if CONFIG_EXAMPLE_TCP_TEST_ENABLE
#if CONFIG_EXAMPLE_TCP_TEST_MODE_RX
    xTaskCreate(tcp_test_rx_task, "tcp_test_rx", 6144, NULL, 5, NULL);
#elif CONFIG_EXAMPLE_TCP_TEST_MODE_TX
    xTaskCreate(tcp_test_tx_task, "tcp_test_tx", 6144, NULL, 5, NULL);
#endif
#endif
}

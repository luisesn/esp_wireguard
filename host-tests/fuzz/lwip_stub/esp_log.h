/* Minimal stand-in for esp-idf's esp_log.h, for host-side fuzzing of
 * src/wireguard.c (see host-tests/fuzz/README.md). Logging is a no-op:
 * the fuzzer runs millions of iterations, and printing on every rejected
 * packet (which is most of them, by design) would be pure noise and slow
 * the fuzz loop down for no benefit. */
#ifndef ESP_LOG_STUB_H
#define ESP_LOG_STUB_H

#define ESP_LOGE(tag, fmt, ...) ((void)0)
#define ESP_LOGW(tag, fmt, ...) ((void)0)
#define ESP_LOGI(tag, fmt, ...) ((void)0)
#define ESP_LOGD(tag, fmt, ...) ((void)0)
#define ESP_LOGV(tag, fmt, ...) ((void)0)

#endif

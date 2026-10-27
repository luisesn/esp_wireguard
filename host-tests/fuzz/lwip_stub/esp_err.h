/* Minimal stand-in for esp-idf's esp_err.h, just enough for
 * wireguard-platform.h's esp_err_t wireguard_platform_init() declaration
 * to compile on the host. Nothing in the fuzz harness calls
 * wireguard_platform_init() (see fuzz_platform.c), so the exact values
 * don't matter -- only that the type exists. */
#ifndef ESP_ERR_STUB_H
#define ESP_ERR_STUB_H

typedef int esp_err_t;

#define ESP_OK 0
#define ESP_FAIL -1

#endif

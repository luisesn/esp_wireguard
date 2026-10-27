idf_component_register(SRCS "main.c" "sync_time.c" "tcp_throughput_test.c"
                    INCLUDE_DIRS "."
                    REQUIRES esp_wifi lwip esp_wireguard nvs_flash esp_timer)

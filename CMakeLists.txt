# This fork targets esp-idf >= 6.0 only (esp32, esp32s2, esp32s3, esp32c3).
# Support for esp-idf 4.x/5.x and ESP8266 RTOS SDK was dropped; see README.
if(${IDF_VERSION_MAJOR} LESS 6)
    message(FATAL_ERROR "esp_wireguard (this fork) requires esp-idf >= 6.0, found ${IDF_VERSION_MAJOR}.${IDF_VERSION_MINOR}")
endif()

idf_component_register(
    SRCS "src/crypto.c"
         "src/wireguard.c"
         "src/wireguardif.c"
         "src/wireguard-platform.c"
         "src/crypto/refc/blake2s.c"
         "src/crypto/refc/chacha20.c"
         "src/crypto/refc/chacha20poly1305.c"
         "src/crypto/refc/poly1305-donna.c"
         "src/crypto/refc/x25519.c"
         "src/esp_wireguard.c"
         "src/nacl/crypto_scalarmult/curve25519/ref/smult.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "src"
    REQUIRES esp_netif lwip mbedtls)

# Known false positive from GCC's -Wstringop-overread against this file's
# pointer arithmetic; kept as a targeted suppression rather than a blanket
# one so a real regression elsewhere still fails the build.
set_source_files_properties(src/crypto/refc/x25519.c
    PROPERTIES COMPILE_FLAGS
    -Wno-error=stringop-overread)

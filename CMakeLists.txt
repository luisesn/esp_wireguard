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
    REQUIRES esp_netif esp_event lwip mbedtls)

# Known false positive from GCC's -Wstringop-overread against mul()'s
# call in ladder_part1() (src/crypto/refc/x25519.c:218): mul() is called
# with nb=1 and only reads b[0], but GCC's diagnostic goes off the
# parameter's declared type (`const fe b`, i.e. `const limb_t[NLIMBS]`,
# NLIMBS=8) rather than the runtime `nb` bound, so it reports a read past
# the 1-element `a24` array actually passed in -- a read that never
# happens. -Wno-error= alone (an earlier version of this suppression)
# only demoted it to a non-fatal warning; fully silencing it here, rather
# than leaving a warning the MVP bar (CHANGES-fork.md) calls for a clean
# build, is deliberate and scoped to just this file so a real regression
# elsewhere still fails the build.
set_source_files_properties(src/crypto/refc/x25519.c
    PROPERTIES COMPILE_FLAGS
    -Wno-stringop-overread)

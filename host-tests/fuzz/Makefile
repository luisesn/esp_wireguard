# libFuzzer harness for src/wireguard.c's incoming-packet parsers (Phase 3's
# "fuzzing of the packet parser" item in CHANGES-fork.md). See README.md.
#
#   make fuzz          # build ./fuzz_wireguard
#   make run            # build and fuzz until Ctrl-C (or a crash)
#   make run SECS=120   # fuzz for a bounded time instead (for CI)
#   make repro CASE=... # re-run one saved crashing input under the fuzzer
#                        # binary directly, with full ASan output
#   make clean
#
# Needs clang (libFuzzer ships inside clang's compiler-rt, no separate
# install). Not gcc: gcc doesn't support -fsanitize=fuzzer.

CC      ?= clang
STUB    := lwip_stub
# These mirror Kconfig's defaults (see ../../Kconfig) -- normally supplied
# by sdkconfig.h in a real esp-idf build; the host build has no Kconfig,
# so they're pinned here instead.
CFLAGS  := -std=c11 -Wall -Wextra -g -O1 \
           -DCONFIG_WIREGUARD_x25519_IMPLEMENTATION_DEFAULT=1 \
           -DCONFIG_WIREGUARD_MAX_PEERS=1 \
           -DCONFIG_WIREGUARD_MAX_SRC_IPS=2 \
           -DCONFIG_MAX_INITIATIONS_PER_SECOND=2 \
           -I$(STUB) -I../../src -I../..
SAN     := -fsanitize=address,undefined,fuzzer

SRCS := fuzz_wireguard.c \
        fuzz_platform.c \
        ../../src/wireguard.c \
        ../../src/crypto.c \
        ../../src/crypto/refc/blake2s.c \
        ../../src/crypto/refc/chacha20.c \
        ../../src/crypto/refc/chacha20poly1305.c \
        ../../src/crypto/refc/poly1305-donna.c \
        ../../src/crypto/refc/x25519.c

.PHONY: fuzz run repro clean

fuzz_wireguard: $(SRCS)
	$(CC) $(CFLAGS) $(SAN) -o $@ $(SRCS)

fuzz: fuzz_wireguard

# -max_len matches the largest message struct (message_handshake_initiation,
# ~148 bytes) plus the 1 selector byte read by LLVMFuzzerTestOneInput --
# there's nothing for the fuzzer to usefully do with longer inputs since
# overlay() in fuzz_wireguard.c never reads past a template's fixed size.
run: fuzz_wireguard
	mkdir -p corpus
	./fuzz_wireguard -max_len=200 $(if $(SECS),-max_total_time=$(SECS)) corpus

repro: fuzz_wireguard
	./fuzz_wireguard $(CASE)

clean:
	rm -f fuzz_wireguard
	rm -rf corpus crash-* leak-* timeout-*

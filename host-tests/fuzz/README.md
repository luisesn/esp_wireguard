# Fuzzing the packet parser

A libFuzzer harness for `src/wireguard.c`'s incoming-message handling --
the last open item under Phase 3 in `CHANGES-fork.md` ("fuzzing of the
packet parser"). Native build, no ESP-IDF or hardware needed; needs
`clang` (libFuzzer ships inside clang's compiler-rt, not gcc).

## What's fuzzed

Four real, non-static entry points in `src/wireguard.c` that process
bytes coming straight off the wire, before any crypto validation has
happened:

- `wireguard_get_message_type()` -- the length/type dispatcher. This is
  the function `CHANGES-fork.md`'s Phase 3 review already went over by
  hand (issue review: "packet-parsing length bounds"); fuzzing gives that
  review an automated, ongoing check.
- `wireguard_process_initiation_message()` -- the full Noise handshake
  initiation parse + decrypt, run as a responder would against an
  attacker-controlled first message.
- `wireguard_process_handshake_response()` -- same, for the second
  handshake message, as an initiator would receive it.
- `wireguard_process_cookie_message()` -- the under-load cookie-reply
  decrypt path (see also the comment at `wireguard_is_under_load()` in
  `src/wireguard-platform.c` on why this path is otherwise never
  exercised by this fork's normal hardware testing).

### Why overlay onto valid templates, not pure random bytes

`fuzz_wireguard.c` builds one real two-party handshake at startup (two
in-process `wireguard_device`s playing both ends), using the library's
own `wireguard_create_*()` functions, giving it one *valid, correctly
authenticated* template message of each type. Each fuzz iteration copies
a template and overlays the fuzzer's raw input bytes on top of it, from
offset 0, rather than treating the raw input as the entire message.

A purely random buffer fails MAC1/AEAD authentication on essentially
every run, so a naive harness would spend nearly all its time bouncing
off the first authentication check and almost never reach the
interesting state-update logic behind it. Overlaying onto a valid
template still gives the fuzzer full control over every byte (it can
corrupt the authentication tag itself, if that's what finds a bug), but
the coverage-guided search starts from "this one is accepted" and mutates
from there, so it spends much more of its budget on the deeper code.

## What's *not* covered

- `src/wireguardif.c` -- the lwIP netif integration layer (`pbuf`,
  `udp_pcb`, `netif` handling, `wireguardif_network_rx()`'s dispatch, the
  MAC1/MAC2 checks in `wireguardif_check_initiation_message()` /
  `wireguardif_check_response_message()`). Fuzzing that would mean
  stubbing real lwIP `pbuf`/`udp_pcb` semantics, not just opaque
  pointers, which is a much bigger lift than stubbing the handful of
  opaque types `src/wireguard.c` needs (see `lwip_stub/`) -- out of scope
  here.
- Multi-packet/stateful sequences (replay windows across many packets,
  rekey timing, session teardown under adversarial timing). Each fuzz
  iteration is a single incoming message against otherwise-fixed state.
- `src/crypto/refc/*` in isolation -- covered by `../test_crypto.c`
  instead (known-answer tests against independent reference
  implementations, which fuzzing isn't a substitute for).

## The stub headers (`lwip_stub/`)

`src/wireguard.h` includes `lwip/netif.h`, `lwip/udp.h`, `lwip/ip_addr.h`
and `lwip/arch.h` for a handful of types it carries but never
dereferences in `src/wireguard.c` (`struct netif *`, `struct udp_pcb *`,
`ip_addr_t`, `u16_t`) -- see the comment in `lwip_stub/lwip/arch.h` for
the reasoning. `esp_log.h` and `esp_err.h` are stubbed the same way
(logging becomes a no-op; `esp_err_t` becomes `int`). `fuzz_platform.c`
replaces `src/wireguard-platform.c` (which needs real PSA Crypto /
esp-idf headers) with trivial, deterministic equivalents of its four
functions -- fine here since none of them are what's under test.

None of this is reusable for fuzzing `wireguardif.c`; see "What's not
covered" above.

## Usage

```sh
make fuzz             # build ./fuzz_wireguard
make run               # fuzz until Ctrl-C (or a crash), corpus/ is kept between runs
make run SECS=120      # fuzz for a bounded time instead (e.g. in CI)
make repro CASE=path   # re-run one saved crashing/leaking input directly
make clean
```

A clean 2-minute local run (`make run SECS=120`) reached ~20,600
executions with ASan+UBSan enabled and no crashes, at corpus-coverage
sizes around 1500 of this binary's ~4100 instrumented coverage points
(most of the uncovered remainder is the crypto primitives' internal
branches, already exercised more directly by `../test_crypto.c`). That's
a smoke-level result, not a guarantee -- run it longer (hours, not
minutes) before treating silence as a clean bill of health, and treat any
crash it finds as a real bug until proven otherwise (these are real
calls into the shipped parsing code, not a toy reimplementation).

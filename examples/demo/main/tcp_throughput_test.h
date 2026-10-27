#ifndef TCP_THROUGHPUT_TEST_H
#define TCP_THROUGHPUT_TEST_H

/* Starts the TCP throughput test task if CONFIG_EXAMPLE_TCP_TEST_ENABLE is
 * set (no-op otherwise). See Kconfig.projbuild ("TCP throughput test
 * (Phase 4)") for the available modes and CHANGES-fork.md's Phase 4 for
 * why this exists: MTU/MSS tuning and throughput measurement need a real
 * stream of TCP bytes over the tunnel, and this is a deliberately
 * protocol-agnostic way to produce one (a plain TCP listener or sender on
 * the peer -- `nc` is enough -- rather than something iperf-specific).
 *
 * Call this once the WireGuard peer is up; it runs in its own FreeRTOS
 * task and returns immediately.
 */
void tcp_throughput_test_start(void);

#endif

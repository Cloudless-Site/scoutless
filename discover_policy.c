#include "discover_policy.h"
#include "web_probe_internal.h"
int discovery_icmp_timeout_ms(void) { return 300; }
int discovery_udp_timeout_ms(void) { return 300; }
int discovery_multicast_timeout_ms(void) { return 650; }
int discovery_ssdp_timeout_ms(void) { return 1400; }

int discovery_tcp_liveness_ms(void) { return 300; }

int discovery_host_scan_timeout_ms(uint16_t connect_ms) {
  int dyn = connect_ms > 0 ? (int)connect_ms * 3 : 300;
  if (dyn < 260) dyn = 260;
  if (dyn > 1500) dyn = 1500;
  return dyn;
}
int scan_connect_timeout_ms(void) { return 2000; }
int web_probe_connect_timeout_ms(void) { return 350; }
int web_probe_io_timeout_ms(void) { return 3000; }
int web_probe_effective_io_timeout_ms(const web_probe_ctx_t *ctx) {
  int timeout_ms = web_probe_io_timeout_ms();
  if (!ctx) return timeout_ms;
  if (ctx->io_timeout_ms <= 0) return timeout_ms;
  if (timeout_ms <= 0) return ctx->io_timeout_ms;
  if (ctx->io_timeout_ms < timeout_ms) return ctx->io_timeout_ms;
  return timeout_ms;
}

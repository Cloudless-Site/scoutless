#pragma once
#include <stdint.h>
enum {
  DISCOVERY_DEFAULT_PACING_US = 10000u,
  DISCOVERY_SERVICE_BUDGET_MS = 120000,
  DISCOVERY_SERVICE_HOST_COST_MS = 100
};
int discovery_udp_timeout_ms(void);
int discovery_multicast_timeout_ms(void);
int discovery_ssdp_timeout_ms(void);
int discovery_icmp_timeout_ms(void);
int discovery_tcp_liveness_ms(void);
int discovery_host_scan_timeout_ms(uint16_t connect_ms);
int scan_connect_timeout_ms(void);

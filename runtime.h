#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
extern int g_debug;
extern int g_debug_services_all;
extern uint64_t g_discovery_started_ms;
extern char g_probe_public_domain[128];
extern uint32_t g_runtime_burst_override;
extern uint32_t g_runtime_epoll_override;
extern uint32_t g_runtime_pacing_override_us;
extern int g_tcp_liveness_disabled;
extern int g_icmp_liveness_disabled;
#ifdef __cplusplus
}
#endif

#pragma once
#include <stdint.h>
#include "plan.h"
void discovery_build_plan(PlanItem *tcp_flat, PlanItem **tcp_items, int *tcp_n, UdpPlanItem *udp_items, int *udp_n, PlanItem **ext_tcp, int ext_tcp_n, UdpPlanItem *ext_udp, int ext_udp_n);
uint64_t discovery_estimate_service_scan_time_ms(int alive_total, int tcp_n, int udp_n, uint32_t pacing_us);

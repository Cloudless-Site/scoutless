#pragma once
#include "scoutless.h"
#include "vendor.h"
#include "plan.h"
int run_discovery(Service *list, const RemotePorts *rp, PlanItem **ext_tcp, int ext_tcp_n, UdpPlanItem *ext_udp, int ext_udp_n, int force_large_net);

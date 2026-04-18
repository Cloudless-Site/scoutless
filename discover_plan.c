#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "scoutless.h"
#include "scan.h"
#include "probes.h"
#include "discover.h"
#include "discover_policy.h"
#include "discover_targets.h"
#include "discover_plan.h"
static void build_default_plan(PlanItem *tcp_plan_storage, PlanItem **tcp_items, int *tcp_n, UdpPlanItem *udp_items, int *udp_n) {
  int tn = 0;
  for (size_t i = 0; i < tcp_probes_len && tn < 512; i++) {
    tcp_plan_storage[tn] = (PlanItem){ .proto = IPPROTO_TCP, .port = (int)tcp_probes[i].port, .forced = SRV_TCP, .force_publish = 0, .is_vendor_probe = 0, .vp = NULL };
    tcp_items[tn] = &tcp_plan_storage[tn];
    tn++;
  }
  *tcp_n = tn;
  int un = 0;
  for (size_t i = 0; i < udp_probes_len && un < 512; i++) {
    udp_items[un++] = (UdpPlanItem){ .port = (int)udp_probes[i].port, .forced = SRV_UDP, .force_publish = 0, .is_vendor_probe = 0, .vp = NULL };
  }
  *udp_n = un;
}
void discovery_build_plan(PlanItem *tcp_flat, PlanItem **tcp_items, int *tcp_n, UdpPlanItem *udp_items, int *udp_n, PlanItem **ext_tcp, int ext_tcp_n, UdpPlanItem *ext_udp, int ext_udp_n) {
  if (!tcp_items || !tcp_n || !udp_items || !udp_n) return;
  int tcp_count = 0;
  if (ext_tcp && ext_tcp_n > 0) {
    tcp_count = ext_tcp_n;
    if (tcp_count > 512) tcp_count = 512;
    for (int i = 0; i < tcp_count; i++)
      tcp_items[i] = ext_tcp[i];
  }
  int udp_count = 0;
  if (ext_udp && ext_udp_n > 0) {
    udp_count = ext_udp_n;
    if (udp_count > 512) udp_count = 512;
    memcpy(udp_items, ext_udp, (size_t)udp_count * sizeof(UdpPlanItem));
  }
  if (tcp_count > 0 || udp_count > 0) {
    *tcp_n = tcp_count;
    *udp_n = udp_count;
    return;
  }
  build_default_plan(tcp_flat, tcp_items, tcp_n, udp_items, udp_n);
}

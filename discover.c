#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "scoutless.h"
#include "runtime.h"
#include "scan.h"
#include "discover.h"
#include "discover_plan.h"
#include "discover_hosts.h"
#include "discover_targets.h"
#include "discover_policy.h"
#include "util.h"
static void discovery_run_active_scans(const DiscoveryContext *ctx, DiscoveryTarget *targets, int n_targets, PlanItem **tcp_items, int tcp_n, UdpPlanItem *udp_items, int udp_n, const RemotePorts *rp, Service *list, int *out_n) {
  if (!ctx || !targets || !out_n) return;

  ScanTarget *candidates = calloc(MAX_SMART_TARGETS, sizeof(*candidates));
  if (!candidates) return;
  int alive_total = discovery_collect_scan_candidates(targets, n_targets, ctx->my_idx, candidates);
  if (alive_total <= 0) {
    free(candidates);
    return;
  }
  if (tcp_n > 0 && *out_n < (int)ctx->max_services) {
    int service_tcp_pacing_us;
    int service_tcp_max_inflight;
    uint64_t tcp_start = now_ms();
    service_tcp_pacing_us = (int)ctx->effective_pacing_us;
    if (service_tcp_pacing_us <= 0) service_tcp_pacing_us = (int)DISCOVERY_DEFAULT_PACING_US;

    if(!ctx->global_epoll_max) {
      service_tcp_max_inflight = ctx->effective_burst_max > 0 ? (int)(ctx->effective_burst_max / 8u) : 0;
      if (service_tcp_max_inflight < 8) service_tcp_max_inflight = 8;
      if (service_tcp_max_inflight > SCOUTLESS_EPOLL_SIZE) service_tcp_max_inflight = SCOUTLESS_EPOLL_SIZE;
   } else 
      service_tcp_max_inflight = ctx->global_epoll_max;

    scan_tcp_targets_paced_limited(candidates, alive_total, tcp_items, tcp_n, rp, list, out_n, service_tcp_pacing_us, service_tcp_max_inflight, (int)ctx->max_services);
    if (g_debug) fprintf(stderr, "*** TCP services: found=%d inflight=%d pacing=%d time=%u ***\n", *out_n, service_tcp_max_inflight, service_tcp_pacing_us, (unsigned)(now_ms() - tcp_start));
  }
  if (udp_n > 0 && *out_n < (int)ctx->max_services) {
    int udp_max_pending;
    uint64_t udp_start = now_ms();
    uint32_t before = (uint32_t)*out_n;
    udp_max_pending = ctx->effective_burst_max > 0 ? (int)ctx->effective_burst_max : 48;
    if (udp_max_pending < 16) udp_max_pending = 16;
    if (udp_max_pending > 4096) udp_max_pending = 4096;
    scan_udp_targets_paced_limited(candidates, alive_total, udp_items, udp_n, rp, list, out_n, (int)ctx->effective_pacing_us, udp_max_pending, (int)ctx->max_services);
    if (g_debug) fprintf(stderr, "*** UDP services: found=%u pending=%d pacing=%u time=%u ***\n", (unsigned)((uint32_t)*out_n - before), udp_max_pending, (unsigned)ctx->effective_pacing_us, (unsigned)(now_ms() - udp_start));
  }
  free(candidates);
}
int run_discovery(Service *list, const RemotePorts *rp, PlanItem **ext_tcp, int ext_tcp_n, UdpPlanItem *ext_udp, int ext_udp_n, int force_large_net) {
  if (!list) return 0;
  int out_n = 0;

  uint32_t *seeds = calloc(MAX_SMART_TARGETS, sizeof(*seeds));
  DiscoveryTarget *targets = calloc(MAX_SMART_TARGETS, sizeof(*targets));
  PlanItem *tcp_flat = calloc(512, sizeof(*tcp_flat));
  PlanItem **tcp_items = calloc(512, sizeof(*tcp_items));
  UdpPlanItem *udp_items = calloc(512, sizeof(*udp_items));
  if (!seeds || !targets || !tcp_flat || !tcp_items || !udp_items)  return 0;

  DiscoveryContext ctx;
  if (!discovery_init_context(&ctx, force_large_net)) goto cleanup;

  uint64_t start = now_ms();
  g_discovery_started_ms = start;
  ctx.global_burst_max = 128u;
  ctx.global_epoll_max = 64u;
  ctx.global_pacing_us = DISCOVERY_DEFAULT_PACING_US;
  if (g_runtime_pacing_override_us > 0) ctx.global_pacing_us = g_runtime_pacing_override_us;
  if (g_runtime_burst_override > 0) ctx.global_burst_max = g_runtime_burst_override;
  if (g_runtime_epoll_override > 0) ctx.global_epoll_max = g_runtime_epoll_override;
  ctx.effective_pacing_us = ctx.global_pacing_us;
  if (ctx.effective_pacing_us == 0) ctx.effective_pacing_us = DISCOVERY_DEFAULT_PACING_US;
  if (ctx.global_burst_max > 0) {
    ctx.effective_burst_max = (ctx.global_burst_max * 3u) / 4u;
    if (ctx.effective_burst_max < 16u) ctx.effective_burst_max = 16u;
    ctx.icmp_host_burst_max = (ctx.global_burst_max * 4u) / 5u;
    if (ctx.icmp_host_burst_max < 16u) ctx.icmp_host_burst_max = 16u;
    if (ctx.icmp_host_burst_max > ctx.global_burst_max) ctx.icmp_host_burst_max = ctx.global_burst_max;
  } else {
    ctx.global_burst_max = 128u;
    ctx.effective_burst_max = 96u;
    ctx.icmp_host_burst_max = 102u;
  }
  int n_seeds = discovery_collect_initial_seeds(&ctx, seeds, MAX_SMART_TARGETS);
  int n_targets = discovery_build_targets(&ctx, seeds, n_seeds, targets);
  if (!discovery_targets_validate(&ctx, targets, n_targets)) goto cleanup;

  discovery_run_host_discovery_loop(&ctx, targets, &n_targets);
  if (!discovery_targets_validate(&ctx, targets, n_targets)) goto cleanup;

  int tcp_n = 0; int udp_n = 0;
  discovery_build_plan(tcp_flat, tcp_items, &tcp_n, udp_items, &udp_n, ext_tcp, ext_tcp_n, ext_udp, ext_udp_n);

  discovery_run_active_scans(&ctx, targets, n_targets, tcp_items, tcp_n, udp_items, udp_n, rp, list, &out_n);
  if (g_debug)
    fprintf(stderr,"****** DISCOVERY statistics: target=%d host=%d services=%d pacing=%u time=%u ******\n", n_targets, discovery_count_alive(targets, n_targets), out_n, (unsigned)ctx.effective_pacing_us, debug_elapsed_total_ms());
cleanup:
  if(udp_items) free(udp_items);
  if(tcp_items) free(tcp_items);
  if(tcp_flat) free(tcp_flat);
  if(targets) free(targets);
  if(seeds) free(seeds);
  return out_n;
}

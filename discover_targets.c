#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "scoutless.h"
#include "runtime.h"
#include "discover.h"
#include "discover_net.h"
#include "discover_targets.h"
#include "discover_policy.h"
#include "util.h"
#include "util_net.h"
int discovery_target_has(const DiscoveryTarget *target, uint16_t flag) {
  return target && (target->flags & flag) != 0;
}
void discovery_target_set(DiscoveryTarget *target, uint16_t flag) {
  if (!target) return;
  target->flags |= flag;
}
static void discovery_target_clear(DiscoveryTarget *target, uint16_t flag) {
  if (!target) return;
  target->flags &= (uint16_t)~flag;
}
static int discovery_popcount32(uint32_t x) {
  int c = 0;
  while (x) {
    x &= x - 1;
    c++;
  }
  return c;
}
static void discovery_ip_from_host(char out[16], uint32_t net_base, uint32_t host_idx) {
  struct in_addr ia;
  const char *s;
  ia.s_addr = htonl(net_base + host_idx);
  s = inet_ntoa(ia);
  strncpy(out, s ? s : "0.0.0.0", 15);
  out[15] = 0;
}
static void discovery_target_init(DiscoveryTarget *target, uint32_t net_base, uint32_t host_idx) {
  if (!target) return;
  memset(target, 0, sizeof(*target));
  target->host_idx = host_idx;
  discovery_ip_from_host(target->ip, net_base, host_idx);
}
int discovery_target_add_unique(DiscoveryTarget *targets, int *n_targets, int max_targets, uint32_t net_base, uint32_t host_idx) {
  if (!targets || !n_targets || *n_targets < 0 || *n_targets >= max_targets) return 0;
  for (int i = 0; i < *n_targets; i++)
    if (targets[i].host_idx == host_idx) return 0;
  discovery_target_init(&targets[*n_targets], net_base, host_idx);
  (*n_targets)++;
  return 1;
}
static void discovery_log_new_host(const char *src, const DiscoveryTarget *target, int was_alive) {
  uint32_t elapsed;
  uint64_t now;
  if (!g_debug || !src || !target || was_alive) return;
  now = now_ms();
  if (target->timing_started_ms == 0 || now <= target->timing_started_ms) elapsed = 0;
  else if (now - target->timing_started_ms > 0xffffffffULL) elapsed = 0xffffffffU;
  else elapsed = (uint32_t)(now - target->timing_started_ms);
  if (target->connect_ms)
    fprintf(stderr, "[%s] %s time=%u\n", src, target->ip, (unsigned)target->connect_ms);
  else
    fprintf(stderr, "[%s] %s time=%u\n", src, target->ip, elapsed);
}
static void discovery_mark_target_alive(DiscoveryTarget *target, uint16_t from_flag, uint16_t connect_ms, const char *src) {
  int was_alive;
  if (!target) return;
  was_alive = discovery_target_has(target, DISCOVERY_TARGET_ALIVE);
  discovery_target_clear(target, DISCOVERY_TARGET_DEAD);
  discovery_target_set(target, DISCOVERY_TARGET_ALIVE | DISCOVERY_TARGET_DISCOVERED | DISCOVERY_TARGET_DONE | from_flag);
  if (connect_ms != 0 && (target->connect_ms == 0 || connect_ms < target->connect_ms))
    target->connect_ms = connect_ms;
  discovery_log_new_host(src, target, was_alive);
}
int discovery_count_alive(DiscoveryTarget *targets, int n_targets) {
  int n = 0;
  if (!targets) return 0;
  for (int i = 0; i < n_targets; i++)
    if (discovery_target_has(&targets[i], DISCOVERY_TARGET_ALIVE)) n++;
  return n;
}
static int discovery_find_target_by_ip(DiscoveryTarget *targets, int n_targets, const char *ip) {
  if (!targets || !ip || !*ip) return -1;
  for (int i = 0; i < n_targets; i++)
    if (strcmp(targets[i].ip, ip) == 0) return i;
  return -1;
}
static int discovery_find_target_by_addr(DiscoveryTarget *targets, int n_targets, uint32_t ip) {
  if (!targets || n_targets <= 0) return -1;
  for (int i = 0; i < n_targets; i++)
    if (targets[i].host_idx == ip) return i;
  return -1;
}
int discovery_try_add_target_from_ip(const DiscoveryContext *ctx, DiscoveryTarget *targets, int *n_targets, const struct in_addr *addr, uint16_t from_flag, const char *src) {
  uint32_t ip;
  uint32_t host_idx;
  int idx;
  int alive_count;
  if (!ctx || !targets || !n_targets || !addr) return -1;
  ip = ntohl(addr->s_addr);
  if (ip <= ctx->net_base) return -1;
  if (ip >= ctx->net_base + ctx->host_count) return -1;
  host_idx = ip - ctx->net_base;
  if (host_idx == 0 || host_idx >= ctx->host_count) return -1;
  idx = discovery_find_target_by_addr(targets, *n_targets, host_idx);
  if (idx >= 0 && discovery_target_has(&targets[idx], DISCOVERY_TARGET_ALIVE)) return idx;
  alive_count = discovery_count_alive(targets, *n_targets);
  if (alive_count >= (int)ctx->max_hosts) return -1;
  if (idx < 0) {
    if (*n_targets >= MAX_SMART_TARGETS) return -1;
    if (!discovery_target_add_unique(targets, n_targets, MAX_SMART_TARGETS, ctx->net_base, host_idx)) return -1;
    idx = *n_targets - 1;
  }
  if (from_flag == DISCOVERY_TARGET_FROM_PASSIVE && targets[idx].timing_started_ms == 0) targets[idx].timing_started_ms = (uint32_t)now_ms();
  discovery_mark_target_alive(&targets[idx], from_flag, 0, src);
  return idx;
}
int discovery_collect_pending_jobs(DiscoveryTarget *targets, int n_targets, ScanProbeJob *jobs) {
  int n = 0;
  if (!targets || !jobs) return 0;
  for (int i = 0; i < n_targets; i++) {
    if (discovery_target_has(&targets[i], DISCOVERY_TARGET_ALIVE)) continue;
    if (discovery_target_has(&targets[i], DISCOVERY_TARGET_DONE)) continue;
    jobs[n].timing_started_ms = &targets[i].timing_started_ms;
    jobs[n].alive = jobs[n].dead = jobs[n].connect_ms = 0;
    jobs[n].ip = targets[i].ip;
    n++;
  }
  return n;
}
void discovery_apply_probe_results(DiscoveryTarget *targets, int n_targets, const ScanProbeJob *jobs, int n_jobs, uint16_t from_flag) {
  const char *src = "unknown";
  if (!targets || !jobs) return;
  if (from_flag == DISCOVERY_TARGET_FROM_ICMP || from_flag == DISCOVERY_TARGET_FROM_UDP)
    src = "icmp";
  else if (from_flag == DISCOVERY_TARGET_FROM_TCP)
    src = "tcp";
  else if (from_flag == DISCOVERY_TARGET_FROM_PASSIVE)
    src = "multicast";
  for (int i = 0; i < n_jobs; i++) {
    int idx;
    int was_alive;
    idx = discovery_find_target_by_ip(targets, n_targets, jobs[i].ip);
    if (idx < 0) continue;
    was_alive = discovery_target_has(&targets[idx], DISCOVERY_TARGET_ALIVE);
    if (jobs[i].alive) {
      discovery_target_clear(&targets[idx], DISCOVERY_TARGET_DEAD);
      discovery_target_set(&targets[idx], DISCOVERY_TARGET_ALIVE | DISCOVERY_TARGET_DISCOVERED | DISCOVERY_TARGET_DONE | from_flag);
      if (jobs[i].connect_ms != 0 && (targets[idx].connect_ms == 0 || jobs[i].connect_ms < targets[idx].connect_ms))
        targets[idx].connect_ms = jobs[i].connect_ms;
      discovery_log_new_host(src, &targets[idx], was_alive);
      continue;
    }
    if (jobs[i].dead && !was_alive)
      discovery_target_set(&targets[idx], DISCOVERY_TARGET_DEAD | DISCOVERY_TARGET_DONE);
  }
}
static int discovery_target_should_scan(const DiscoveryTarget *target, uint32_t my_idx) {
  if (!target) return 0;
  if (target->host_idx == my_idx) return 0;
  if (discovery_target_has(target, DISCOVERY_TARGET_ALIVE)) return 1;
  return 0;
}
int discovery_collect_scan_candidates(DiscoveryTarget *targets, int n_targets, uint32_t my_idx, ScanTarget *candidates) {
  int n = 0;
  if (!targets || !candidates) return 0;
  for (int i = 0; i < n_targets; i++) {
    if (!discovery_target_should_scan(&targets[i], my_idx)) continue;
    candidates[n].ip = targets[i].ip;
    candidates[n].timeout_ms = discovery_host_scan_timeout_ms(targets[i].connect_ms);
    n++;
  }
  return n;
}
static int add_host_unique_u32(uint32_t *hosts, int *n, int cap, uint32_t host, uint32_t total_hosts) {
  if (!hosts || !n || *n < 0 || cap <= 0 || host >= total_hosts) return 0;
  for (int i = 0; i < *n; i++)
    if (hosts[i] == host) return 0;
  if (*n >= cap) return 0;
  hosts[*n] = host;
  (*n)++;
  return 1;
}
static void discovery_add_window_hosts(uint32_t *hosts, int *n_hosts, int max_hosts, uint32_t center, uint32_t total_hosts, int radius) {
  uint32_t start;
  uint32_t end;
  if (!hosts || !n_hosts || max_hosts <= 0 || total_hosts == 0 || radius < 0) return;
  if (center >= total_hosts) return;
  start = center > (uint32_t)radius ? center - (uint32_t)radius : 1;
  end = center + (uint32_t)radius;
  if (end >= total_hosts) end = total_hosts - 1;
  if (start == 0) start = 1;
  for (uint32_t host = start; host <= end; host++)
    (void)add_host_unique_u32(hosts, n_hosts, max_hosts, host, total_hosts);
}
int discovery_init_context(DiscoveryContext *ctx, int force_large_net) {
  struct in_addr ia;
  if (!ctx) return 0;
  memset(ctx, 0, sizeof(*ctx));
  ctx->force_large_net = force_large_net;
  ctx->max_hosts = DISCOVERY_MAX_HOSTS;
  ctx->max_services = DISCOVERY_MAX_SERVICES;
  ctx->gw_idx = UINT32_MAX;
  if (!get_local_network(ctx->iface, &ctx->ip, &ctx->netmask)) {
    if (g_debug) fprintf(stderr, "No network interface detected.\n");
    return 0;
  }
  ctx->net_base = ctx->ip & ctx->netmask;
  ctx->host_count = (~ctx->netmask) & 0xFFFFFFFFu;
  if (discovery_popcount32(ctx->netmask) >= 32) ctx->host_count = 1;
  else if (discovery_popcount32(ctx->netmask) == 31) ctx->host_count = 2;
  else if (ctx->host_count == 0) ctx->host_count = 255;
  ctx->my_idx = ctx->ip - ctx->net_base;
  ctx->gw = get_default_gateway();
  if (ctx->gw && ctx->gw >= ctx->net_base && ctx->gw < ctx->net_base + ctx->host_count)
    ctx->gw_idx = ctx->gw - ctx->net_base;
  ctx->dns = get_local_dns();
  ctx->scan_mode = ctx->host_count < DISCOVERY_SMALL_NET_THRESHOLD ? DISCOVERY_SCAN_MODE_FULL : DISCOVERY_SCAN_MODE_WINDOW;
  if (ctx->force_large_net) ctx->scan_mode = DISCOVERY_SCAN_MODE_WINDOW;
  ctx->global_pacing_us = 0;
  ctx->global_burst_max = 0;
  ctx->effective_pacing_us = 0;
  ctx->effective_burst_max = 0;
  ctx->icmp_host_burst_max = 0;
  if (g_debug) {
    ia.s_addr = htonl(ctx->ip);
    fprintf(stderr, "Start iface=%s ip=%s ", ctx->iface, inet_ntoa(ia));
    ia.s_addr = htonl(ctx->gw);
    fprintf(stderr, "router=%s mask_bits=%d total_hosts=%u scan_mode=%s force_large_net=%d\n", inet_ntoa(ia), discovery_popcount32(ctx->netmask), ctx->host_count,
            ctx->scan_mode == DISCOVERY_SCAN_MODE_FULL ? "full" : "window", ctx->force_large_net);
  }
  return 1;
}
int discovery_collect_initial_seeds(const DiscoveryContext *ctx, uint32_t *seeds, int max_seeds) {
  int n_seeds = 0;
  if (!ctx || !seeds || max_seeds <= 0) return 0;
  if (ctx->host_count <= 1) return 0;
  if (discovery_popcount32(ctx->netmask) == 31 && ctx->host_count == 2) {
    for (uint32_t host = 0; host < ctx->host_count && n_seeds < max_seeds; host++) {
      if (host == ctx->my_idx) continue;
      (void)add_host_unique_u32(seeds, &n_seeds, max_seeds, host, ctx->host_count);
    }
    return n_seeds;
  }
  if (ctx->scan_mode == DISCOVERY_SCAN_MODE_FULL) {
    for (uint32_t host = 1; host < ctx->host_count && n_seeds < max_seeds; host++)
      (void)add_host_unique_u32(seeds, &n_seeds, max_seeds, host, ctx->host_count);
    return n_seeds;
  }
  discovery_add_window_hosts(seeds, &n_seeds, max_seeds, ctx->my_idx, ctx->host_count, DISCOVERY_WINDOW_SEED);
  if (ctx->gw_idx < ctx->host_count)
    discovery_add_window_hosts(seeds, &n_seeds, max_seeds, ctx->gw_idx, ctx->host_count, DISCOVERY_WINDOW_SEED);
  return n_seeds;
}

int discovery_targets_validate(const DiscoveryContext *ctx, const DiscoveryTarget *targets, int n_targets) {
  uint32_t min_host_idx;
  if (!ctx || !targets || n_targets < 0 || n_targets > MAX_SMART_TARGETS) return 0;
  min_host_idx = 1;
  if (discovery_popcount32(ctx->netmask) == 31 && ctx->host_count == 2) min_host_idx = 0;
  for (int i = 0; i < n_targets; i++) {
    if (targets[i].host_idx < min_host_idx || targets[i].host_idx >= ctx->host_count) return 0;
    if (discovery_target_has(&targets[i], DISCOVERY_TARGET_ALIVE) && discovery_target_has(&targets[i], DISCOVERY_TARGET_DEAD)) return 0;
    for (int j = i + 1; j < n_targets; j++)
      if (targets[i].host_idx == targets[j].host_idx) return 0;
  }
  return 1;
}

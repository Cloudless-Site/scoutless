#pragma once
#include <netinet/in.h>
#include <stdint.h>
#include "scan.h"
typedef enum {
  DISCOVERY_TARGET_ALIVE = 1u << 0,
  DISCOVERY_TARGET_DEAD = 1u << 1,
  DISCOVERY_TARGET_DISCOVERED = 1u << 2,
  DISCOVERY_TARGET_FROM_PASSIVE = 1u << 3,
  DISCOVERY_TARGET_FROM_ICMP = 1u << 4,
  DISCOVERY_TARGET_FROM_UDP  = 1u << 5,
  DISCOVERY_TARGET_FROM_TCP = 1u << 6,
  DISCOVERY_TARGET_DONE = 1u << 7,
  DISCOVERY_TARGET_EXPANDED = 1u << 8
} DiscoveryTargetFlag;
typedef struct {
  uint32_t host_idx;
  uint16_t flags;
  uint16_t connect_ms;
  uint32_t timing_started_ms;
  char ip[16];
} DiscoveryTarget;
typedef enum {
  DISCOVERY_SCAN_MODE_FULL = 0,
  DISCOVERY_SCAN_MODE_WINDOW = 1
} DiscoveryScanMode;
typedef struct {
  uint32_t ip;
  uint32_t netmask;
  uint32_t net_base;
  uint32_t host_count;
  uint32_t my_idx;
  uint32_t gw;
  uint32_t gw_idx;
  uint32_t dns;
  uint32_t max_hosts;
  uint32_t max_services;
  uint32_t global_pacing_us;
  uint32_t global_burst_max;
  uint32_t global_epoll_max;
  uint32_t effective_pacing_us;
  uint32_t effective_burst_max;
  uint32_t icmp_host_burst_max;
  DiscoveryScanMode scan_mode;
  int force_large_net;
  char iface[64];
} DiscoveryContext;
int discovery_target_has(const DiscoveryTarget *target, uint16_t flag);
void discovery_target_set(DiscoveryTarget *target, uint16_t flag);
int discovery_target_add_unique(DiscoveryTarget *targets, int *n_targets, int max_targets, uint32_t net_base, uint32_t host_idx);
int discovery_count_alive(DiscoveryTarget *targets, int n_targets);
int discovery_try_add_target_from_ip(const DiscoveryContext *ctx, DiscoveryTarget *targets, int *n_targets, const struct in_addr *addr, uint16_t from_flag, const char *src);
int discovery_collect_pending_jobs(DiscoveryTarget *targets, int n_targets, ScanProbeJob *jobs);
void discovery_apply_probe_results(DiscoveryTarget *targets, int n_targets, const ScanProbeJob *jobs, int n_jobs, uint16_t from_flag);
int discovery_collect_scan_candidates(DiscoveryTarget *targets, int n_targets, uint32_t my_idx, ScanTarget *candidates);
int discovery_init_context(DiscoveryContext *ctx, int force_large_net);
int discovery_collect_initial_seeds(const DiscoveryContext *ctx, uint32_t *seeds, int max_seeds);
int discovery_targets_validate(const DiscoveryContext *ctx, const DiscoveryTarget *targets, int n_targets);

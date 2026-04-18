#pragma once
#include <stddef.h>
#include <stdint.h>
#include "discover_targets.h"
#include "scan.h"
#define DISCOVERY_DRAIN_BUDGET 128
typedef struct {
  int s;
  int port;
  const char *tag;
  const char *dst_ip;
  const void *payload;
  size_t payload_len;
  int timeout_ms;
  int is_broadcast;
} DiscoveryPassiveProbe;
int discovery_run_initial_multicast_icmp_step(const DiscoveryContext *ctx, DiscoveryTarget *targets, int *n_targets);
uint64_t discovery_probe_earliest_deadline(const DiscoveryPassiveProbe *probes, const uint64_t *deadlines, int n_probes);
void discovery_close_expired_passive(int ep, DiscoveryPassiveProbe *probes, const uint64_t *deadlines, int n_probes, uint64_t now);
void discovery_drain_passive_probe_events(const DiscoveryContext *ctx, DiscoveryTarget *targets, int *n_targets, DiscoveryPassiveProbe *probes, int n_probes, int tag);
void discovery_close_fd_from_epoll(int ep, int *fd);
int discovery_run_icmp_probe_loop(const DiscoveryContext *ctx, DiscoveryTarget *targets, int *n_targets, ScanProbeJob *jobs, int pending, int ep, int icmp_sock, int uses_dgram, DiscoveryPassiveProbe *probes, uint64_t *probe_deadlines, int n_probes);
int discovery_icmp_open_socket(int *uses_dgram);

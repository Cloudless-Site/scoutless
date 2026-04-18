#pragma once
#define SCOUTLESS_EPOLL_SIZE 64
#include <stdint.h>
#include "scoutless.h"
#include "vendor.h"
#include "plan.h"
typedef struct {
  const char *ip;
  uint8_t alive;
  uint8_t dead;
  uint16_t connect_ms;
  uint32_t *timing_started_ms;
} ScanProbeJob;
typedef struct {
  const char *ip;
  int timeout_ms;
} ScanTarget;
int tcp_liveness_sweep_jobs_epoll(ScanProbeJob *jobs, int n_jobs, int timeout_ms, int max_window);
int tcp_liveness_sweep_jobs_epoll_paced(ScanProbeJob *jobs, int n_jobs, int timeout_ms, int max_window, int pacing_us); int tcp_connect_single_nb(const char *ip_str, int port, int *immediate_ok);
void scan_udp_targets_paced_limited(const ScanTarget *targets, int n_targets, const UdpPlanItem *udp_items, int udp_n, const RemotePorts *rp, Service *list, int *out_n, int pacing_us, int max_pending, int max_services);
void scan_tcp_targets_paced_limited(const ScanTarget *targets, int n_targets, PlanItem **tcp_items, int tcp_n, const RemotePorts *rp, Service *list, int *out_n, int pacing_us, int max_inflight, int max_services);
int icmp_open_socket(int *uses_dgram);
enum {
  TCP_LIVENESS_RESULT_FAIL = -1,
  TCP_LIVENESS_RESULT_PENDING = 0,
  TCP_LIVENESS_RESULT_ALIVE = 1,
  TCP_LIVENESS_RESULT_HARD_UNREACH = -2,
  TCP_LIVENESS_RESULT_RESOURCE = -3
};
typedef struct {
  int fd;
  int port;
  int phase;
  uint8_t hard80;
  uint8_t finished;
  uint8_t epoll_registered;
  uint64_t started_ms;
  uint64_t decision_started_ms;
  uint64_t deadline_ms;
} tcp_liveness_slot_t;

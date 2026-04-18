#include "scoutless.h"
#include "runtime.h"
#include "scan.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/ip_icmp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include "probes.h"
#include "util.h"
#include "discover.h"
#include "discover_net.h"
#include "discover_policy.h"
#include "discover_targets.h"
#include "discover_hosts.h"
#include "discover_hosts_internal.h"

static int discovery_effective_burst_cap(const DiscoveryContext *ctx) {
  if (!ctx) return 64;
  int cap = ctx->icmp_host_burst_max > 0 ? (int)ctx->icmp_host_burst_max : 64;
  if (cap < 16) cap = 16;
  return cap;
}
static uint16_t discovery_icmp_checksum(const void *buf, size_t len) {
  const uint8_t *p = (const uint8_t *)buf;
  uint32_t sum = 0;
  while (len > 1) {
    sum += (uint32_t)((p[0] << 8) | p[1]);
    p += 2; len -= 2;
  }
  if (len > 0) sum += (uint32_t)(p[0] << 8);
  while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
  return (uint16_t)(~sum & 0xFFFFu);
}
int discovery_icmp_open_socket(int *uses_dgram) {
    if (uses_dgram) *uses_dgram = 0;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock >= 0) return sock;
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (sock < 0) return -1;
    if (uses_dgram) *uses_dgram = 1;
    return sock;
}
static int discovery_wait_ms_until(uint64_t now, uint64_t deadline) {
  if (deadline == 0) return -1;
  if (deadline <= now) return 0;
  if (deadline - now > (uint64_t)INT32_MAX) return INT32_MAX;
  return (int)(deadline - now);
}
static int discovery_wait_ms_clamped(uint64_t now, uint64_t deadline) {
  int wait_ms = discovery_wait_ms_until(now, deadline);
  if (wait_ms == 0 && deadline > now) return 1;
  return wait_ms;
}
static int discovery_find_pending_job_by_ip(const ScanProbeJob *jobs, const uint32_t *sent_at_ms, const unsigned char *settled, int pending, const char *ip) {
  if (!jobs || !sent_at_ms || !settled || pending <= 0 || !ip || !*ip) return -1;
  for (int i = 0; i < pending; i++) {
    if (settled[i] || sent_at_ms[i] == 0) continue;
    if (strcmp(jobs[i].ip, ip) == 0) return i;
  }
  return -1;
}
static int discovery_refresh_icmp_inflight(const ScanProbeJob *jobs, const uint32_t *sent_at_ms, unsigned char *settled, int pending, uint64_t now, int timeout_ms) {
  if (!sent_at_ms || !settled || pending <= 0) return 0;
  int inflight = 0;
  for (int i = 0; i < pending; i++) {
    if (settled[i] || sent_at_ms[i] == 0) continue;
    if (now >= (uint64_t)sent_at_ms[i] + (uint64_t)timeout_ms) {
      if (jobs && jobs[i].ip[0]) dbg_host_trace("timeout", "icmp", jobs[i].ip, "timeout_ms=%d", timeout_ms);
      settled[i] = 1;
      continue;
    }
    inflight++;
  }
  return inflight;
}

static uint64_t discovery_next_icmp_timeout_deadline(const uint32_t *sent_at_ms, const unsigned char *settled, int pending, int timeout_ms) {
  if (!sent_at_ms || !settled || pending <= 0) return 0;
  uint64_t deadline = 0;
  for (int i = 0; i < pending; i++) {
    if (settled[i] || sent_at_ms[i] == 0) continue;
    uint64_t cur = (uint64_t)sent_at_ms[i] + (uint64_t)timeout_ms;
    if (deadline == 0 || cur < deadline) deadline = cur;
  }
  return deadline;
}
static int discovery_try_send_icmp_job(const DiscoveryContext *ctx, const ScanProbeJob *job, uint64_t now, int icmp_sock, int uses_dgram, uint16_t ident, int seq, int timeout_ms, uint32_t *sent_at_ms, unsigned char *settled) {
  if (!ctx || !job || !sent_at_ms || !settled) return 0;
  struct sockaddr_in sa = { .sin_family = AF_INET };
  if (inet_pton(AF_INET, job->ip, &sa.sin_addr) != 1) {
    *settled = 1;
    return 1;
  }
  unsigned char pkt[64];
  memset(pkt, 0, sizeof(pkt));
  struct icmphdr *icmp = (struct icmphdr *)pkt;
  icmp->code = icmp->checksum = 0;
  icmp->type = ICMP_ECHO;
  icmp->un.echo.id = htons(ident);
  icmp->un.echo.sequence = htons((uint16_t)seq);
  memcpy(pkt + sizeof(struct icmphdr), "scoutless", 9);

  if (!uses_dgram) icmp->checksum = htons(discovery_icmp_checksum(pkt, sizeof(struct icmphdr) + 9));
  if (job->timing_started_ms && *job->timing_started_ms == 0) *job->timing_started_ms = (uint32_t)now;
  dbg_host_trace("send", "icmp", job->ip, "timeout_ms=%d", timeout_ms);
  if (sendto(icmp_sock, pkt, sizeof(struct icmphdr) + 9, 0, (struct sockaddr *)&sa, sizeof(sa)) >= 0) *sent_at_ms = (uint32_t)now;
  else {
    dbg_host_trace("send-fail", "icmp", job->ip, "errno=%d", errno);
    *settled = 1;
  }
  return 1;
}
static int discovery_compute_icmp_wait_ms(int next_job, int pending, uint64_t now, uint64_t next_send_at, int inflight, const uint32_t *sent_at_ms, const unsigned char *settled, int timeout_ms, const DiscoveryPassiveProbe *probes, const uint64_t *probe_deadlines, int n_probes, uint64_t *passive_deadline_out) {
  int wait_ms = -1;
  if (next_job < pending) wait_ms = discovery_wait_ms_clamped(now, next_send_at);
  uint64_t inflight_deadline = discovery_next_icmp_timeout_deadline(sent_at_ms, settled, pending, timeout_ms);
  if (inflight_deadline != 0) {
    int inflight_wait_ms;
    inflight_wait_ms = discovery_wait_ms_until(now, inflight_deadline);
    if (wait_ms < 0 || inflight_wait_ms < wait_ms) wait_ms = inflight_wait_ms;
  }
  uint64_t passive_deadline = discovery_probe_earliest_deadline(probes, probe_deadlines, n_probes);
  if (passive_deadline != 0) {
    int passive_wait_ms;
    passive_wait_ms = discovery_wait_ms_until(now, passive_deadline);
    if (wait_ms < 0 || passive_wait_ms < wait_ms) wait_ms = passive_wait_ms;
  }
  if (wait_ms < 0) wait_ms = 0;
  if (passive_deadline_out) *passive_deadline_out = passive_deadline;
  if (next_job >= pending && inflight <= 0 && passive_deadline == 0) return -2;
  return wait_ms;
}
static void discovery_drain_icmp_events(const DiscoveryContext *ctx, DiscoveryTarget *targets, int *n_targets, ScanProbeJob *jobs, const uint32_t *sent_at_ms, unsigned char *settled, int pending, int icmp_sock, int uses_dgram) {
  int drain_budget = DISCOVERY_DRAIN_BUDGET;
  while (drain_budget-- > 0) {
    unsigned char buf[2048];
    struct sockaddr_in src;
    socklen_t slen = sizeof(src);
    ssize_t rd = recvfrom(icmp_sock, buf, sizeof(buf), 0, (struct sockaddr *)&src, &slen);
    if (rd < 0) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) break;
      break;
    }
    if (rd == 0) continue;
    char ipbuf[16];
    if (!inet_ntop(AF_INET, &src.sin_addr, ipbuf, sizeof(ipbuf))) ipbuf[0] = 0;
    if (ipbuf[0]) dbg_host_trace("reply", "icmp", ipbuf, "rd=%d", (int)rd);
    int idx = discovery_find_pending_job_by_ip(jobs, sent_at_ms, settled, pending, ipbuf);
    if (idx >= 0) {
      jobs[idx].alive = settled[idx] = 1;
      jobs[idx].dead = 0;
    }
    (void)discovery_try_add_target_from_ip(ctx, targets, n_targets, &src.sin_addr, uses_dgram ? DISCOVERY_TARGET_FROM_UDP : DISCOVERY_TARGET_FROM_ICMP, "icmp");
  }
}
static void discovery_handle_icmp_epoll_events(const DiscoveryContext *ctx, DiscoveryTarget *targets, int *n_targets, ScanProbeJob *jobs, const uint32_t *sent_at_ms, unsigned char *settled, int pending, int icmp_sock, int uses_dgram, DiscoveryPassiveProbe *probes, const uint64_t *probe_deadlines, int n_probes, const struct epoll_event *events, int n_events) {
  if (!ctx || !targets || !n_targets || !events || n_events <= 0) return;
  for (int i = 0; i < n_events; i++) {
    if (events[i].data.u32 == 100) {
      if (icmp_sock >= 0 && jobs && sent_at_ms && settled) discovery_drain_icmp_events(ctx, targets, n_targets, jobs, sent_at_ms, settled, pending, icmp_sock, uses_dgram);
      continue;
    }
    if (probes && probe_deadlines && events[i].data.u32 < (uint32_t)n_probes) discovery_drain_passive_probe_events(ctx, targets, n_targets, probes, n_probes, (int)events[i].data.u32);
  }
}
int discovery_run_icmp_probe_loop(const DiscoveryContext *ctx, DiscoveryTarget *targets, int *n_targets, ScanProbeJob *jobs, int pending, int ep, int icmp_sock, int uses_dgram, DiscoveryPassiveProbe *probes, uint64_t *probe_deadlines, int n_probes) {
  if (!ctx || !targets || !n_targets || ep < 0) return discovery_count_alive(targets, *n_targets);
  uint32_t *sent_at_ms = NULL;
  unsigned char *settled = NULL;
  if (pending > 0 && jobs && icmp_sock >= 0) {
    sent_at_ms = calloc((size_t)pending, sizeof(*sent_at_ms));
    if (!sent_at_ms) return discovery_count_alive(targets, *n_targets);
    settled = calloc((size_t)pending, sizeof(*settled));
    if (!settled) {
      free(sent_at_ms);
      return discovery_count_alive(targets, *n_targets);
    }
  }
  uint16_t ident = (uint16_t)(((uint32_t)getpid() ^ (uint32_t)now_ms()) & 0xFFFFu);
  int max_outstanding = discovery_effective_burst_cap(ctx);
  int timeout_ms = discovery_icmp_timeout_ms();
  uint64_t next_send_at = now_ms();
  int next_job = 0;
  for (;;) {
    uint64_t now = now_ms();
    int inflight = discovery_refresh_icmp_inflight(jobs, sent_at_ms, settled, pending, now, timeout_ms);
    if (icmp_sock >= 0 && sent_at_ms && settled && next_job < pending && now >= next_send_at && inflight < max_outstanding) {
      (void)discovery_try_send_icmp_job(ctx, &jobs[next_job], now, icmp_sock, uses_dgram, ident, next_job + 1, timeout_ms, &sent_at_ms[next_job], &settled[next_job]);
      next_send_at = now + (uint64_t)((ctx->effective_pacing_us + 999u) / 1000u);
      next_job++;
      continue;
    }
    now = now_ms();
    uint64_t passive_deadline;
    inflight = discovery_refresh_icmp_inflight(jobs, sent_at_ms, settled, pending, now, timeout_ms);
    if (icmp_sock < 0 || (next_job >= pending && inflight <= 0)) {
      passive_deadline = discovery_probe_earliest_deadline(probes, probe_deadlines, n_probes);
      if (passive_deadline == 0 || now >= passive_deadline) break;
    }
    int wait_ms;
    if(icmp_sock >= 0) {
    	wait_ms = discovery_compute_icmp_wait_ms(next_job, pending, now, next_send_at, inflight, sent_at_ms, settled, timeout_ms, probes, probe_deadlines, n_probes, &passive_deadline);;
        if (wait_ms == -2) break;
    } else
        wait_ms = (int)(passive_deadline-now);

    struct epoll_event events[8];
    int k = epoll_wait(ep, events, 8, wait_ms);
    now = now_ms();
    discovery_close_expired_passive(ep, probes, probe_deadlines, n_probes, now);
    if (k < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (k > 0) discovery_handle_icmp_epoll_events(ctx, targets, n_targets, jobs, sent_at_ms, settled, pending, icmp_sock, uses_dgram, probes, probe_deadlines, n_probes, events, k);
  }
  free(settled);
  free(sent_at_ms);
  return discovery_count_alive(targets, *n_targets);
}
static void discovery_mark_pending_dead(DiscoveryTarget *targets, int n_targets) {
  if (!targets) return;
  for (int i = 0; i < n_targets; i++) {
    if (discovery_target_has(&targets[i], DISCOVERY_TARGET_ALIVE)) continue;
    if (discovery_target_has(&targets[i], DISCOVERY_TARGET_DONE)) continue;
    discovery_target_set(&targets[i], DISCOVERY_TARGET_DEAD | DISCOVERY_TARGET_DONE);
  }
}
static void discovery_run_tcp_liveness_step(const DiscoveryContext *ctx, DiscoveryTarget *targets, int n_targets) {
  if (!ctx || !targets || n_targets <= 0) return;
  ScanProbeJob *jobs = calloc(MAX_SMART_TARGETS, sizeof(*jobs));
  if (!jobs) return;
  int pending = discovery_collect_pending_jobs(targets, n_targets, jobs);
  if (pending <= 0) {
    discovery_mark_pending_dead(targets, n_targets);
    free(jobs);
    return;
  }
  uint64_t phase_started_ms = now_ms();
  int alive_before = discovery_count_alive(targets, n_targets);
  int window = SCOUTLESS_EPOLL_SIZE;
  if(ctx->global_epoll_max) window = ctx->global_epoll_max;
     
  (void)tcp_liveness_sweep_jobs_epoll_paced(jobs, pending, discovery_tcp_liveness_ms(), window, (int)ctx->effective_pacing_us);
  discovery_apply_probe_results(targets, n_targets, jobs, pending, DISCOVERY_TARGET_FROM_TCP);
  discovery_mark_pending_dead(targets, n_targets);
  int alive_after = discovery_count_alive(targets, n_targets);
  if (g_debug) fprintf(stderr, "*** TCP liveness: hosts=%d time=%u epoll=%u ***\n", alive_after - alive_before,(unsigned)(now_ms() - phase_started_ms),window);
  free(jobs);
}
int discovery_build_targets(const DiscoveryContext *ctx, const uint32_t *seeds, int n_seeds, DiscoveryTarget *targets) {
  int n_targets = 0;
  if (!ctx || !seeds || !targets) return 0;
  for (int i = 0; i < n_seeds; i++)
    (void)discovery_target_add_unique(targets, &n_targets, MAX_SMART_TARGETS, ctx->net_base, seeds[i]);
  return n_targets;
}
static int discovery_run_icmp_only_step(const DiscoveryContext *ctx, DiscoveryTarget *targets, int *n_targets) {
  if (!ctx || !targets || !n_targets || *n_targets <= 0) return 0;

  ScanProbeJob *jobs = calloc(MAX_SMART_TARGETS, sizeof(*jobs));
  if (!jobs) return discovery_count_alive(targets, *n_targets);
  int pending = discovery_collect_pending_jobs(targets, *n_targets, jobs);
  int alive = discovery_count_alive(targets, *n_targets);

  int ep = -1;
  int icmp_sock = -1;
  if (pending > 0) {
    ep = epoll_create1(0);
    if (ep >= 0) {
      int uses_dgram = 0;
      icmp_sock = discovery_icmp_open_socket(&uses_dgram);
      if (icmp_sock >= 0) {
        struct epoll_event ev;
        (void)set_nonblock_fd(icmp_sock);
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
        ev.data.u32 = 100;
        if (epoll_ctl(ep, EPOLL_CTL_ADD, icmp_sock, &ev) == 0) {
          alive = discovery_run_icmp_probe_loop(ctx, targets, n_targets, jobs, pending, ep, icmp_sock, uses_dgram, NULL, NULL, 0);
        }
      }
    }
  }
  if (icmp_sock >= 0) discovery_close_fd_from_epoll(ep, &icmp_sock);
  if (ep >= 0) close(ep);
  free(jobs);
  return alive;
}
static int discovery_expand_windows_from_new_alive(const DiscoveryContext *ctx, DiscoveryTarget *targets, int *n_targets) {
  if (!ctx || !targets || !n_targets || *n_targets <= 0) return 0;

  int added = 0;
  for (int i = 0; i < *n_targets; i++) {
    if (!discovery_target_has(&targets[i], DISCOVERY_TARGET_ALIVE)) continue;
    if (discovery_target_has(&targets[i], DISCOVERY_TARGET_EXPANDED)) continue;
    if (ctx->scan_mode == DISCOVERY_SCAN_MODE_WINDOW) {
      uint32_t center = targets[i].host_idx;
      uint32_t start = center > DISCOVERY_WINDOW_EXPAND ? center - DISCOVERY_WINDOW_EXPAND : 1;
      uint32_t end = center + DISCOVERY_WINDOW_EXPAND;
      if (end >= ctx->host_count) end = ctx->host_count - 1;
      if (start == 0) start = 1;
      for (uint32_t host = start; host <= end; host++)
        added += discovery_target_add_unique(targets, n_targets, MAX_SMART_TARGETS, ctx->net_base, host);
    }
    discovery_target_set(&targets[i], DISCOVERY_TARGET_EXPANDED);
  }
  return added;
}
static int discovery_run_initial_host_liveness_step(const DiscoveryContext *ctx, DiscoveryTarget *targets, int *n_targets) {
  if (!ctx || !targets || !n_targets || *n_targets <= 0) return 0;
  int alive_after_sweep;
  int alive_before_sweep = discovery_count_alive(targets, *n_targets);
  if (!g_icmp_liveness_disabled) {
    uint64_t phase_started_ms = now_ms();
    (void)discovery_run_initial_multicast_icmp_step(ctx, targets, n_targets);
    alive_after_sweep = discovery_count_alive(targets, *n_targets);
    if (g_debug) fprintf(stderr, "*** ICMP liveness: hosts=%d time=%u ***\n", alive_after_sweep - alive_before_sweep, (unsigned)(now_ms() - phase_started_ms));
  }
  else alive_after_sweep = discovery_count_alive(targets, *n_targets);
  return alive_after_sweep;
}
static int discovery_run_expansion_icmp_step(const DiscoveryContext *ctx, DiscoveryTarget *targets, int *n_targets) {
  if (!ctx || !targets || !n_targets || *n_targets <= 0) return 0;
  int alive_before_sweep = discovery_count_alive(targets, *n_targets);
  uint64_t phase_started_ms = now_ms();
  (void)discovery_run_icmp_only_step(ctx, targets, n_targets);
  int alive_after_sweep = discovery_count_alive(targets, *n_targets);
  if (g_debug) fprintf(stderr, "*** ICMP: hosts=%d time=%u ***\n", alive_after_sweep - alive_before_sweep, (unsigned)(now_ms() - phase_started_ms));
  return alive_after_sweep;
}
void discovery_run_host_discovery_loop(const DiscoveryContext *ctx, DiscoveryTarget *targets, int *n_targets) {
  if (!ctx || !targets || !n_targets || *n_targets <= 0) return;
  int alive_after_sweep = discovery_run_initial_host_liveness_step(ctx, targets, n_targets);
  if (!g_tcp_liveness_disabled && alive_after_sweep < (int)ctx->max_hosts) discovery_run_tcp_liveness_step(ctx, targets, *n_targets);
  else {
    discovery_mark_pending_dead(targets, *n_targets);
    return;
  }
  for (;;) {
    if (discovery_count_alive(targets, *n_targets) >= (int)ctx->max_hosts) break;
    int added = discovery_expand_windows_from_new_alive(ctx, targets, n_targets);
    if (added <= 0) break;
    alive_after_sweep = discovery_run_expansion_icmp_step(ctx, targets, n_targets);
    if (alive_after_sweep < (int)ctx->max_hosts) discovery_run_tcp_liveness_step(ctx, targets, *n_targets);
    else {
      discovery_mark_pending_dead(targets, *n_targets);
      break;
    }
  }
}

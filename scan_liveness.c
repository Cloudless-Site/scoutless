#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#include "scoutless.h"
#include "probes.h"
#include "util.h"
#include "scan.h"
#include "discover_policy.h"
#include "scan_internal.h"
#include "scan_tcp_internal.h"

static uint16_t clamp_elapsed_ms(uint64_t started_ms) {
  uint64_t dt = now_ms() - started_ms;
  if (dt == 0) dt = 1;
  if (dt > 65535) dt = 65535;
  return (uint16_t)dt;
}
static int tcp_scan_pacing_wait_ms(uint64_t next_launch_ms) {
  if (next_launch_ms == 0) return 0;
  uint64_t now = now_ms();
  if (now >= next_launch_ms) return 0;
  uint64_t delta = next_launch_ms - now;
  if (delta == 0) return 0;
  if (delta > (uint64_t)INT_MAX) return INT_MAX;
  return (int)delta;
}
static void tcp_liveness_slot_reset(tcp_liveness_slot_t *slot) {
  if (!slot) return;
  slot->port = slot->phase = slot->hard80 = slot->finished = slot->epoll_registered = slot->started_ms = slot->decision_started_ms = slot->deadline_ms = 0;
  slot->fd = -1;
}
static void tcp_epoll_del_ignore(int ep, int fd) {
  if (ep < 0 || fd < 0) return;
  if (epoll_ctl(ep, EPOLL_CTL_DEL, fd, NULL) == 0) return;
  if (errno == ENOENT || errno == EBADF) return;
}
static void tcp_liveness_slot_close(int ep, tcp_liveness_slot_t *slot) {
  if (!slot || slot->fd < 0) return;
  if (slot->epoll_registered) tcp_epoll_del_ignore(ep, slot->fd);
  hard_close(slot->fd);
  slot->epoll_registered = 0;
  slot->fd = -1;
}
static void tcp_liveness_mark_alive(ScanProbeJob *job, tcp_liveness_slot_t *slot) {
  if (!job || !slot) return;
  SCOUT_ASSERT(!job->dead);
  job->alive = 1;
  job->dead = 0;
  job->connect_ms = clamp_elapsed_ms(slot->decision_started_ms ? slot->decision_started_ms : slot->started_ms);
  dbg_service_trace("alive", job->ip, slot->port, IPPROTO_TCP, "connect_ms=%u", job->connect_ms);
  slot->finished = 1;
  slot->phase = 3;
}
static void tcp_liveness_mark_dead(ScanProbeJob *job, tcp_liveness_slot_t *slot) {
  if (!job || !slot) return;
  SCOUT_ASSERT(!job->alive);
  job->dead = 1;
  job->alive = 0;
  dbg_service_trace("dead", job->ip, slot->port, IPPROTO_TCP, "phase=%d hard80=%d", slot->phase, slot->hard80);
  slot->finished = 1;
  slot->phase = 3;
}
static void tcp_liveness_complete_target(int *active_targets) {
  if (!active_targets) return;
  if (*active_targets <= 0) return;
  (*active_targets)--;
}
static int tcp_liveness_slot_pending(const tcp_liveness_slot_t *slot) {
  if (!slot) return 0;
  return !slot->finished && slot->fd >= 0;
}
static int tcp_liveness_slot_remaining_ms(const tcp_liveness_slot_t *slot, int timeout_ms, uint64_t now_ms) {
  int left;
  if (!slot || slot->finished || timeout_ms <= 0) return 0;
  if (slot->deadline_ms > 0) {
    if (now_ms >= slot->deadline_ms) return 0;
    left = (int)(slot->deadline_ms - now_ms);
  } else {
    left = timeout_ms - (int)(now_ms - slot->started_ms);
  }
  if (left < 0) left = 0;
  return left;
}
static int tcp_liveness_launch_one(int ep, ScanProbeJob *job, const char *ip, int idx, int port, tcp_liveness_slot_t *slot, int timeout_ms);
static int tcp_liveness_try_port(int ep, ScanProbeJob *job, int idx, tcp_liveness_slot_t *slot, int port) {
  if (!job || !slot) return TCP_LIVENESS_RESULT_FAIL;
  dbg_service_trace("connect-start", job->ip, port, IPPROTO_TCP, "timeout_ms=%d", discovery_tcp_liveness_ms());
  int rc = tcp_liveness_launch_one(ep, job, job->ip, idx, port, slot, discovery_tcp_liveness_ms());
  if (rc > 0) {
    tcp_liveness_mark_alive(job, slot);
    return TCP_LIVENESS_RESULT_ALIVE;
  }
  if (rc == TCP_LIVENESS_RESULT_HARD_UNREACH) {
    if (port == 80) slot->hard80 = 1;
    return TCP_LIVENESS_RESULT_HARD_UNREACH;
  }
  if (rc == TCP_LIVENESS_RESULT_PENDING) return TCP_LIVENESS_RESULT_PENDING;
  slot->phase = 3;
  return TCP_LIVENESS_RESULT_FAIL;
}
static int tcp_liveness_start_443(int ep, ScanProbeJob *job, int idx, tcp_liveness_slot_t *slot) {
  if (!job || !slot) return TCP_LIVENESS_RESULT_FAIL;
  slot->phase = 2;
  dbg_service_trace("fallback-443", job->ip, 443, IPPROTO_TCP, "after_port=80");
  int rc = tcp_liveness_try_port(ep, job, idx, slot, 443);
  if (rc == TCP_LIVENESS_RESULT_ALIVE) return TCP_LIVENESS_RESULT_ALIVE;
  if (rc == TCP_LIVENESS_RESULT_HARD_UNREACH) {
    if (slot->hard80) {
      tcp_liveness_mark_dead(job, slot);
      return TCP_LIVENESS_RESULT_HARD_UNREACH;
    }
    slot->phase = 3;
    return TCP_LIVENESS_RESULT_FAIL;
  }
  if (rc == TCP_LIVENESS_RESULT_PENDING) return TCP_LIVENESS_RESULT_PENDING;
  return TCP_LIVENESS_RESULT_FAIL;
}

static int tcp_liveness_handle_80_result(int ep, ScanProbeJob *job, int idx, tcp_liveness_slot_t *slot, int err) {
  if (!slot || slot->port != 80) return TCP_LIVENESS_RESULT_FAIL;
  if (is_hard_unreach(err)) slot->hard80 = 1;
  return tcp_liveness_start_443(ep, job, idx, slot);
}
static int tcp_liveness_complete_after_close(int ep, ScanProbeJob *job, int idx, tcp_liveness_slot_t *slot, int *inflight, int max_window, int *active_targets, int err, int allow_alive, int had_inflight) {
  if (!slot || !job) return TCP_LIVENESS_RESULT_PENDING;
  SCOUT_ASSERT(!job->alive || !job->dead);
  if (allow_alive && (err == 0 || err == ECONNREFUSED)) {
    tcp_liveness_mark_alive(job, slot);
    tcp_liveness_complete_target(active_targets);
    return TCP_LIVENESS_RESULT_ALIVE;
  }
  if (slot->port == 80) {
    int rc = tcp_liveness_handle_80_result(ep, job, idx, slot, err);
    if (rc == TCP_LIVENESS_RESULT_PENDING) {
      if (!slot->finished && slot->fd >= 0) {
        if (had_inflight && inflight && *inflight < max_window) {
          (*inflight)++;
          SCOUT_ASSERT(*inflight <= max_window);
          return TCP_LIVENESS_RESULT_PENDING;
        }
        tcp_liveness_slot_close(ep, slot);
      }
      tcp_liveness_mark_dead(job, slot);
      tcp_liveness_complete_target(active_targets);
      return TCP_LIVENESS_RESULT_FAIL;
    }
    if (rc == TCP_LIVENESS_RESULT_ALIVE) {
      tcp_liveness_complete_target(active_targets);
      return TCP_LIVENESS_RESULT_ALIVE;
    }
    if (rc == TCP_LIVENESS_RESULT_RESOURCE) {
      tcp_liveness_mark_dead(job, slot);
      tcp_liveness_complete_target(active_targets);
      return TCP_LIVENESS_RESULT_FAIL;
    }
  }
  tcp_liveness_mark_dead(job, slot);
  tcp_liveness_complete_target(active_targets);
  return TCP_LIVENESS_RESULT_FAIL;
}
static int tcp_liveness_finish_slot(int ep, ScanProbeJob *job, int idx, tcp_liveness_slot_t *slot, int *inflight, int max_window, int *active_targets, int err) {
  int had_inflight = 0;
  if (!slot || !job || slot->finished) return TCP_LIVENESS_RESULT_PENDING;
  tcp_liveness_slot_close(ep, slot);
  if (inflight && *inflight > 0) {
    (*inflight)--;
    SCOUT_ASSERT(*inflight >= 0);
    had_inflight = 1;
  }
  return tcp_liveness_complete_after_close(ep, job, idx, slot, inflight, max_window, active_targets, err, 1, had_inflight);
}
static int tcp_liveness_handle_timeout(int ep, ScanProbeJob *job, int idx, tcp_liveness_slot_t *slot, int *inflight, int max_window, int *active_targets) {
  int had_inflight = 0;
  if (!slot || !job || slot->finished) return TCP_LIVENESS_RESULT_PENDING;
  dbg_service_trace("timeout", job->ip, slot->port, IPPROTO_TCP, "timeout_ms=%d", discovery_tcp_liveness_ms());
  tcp_liveness_slot_close(ep, slot);
  if (inflight && *inflight > 0) {
    (*inflight)--;
    SCOUT_ASSERT(*inflight >= 0);
    had_inflight = 1;
  }
  return tcp_liveness_complete_after_close(ep, job, idx, slot, inflight, max_window, active_targets, ETIMEDOUT, 0, had_inflight);
}
static int tcp_liveness_launch_one(int ep, ScanProbeJob *job, const char *ip, int idx, int port, tcp_liveness_slot_t *slot, int timeout_ms) {
  if (!slot || !ip || !ip[0]) return TCP_LIVENESS_RESULT_FAIL;
  struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port) };
  if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) return TCP_LIVENESS_RESULT_FAIL;
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS || errno == ENOMEM) return TCP_LIVENESS_RESULT_RESOURCE;
    return TCP_LIVENESS_RESULT_FAIL;
  }
  (void)set_nonblock_fd(fd);
  (void)set_nodelay(fd);
  if (job && job->timing_started_ms && *job->timing_started_ms == 0) *job->timing_started_ms = (uint32_t)now_ms();
  if (slot->decision_started_ms == 0) slot->decision_started_ms = now_ms();
  slot->started_ms = now_ms();
  slot->deadline_ms = slot->started_ms + (uint64_t)(timeout_ms > 0 ? timeout_ms : 0);
  slot->finished = slot->epoll_registered = 0;
  int rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
  int e = (rc == 0) ? 0 : errno;
  if (rc == 0 || e == ECONNREFUSED) {
    dbg_service_trace("connect-ok", ip, port, IPPROTO_TCP, "immediate=1 err=%d", e);
    hard_close(fd);
    slot->fd = -1;
    slot->port = port;
    return TCP_LIVENESS_RESULT_ALIVE;
  }
  if (is_hard_unreach(e)) {
    dbg_service_trace("connect-fail", ip, port, IPPROTO_TCP, "err=%d", e);
    hard_close(fd);
    slot->fd = -1;
    slot->port = port;
    return TCP_LIVENESS_RESULT_HARD_UNREACH;
  }
  if (e != EINPROGRESS && e != EALREADY && e != EWOULDBLOCK) {
    dbg_service_trace("connect-fail", ip, port, IPPROTO_TCP, "err=%d", e);
    hard_close(fd);
    slot->fd = -1;
    slot->port = port;
    if (e == EMFILE || e == ENFILE || e == ENOBUFS || e == ENOMEM) return TCP_LIVENESS_RESULT_RESOURCE;
    return TCP_LIVENESS_RESULT_FAIL;
  }
  struct epoll_event ev;
  memset(&ev, 0, sizeof(ev));
  ev.events = EPOLLOUT | EPOLLERR | EPOLLHUP;
  ev.data.u32 = (uint32_t)idx;
  if (epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev) != 0) {
    int e2 = errno;
    dbg_service_trace("epoll-arm-fail", ip, port, IPPROTO_TCP, "errno=%d", e2);
    hard_close(fd);
    slot->fd = -1;
    slot->port = port;
    if (e2 == EMFILE || e2 == ENFILE || e2 == ENOBUFS || e2 == ENOMEM) return TCP_LIVENESS_RESULT_RESOURCE;
    return TCP_LIVENESS_RESULT_FAIL;
  }
  slot->fd = fd;
  slot->port = port;
  slot->epoll_registered = 1;
  dbg_service_trace("wait", ip, port, IPPROTO_TCP, "timeout_ms=%d", timeout_ms);
  return 0;
}
static int tcp_liveness_launch_pending_jobs(int ep, ScanProbeJob *jobs, int n_jobs, tcp_liveness_slot_t *slots, int *next_idx, int *inflight, int *active_targets, int max_window, int pacing_us, uint64_t *next_launch_ms) {
  while (*inflight < max_window && *next_idx < n_jobs) {
    int idx = *next_idx;
    int rc;
    if (jobs[idx].alive || jobs[idx].dead || !jobs[idx].ip || !jobs[idx].ip[0]) {
      (*next_idx)++;
      continue;
    }
    if (pacing_us > 0) {
      uint64_t now = now_ms();
      if (*next_launch_ms != 0 && now < *next_launch_ms) break;
      *next_launch_ms = now + ((((uint64_t)pacing_us) + ((uint64_t)999)) / ((uint64_t)1000));
    }
    slots[idx].phase = 1;
    rc = tcp_liveness_try_port(ep, &jobs[idx], idx, &slots[idx], 80);
    if (rc == TCP_LIVENESS_RESULT_RESOURCE) {
      tcp_liveness_mark_dead(&jobs[idx], &slots[idx]);
      (*next_idx)++;
      continue;
    }
    (*next_idx)++;
    if (rc == TCP_LIVENESS_RESULT_ALIVE) continue;
    if (rc == TCP_LIVENESS_RESULT_HARD_UNREACH) {
      rc = tcp_liveness_start_443(ep, &jobs[idx], idx, &slots[idx]);
      if (rc == TCP_LIVENESS_RESULT_RESOURCE) {
        tcp_liveness_mark_dead(&jobs[idx], &slots[idx]);
        continue;
      }
      if (rc == TCP_LIVENESS_RESULT_ALIVE || rc == TCP_LIVENESS_RESULT_HARD_UNREACH) continue;
      if (rc == TCP_LIVENESS_RESULT_PENDING) {
        (*inflight)++;
        SCOUT_ASSERT(*inflight <= max_window);
        (*active_targets)++;
        continue;
      }
      tcp_liveness_mark_dead(&jobs[idx], &slots[idx]);
      continue;
    }
    if (rc == TCP_LIVENESS_RESULT_PENDING) {
      (*inflight)++;
      (*active_targets)++;
      continue;
    }
    slots[idx].phase = 3;
  }
  return 0;
}
static int tcp_liveness_compute_wait_ms(const tcp_liveness_slot_t *slots, int n_jobs, int timeout_ms, int next_idx, int inflight, int pacing_us, uint64_t next_launch_ms, uint64_t now) {
  int wait_ms = -1;
  int pacing_wait_ms = tcp_scan_pacing_wait_ms(next_launch_ms);
  if (next_idx < n_jobs && (pacing_us <= 0 || pacing_wait_ms > 0 || inflight <= 0)) wait_ms = pacing_wait_ms;
  for (int i = 0; i < n_jobs; i++) {
    if (!tcp_liveness_slot_pending(&slots[i])) continue;
    int left = tcp_liveness_slot_remaining_ms(&slots[i], timeout_ms, now);
    if (left < 0) left = 0;
    if (wait_ms < 0 || left < wait_ms) wait_ms = left;
  }
  if (wait_ms < 0) wait_ms = 0;
  return wait_ms;
}
static void tcp_liveness_handle_epoll_events(int ep, struct epoll_event *evs, int k, ScanProbeJob *jobs, int n_jobs, tcp_liveness_slot_t *slots, int *inflight, int max_window, int *active_targets) {
  for (int j = 0; j < k; j++) {
    int idx = (int)evs[j].data.u32;
    if (idx < 0 || idx >= n_jobs || !tcp_liveness_slot_pending(&slots[idx])) continue;
    int err = 0;
    socklen_t elen = sizeof(err);
    if (getsockopt(slots[idx].fd, SOL_SOCKET, SO_ERROR, (char *)&err, &elen) != 0) err = errno;
    dbg_service_trace("event", jobs[idx].ip, slots[idx].port, IPPROTO_TCP, "events=0x%x err=%d phase=%d", evs[j].events, err, slots[idx].phase);
    int rc = tcp_liveness_finish_slot(ep, &jobs[idx], idx, &slots[idx], inflight, max_window, active_targets, err);
    if (rc == TCP_LIVENESS_RESULT_RESOURCE) {
      jobs[idx].dead = 1;
      jobs[idx].alive = 0;
    }
  }
}
static void tcp_liveness_expire_timeouts(int ep, ScanProbeJob *jobs, int n_jobs, tcp_liveness_slot_t *slots, int timeout_ms, uint64_t now, int *inflight, int max_window, int *active_targets) {
  for (int i = 0; i < n_jobs; i++) {
    if (!tcp_liveness_slot_pending(&slots[i])) continue;
    if (tcp_liveness_slot_remaining_ms(&slots[i], timeout_ms, now) > 0) continue;
    (void)tcp_liveness_handle_timeout(ep, &jobs[i], i, &slots[i], inflight, max_window, active_targets);
  }
}
int tcp_liveness_sweep_jobs_epoll_paced(ScanProbeJob *jobs, int n_jobs, int timeout_ms, int max_window, int pacing_us) {
  if (!jobs || n_jobs <= 0) return 0;
  int ep = epoll_create1(0);
  if (ep < 0) return -1;
  tcp_liveness_slot_t *slots = (tcp_liveness_slot_t *)calloc((size_t)n_jobs, sizeof(*slots));
  if (!slots) {
    close(ep);
    return TCP_LIVENESS_RESULT_FAIL;
  }
  for (int i = 0; i < n_jobs; i++)
    tcp_liveness_slot_reset(&slots[i]);
  int next_idx = 0;
  int inflight = 0;
  int active_targets = 0;
  uint64_t next_launch_ms = 0;
  if (max_window <= 0) max_window = SCOUTLESS_EPOLL_SIZE;
  for (;;) {
    tcp_liveness_launch_pending_jobs(ep, jobs, n_jobs, slots, &next_idx, &inflight, &active_targets, max_window, pacing_us, &next_launch_ms);
    if (next_idx >= n_jobs && inflight <= 0 && active_targets <= 0) break;
    uint64_t now = now_ms();
    int wait_ms = tcp_liveness_compute_wait_ms(slots, n_jobs, timeout_ms, next_idx, inflight, pacing_us, next_launch_ms, now);

    struct epoll_event evs[64];
    int k = epoll_wait(ep, evs, 64, wait_ms);
    now = now_ms();
    if (k < 0) {
      if (errno == EINTR) continue;
      break;
    }
    tcp_liveness_handle_epoll_events(ep, evs, k, jobs, n_jobs, slots, &inflight, max_window, &active_targets);
    tcp_liveness_expire_timeouts(ep, jobs, n_jobs, slots, timeout_ms, now, &inflight, max_window, &active_targets);
  }
  for (int i = 0; i < n_jobs; i++)
    tcp_liveness_slot_close(ep, &slots[i]);
  free(slots);
  close(ep);
  return 0;
}


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
#include "runtime.h"
#include "probes.h"
#include "util.h"
#include "scan.h"
#include "discover_policy.h"
#include "scan_internal.h"
#include "scan_tcp_internal.h"

static int tcp_scan_pacing_wait_ms(uint64_t next_launch_ms) {
  if (next_launch_ms == 0) return 0;
  uint64_t now = now_ms();
  if (now >= next_launch_ms) return 0;
  uint64_t delta = next_launch_ms - now;
  if (delta == 0) return 0;
  if (delta > (uint64_t)INT_MAX) return INT_MAX;
  return (int)delta;
}
int tcp_connect_single_nb(const char *ip_str, int port, int *immediate_ok) {
  struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port) };
  if (immediate_ok) *immediate_ok = 0;
  if (inet_pton(AF_INET, ip_str, &sa.sin_addr) != 1) return -1;
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  (void)set_nonblock_fd(fd);
  (void)set_nodelay(fd);
  int rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
  int e = (rc == 0) ? 0 : errno;
  if (rc == 0) {
    if (immediate_ok) *immediate_ok = 1;
    return fd;
  }
  if (e == EINPROGRESS || e == EALREADY || e == EWOULDBLOCK) return fd;
  hard_close(fd);
  return -1;
}
uint32_t tcp_scan_elapsed_ms(uint64_t started_ms, uint64_t ended_ms) {
  if (started_ms == 0 || ended_ms <= started_ms) return 0;
  if (ended_ms - started_ms > 0xffffffffULL) return 0xffffffffU;
  return (uint32_t)(ended_ms - started_ms);
}
static int tcp_scan_fill_window(tcp_scan_slot_t *slots, int ep, const ScanTarget *targets, int n_targets, PlanItem **tcp_items, int tcp_n, int *next_port_idx, int *next_host_idx, int pacing_us, int max_inflight, uint64_t *next_launch_ms) {
  int filled = 0;
  for (;;) {
    int free_idx = tcp_scan_find_free_slot(slots,max_inflight);
    if (free_idx < 0) break;
    int port_idx;
    int host_idx;
    int saved_port_idx = *next_port_idx;
    int saved_host_idx = *next_host_idx;
    if (!scan_next_pair(next_port_idx, next_host_idx, tcp_n, n_targets, &port_idx, &host_idx)) break;
    if (!tcp_items[port_idx]) continue;

    tcp_scan_slot_t *slot = &slots[free_idx];
    slot->fd = -1;
    slot->web.fd = -1;
    slot->slot_id = free_idx;
    if (pacing_us > 0 && next_launch_ms) {
      uint64_t now = now_ms();
      if (*next_launch_ms != 0 && now < *next_launch_ms) {
        *next_port_idx = saved_port_idx;
        *next_host_idx = saved_host_idx;
        break;
      }
      *next_launch_ms = now + ((((uint64_t)pacing_us) + ((uint64_t)999)) / ((uint64_t)1000));
    }
    int prep_err = 0;
    if (!tcp_scan_prepare_slot(slot, ep, &targets[host_idx], tcp_items[port_idx], &prep_err)) {
      if (prep_err == EMFILE || prep_err == ENFILE || prep_err == ENOBUFS || prep_err == ENOMEM) {
        *next_port_idx = saved_port_idx;
        *next_host_idx = saved_host_idx;
        break;
      }
      continue;
    }
    filled = 1;
  }
  return filled;
}
static void tcp_scan_update_wait_state(const tcp_scan_slot_t *slots, int max_inflight,uint64_t now, tcp_scan_wait_state_t *state) {
  if (!slots || !state) return;
  state->wait_ms = -1;
  state->any_pending = state->has_ready = 0;
  for (int i = 0; i < max_inflight; i++) {
    const tcp_scan_slot_t *slot = &slots[i];
    int left;
    if (slot->state == TCP_SLOT_READY) {
      state->has_ready = 1;
      continue;
    }
    if (!tcp_scan_slot_is_pending(slot)) continue;
    left = tcp_scan_slot_timeout_left(slot, now);
    if (left < 0) left = 0;
    state->any_pending = 1;
    if (state->wait_ms < 0 || left < state->wait_ms) state->wait_ms = left;
  }
}
static int tcp_scan_run_wait_cycle(tcp_scan_slot_t *slots, int max_inflight, int ep, int next_port_idx, int next_host_idx, int tcp_n, int n_targets, uint64_t next_launch_ms, const RemotePorts *prp, const char *public_name, Service *list, int *out_n, uint32_t *host_read_hints_ms, int n_targets_total, int max_services) {
  int pacing_wait_ms = -1;
  uint64_t now = now_ms();
  tcp_scan_wait_state_t wait_state;
  tcp_scan_update_wait_state(slots, max_inflight, now, &wait_state);
  int has_active = wait_state.any_pending || wait_state.has_ready;
  if (scan_has_more_pairs(next_port_idx, next_host_idx, tcp_n, n_targets)) pacing_wait_ms = tcp_scan_pacing_wait_ms(next_launch_ms);
  if (!has_active) {
    if (!scan_has_more_pairs(next_port_idx, next_host_idx, tcp_n, n_targets)) return -1;
    if (pacing_wait_ms > 0) {
      struct epoll_event events[1];
      (void)epoll_wait(ep, events, 1, pacing_wait_ms);
    }
    return 0;
  }
  if (wait_state.wait_ms < 0) {
    if (pacing_wait_ms < 0) return 0;
    wait_state.wait_ms = pacing_wait_ms;
  } else if (pacing_wait_ms >= 0 && pacing_wait_ms < wait_state.wait_ms) {
    wait_state.wait_ms = pacing_wait_ms;
  }
  if (wait_state.wait_ms < 0) return 0;
  int rc = tcp_scan_wait_for_events(ep, slots, max_inflight, wait_state.wait_ms, prp, public_name, list, out_n, host_read_hints_ms, n_targets_total, max_services);
  if (rc < 0) return -1;
  if (rc > 0) return 1;
  return 0;
}
void scan_tcp_targets_paced_limited(const ScanTarget *targets, int n_targets, PlanItem **tcp_items, int tcp_n, const RemotePorts *rp, Service *list, int *out_n, int pacing_us, int max_inflight, int max_services) {
  if (!targets || n_targets <= 0 || !tcp_items || tcp_n <= 0 || !list || !out_n) return;
  uint32_t *host_read_hints_ms = (uint32_t *)calloc((size_t)n_targets, sizeof(*host_read_hints_ms));
  if (!host_read_hints_ms) return;
  if (max_services <= 0) max_services = MAX_SERVICES;
  const RemotePorts rp0 = {0};
  const RemotePorts *prp = rp ? rp : &rp0;
  const char * public_name = g_probe_public_domain[0] ? g_probe_public_domain : NULL;
  int ep = epoll_create1(0);
  if (ep < 0) {
    free(host_read_hints_ms);
    return;
  }
  tcp_scan_slot_t *slots = calloc(max_inflight, sizeof(tcp_scan_slot_t));
  if (!slots) {
    free(host_read_hints_ms);
    close(ep);
    return;
  }
  for (int i = 0; i < max_inflight; i++) {
    slots[i].state = TCP_SLOT_FREE;
    slots[i].web.fd = -1;
    slots[i].fd = -1;
  }
  uint64_t next_launch_ms = 0;
  int next_port_idx = 0;
  int next_host_idx = 0;
  for (;;) {
    if (*out_n >= max_services) {
      tcp_scan_cleanup_unused_ready_slots(slots, max_inflight, ep);
      break;
    }
    (void)tcp_scan_fill_window(slots, ep, targets, n_targets, tcp_items, tcp_n, &next_port_idx, &next_host_idx, pacing_us, max_inflight, &next_launch_ms);
    tcp_scan_handle_pending_timeouts(slots, max_inflight, ep, prp, public_name, list, out_n, host_read_hints_ms, n_targets);
    tcp_scan_publish_ready_slots(slots, max_inflight, ep, prp, public_name, list, out_n, host_read_hints_ms, n_targets, max_services);
    if (*out_n >= max_services) {
      tcp_scan_cleanup_unused_ready_slots(slots, max_inflight, ep);
      break;
    }
    tcp_scan_reclaim_done_slots(slots, max_inflight, ep);
    int wait_rc = tcp_scan_run_wait_cycle(slots, max_inflight, ep, next_port_idx, next_host_idx, tcp_n, n_targets, next_launch_ms, prp, public_name, list, out_n, host_read_hints_ms, n_targets, max_services);
    if (wait_rc < 0) break;
    if (wait_rc > 0) break;
    if (*out_n >= max_services) break;
    tcp_scan_reclaim_done_slots(slots, max_inflight, ep);
  }
  for (int i = 0; i < max_inflight; i++) tcp_scan_slot_reset(&slots[i], ep);
  close(ep);
  free(host_read_hints_ms);
  free(slots);
}

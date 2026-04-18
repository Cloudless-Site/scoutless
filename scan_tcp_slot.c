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
#include "proto.h"
#include "probes.h"
#include "util.h"
#include "vendor.h"
#include "scan.h"
#include "discover_policy.h"
#include "web_probe_internal.h"
#include "scan_internal.h"
#include "scan_tcp_internal.h"

static int tcp_send_all(int fd, const void *buf, size_t len, size_t *io_off) {
  if (fd < 0 || !buf || !io_off) return -1;
  const unsigned char *p = (const unsigned char *)buf;
  size_t off = *io_off;
  int flags = 0;
#ifdef MSG_NOSIGNAL
  flags |= MSG_NOSIGNAL;
#endif
  while (off < len) {
    ssize_t wr = send(fd, p + off, len - off, flags);
    if (wr < 0) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        *io_off = off;
        return 1;
      }
      return -1;
    }
    if (wr == 0) return -1;
    off += (size_t)wr;
  }
  *io_off = off;
  return 0;
}
static void tcp_epoll_del_ignore(int ep, int fd) {
  if (ep < 0 || fd < 0) return;
  if (epoll_ctl(ep, EPOLL_CTL_DEL, fd, NULL) == 0) return;
  if (errno == ENOENT || errno == EBADF) return;
}
static void tcp_scan_slot_close(int ep, tcp_scan_slot_t *slot) {
  if (!slot || slot->fd < 0) return;
  if (slot->epoll_registered) tcp_epoll_del_ignore(ep, slot->fd);
  hard_close(slot->fd);
  slot->epoll_registered = 0;
  slot->fd = -1;
}
static void tcp_scan_slot_transfer_fd_to_web(tcp_scan_slot_t *slot) {
  if (!slot || slot->fd < 0) return;
  slot->web.fd = slot->fd;
  slot->epoll_registered = 0;
  slot->fd = -1;
}
static void tcp_scan_slot_close_web_owner(tcp_scan_slot_t *slot) {
  if (!slot || slot->web.fd < 0) return;
  slot->web.active = 0;
  slot->web.fd = -1;
}
static void tcp_scan_slot_finish(tcp_scan_slot_t *slot) {
  if (!slot) return;
  slot->finished = 1;
}
void tcp_scan_slot_reset(tcp_scan_slot_t *slot, int ep) {
  if (!slot) return;
  tcp_scan_slot_close_web_owner(slot);
  tcp_scan_slot_close(ep, slot);
  memset(slot, 0, sizeof(*slot));
  slot->fd = -1;
  slot->web.fd = -1;
}
void tcp_scan_slot_mark_done(tcp_scan_slot_t *slot, int ep) {
  if (!slot || slot->finished) return;
  dbg_service_trace("slot-done", slot->ip, slot->item ? slot->item->port : 0, IPPROTO_TCP, "slot=%d fd=%d web_fd=%d state=%d", slot->slot_id, slot->fd, slot->web.fd, (int)slot->state);
  tcp_scan_slot_close_web_owner(slot);
  tcp_scan_slot_close(ep, slot);
  tcp_scan_slot_finish(slot);
  slot->state = TCP_SLOT_DONE;
}
void tcp_scan_reclaim_done_slots(tcp_scan_slot_t *slots, int max_inflight, int ep) {
  if (!slots) return;
  for (int i = 0; i < max_inflight; i++) {
    if (slots[i].state != TCP_SLOT_DONE) continue;
    tcp_scan_slot_reset(&slots[i], ep);
  }
}
void tcp_scan_cleanup_unused_ready_slots(tcp_scan_slot_t *slots, int max_inflight, int ep) {
  if (!slots) return;
  for (int i = 0; i < max_inflight; i++) {
    tcp_scan_slot_t *slot = &slots[i];
    if (slot->finished || slot->state != TCP_SLOT_READY) continue;
    tcp_scan_slot_mark_done(slot, ep);
  }
}
void tcp_scan_publish_ready_slots(tcp_scan_slot_t *slots, int max_inflight, int ep, const RemotePorts *rp, const char *public_name, Service *list, int *out_n, uint32_t *host_read_hints_ms, int n_targets, int max_services) {
  if (!slots) return;
  for (int i = 0; i < max_inflight; i++) {
    tcp_scan_slot_t *slot = &slots[i];
    if (slot->state != TCP_SLOT_READY || slot->finished) continue;
    if (out_n && *out_n >= max_services) break;
    tcp_scan_slot_publish_connected(slot, ep, rp, public_name, list, out_n, host_read_hints_ms, n_targets);
  }
}
static uint32_t tcp_scan_connect_ms(const tcp_scan_slot_t *slot) {
  if (!slot) return 0;
  return tcp_scan_elapsed_ms(slot->service_started_ms, slot->connect_done_ms);
}
static uint32_t tcp_scan_match_ms(const tcp_scan_slot_t *slot, uint64_t ended_ms) {
  if (!slot) return 0;
  return tcp_scan_elapsed_ms(slot->match_started_ms, ended_ms);
}
static uint32_t tcp_scan_total_ms(const tcp_scan_slot_t *slot, uint64_t ended_ms) {
  if (!slot) return 0;
  uint32_t connect_ms = tcp_scan_elapsed_ms(slot->service_started_ms, slot->connect_done_ms);
  uint32_t match_ms = tcp_scan_elapsed_ms(slot->match_started_ms, ended_ms);
  if (0xffffffffU - connect_ms < match_ms) return 0xffffffffU;
  return connect_ms + match_ms;
}
static void tcp_probe_publish_vendor_result(const tcp_scan_slot_t *slot, ServiceType t, const ServiceInfo *si, Service *list, int *out_n) {
  if (!slot || !slot->item || !slot->item->vp || !si || !list || !out_n) return;
  const struct vendor_probe *vp = slot->item->vp;
  int matched = vendor_probe_expect_match(vp, slot->acc, slot->acc_len);
  if (!matched && !slot->item->force_publish) return;
  char pub_name[64];
  safe_strncpy(pub_name, si->name[0] ? si->name : vp->send_text, sizeof(pub_name));
  add_service_unique(list, out_n, slot->ip, slot->item->port, slot->item->port, slot->item->force_publish ? slot->item->forced : t, pub_name);
  uint64_t ended_ms = now_ms();
  dbg_service_found("tcp", slot->ip, slot->item->port, (int)(slot->item->force_publish ? slot->item->forced : t), pub_name, NULL, tcp_scan_total_ms(slot, ended_ms), tcp_scan_connect_ms(slot), tcp_scan_match_ms(slot, ended_ms));
}
static void tcp_probe_publish_service_result(const tcp_scan_slot_t *slot, const RemotePorts *prp, Service *list, int *out_n) {
  if (!slot || !slot->item || slot->acc_len == 0 || !list || !out_n) return;
  ServiceInfo si;
  analyze_tcp_response(slot->item->port, slot->acc, slot->acc_len, &si);
  ServiceType t = map_service_to_tunnel(si.type, IPPROTO_TCP, slot->item->port, prp);
  if (slot->item->is_vendor_probe && slot->item->vp) {
    tcp_probe_publish_vendor_result(slot, t, &si, list, out_n);
    return;
  }
  add_service_unique(list, out_n, slot->ip, slot->item->port, slot->item->port, t, si.name);
  uint64_t ended_ms = now_ms();
  dbg_service_found("tcp", slot->ip, slot->item->port, t, si.name, NULL, tcp_scan_total_ms(slot, ended_ms), tcp_scan_connect_ms(slot), tcp_scan_match_ms(slot, ended_ms));
}
static void tcp_scan_slot_publish_tcp_fallback(tcp_scan_slot_t *slot, Service *list, int *out_n) {
  char tmpn[64];
  strcpy(tmpn, "tcp");
  add_service_unique(list, out_n, slot->ip, slot->item->port, slot->item->port, SRV_TCP, tmpn);
  service_clear_hint(list, *out_n, slot->ip, slot->item->port, SRV_TCP);
  uint64_t ended_ms = now_ms();
  dbg_service_found("tcp-fallback", slot->ip, slot->item->port, SRV_TCP, tmpn, NULL, tcp_scan_total_ms(slot, ended_ms), tcp_scan_connect_ms(slot), tcp_scan_match_ms(slot, ended_ms));
}
void tcp_scan_slot_publish_connected_result(tcp_scan_slot_t *slot, Service *list, int *out_n) {
  if (!slot || !slot->item || !list || !out_n) return;
  const char *dname = NULL;
  char tmpn[64];
  ServiceType dt = default_tcp_type_for_port(slot->item->port, &dname);
  strncpy(tmpn, dname ? dname : "unknown", sizeof(tmpn) - 1);
  tmpn[sizeof(tmpn) - 1] = 0;
  add_service_unique(list, out_n, slot->ip, slot->item->port, slot->item->port, dt, tmpn);
  service_clear_hint(list, *out_n, slot->ip, slot->item->port, dt);
  uint64_t ended_ms = now_ms();
  dbg_service_found("tcp-connect", slot->ip, slot->item->port, dt, tmpn, NULL, tcp_scan_total_ms(slot, ended_ms), tcp_scan_connect_ms(slot), tcp_scan_match_ms(slot, ended_ms));
}
static void tcp_scan_slot_publish_nonweb_result(tcp_scan_slot_t *slot, Service *list, int *out_n) {
  if (!slot) return;
  if (slot->connect_mode == TCP_CONNECT_MODE_VENDOR_FALLBACK) tcp_scan_slot_publish_tcp_fallback(slot, list, out_n);
  else tcp_scan_slot_publish_connected_result(slot, list, out_n);
}
static void tcp_scan_slot_finalize_nonweb_result(tcp_scan_slot_t *slot, int ep, Service *list, int *out_n) {
  tcp_scan_slot_publish_nonweb_result(slot, list, out_n);
  tcp_scan_slot_mark_done(slot, ep);
}
static int tcp_scan_slot_start_plain_send(tcp_scan_slot_t *slot, int ep, const RemotePorts *rp, uint32_t *host_read_hints_ms, int n_targets) {
  if (!slot || slot->fd < 0 || !slot->item) return 0;
  int n = tcp_probe_build_request(slot->tx_buf, sizeof(slot->tx_buf), slot->ip, slot->item->port, slot->item, rp);
  if (n < 0) return 0;
  slot->tx_len = (uint16_t)n;
  slot->tx_off = slot->match_started_ms = 0;
  dbg_service_trace("send-prepare", slot->ip, slot->item->port, IPPROTO_TCP, "tx_len=%u", (unsigned)slot->tx_len);
  if (slot->tx_len == 0) {
    slot->write_shutdown = 0;
    slot->match_started_ms = now_ms();
    if (epoll_add_or_mod_ptr(ep, slot->fd, slot, EPOLLIN | EPOLLERR | EPOLLHUP) != 0) {
      dbg_service_trace("epoll-arm-fail", slot->ip, slot->item->port, IPPROTO_TCP, "slot=%d fd=%d errno=%d state=read-wait", slot->slot_id, slot->fd, errno);
      return 0;
    }
    slot->epoll_registered = 1;
    slot->state = TCP_SLOT_READ;
    slot->deadline_ms = now_ms() + (uint64_t)tcp_scan_host_read_timeout_ms(slot->timeout_ms, host_read_hints_ms && slot->target_idx >= 0 && slot->target_idx < n_targets ? host_read_hints_ms[slot->target_idx] : 0);
    dbg_service_trace("read-wait", slot->ip, slot->item->port, IPPROTO_TCP, "slot=%d fd=%d tx_len=0", slot->slot_id, slot->fd);
    return 1;
  }
  size_t off = 0;
  n = tcp_send_all(slot->fd, slot->tx_buf, slot->tx_len, &off);
  if (off > 0 && slot->tx_off == 0) slot->match_started_ms = now_ms();
  slot->tx_off = (uint16_t)off;
  if (n < 0) {
    dbg_service_trace("send-fail", slot->ip, slot->item->port, IPPROTO_TCP, "sent=%u total=%u errno=%d", (unsigned)slot->tx_off, (unsigned)slot->tx_len, errno);
    return 0;
  }
  if (slot->tx_off >= slot->tx_len) {
    if (!slot->write_shutdown) {
      shutdown(slot->fd, SHUT_WR);
      slot->write_shutdown = 1;
    }
    if (epoll_add_or_mod_ptr(ep, slot->fd, slot, EPOLLIN | EPOLLERR | EPOLLHUP) != 0) {
      dbg_service_trace("epoll-arm-fail", slot->ip, slot->item->port, IPPROTO_TCP, "slot=%d fd=%d errno=%d state=send-done", slot->slot_id, slot->fd, errno);
      return 0;
    }
    slot->epoll_registered = 1;
    slot->state = TCP_SLOT_READ;
    slot->deadline_ms = now_ms() + (uint64_t)tcp_scan_host_read_timeout_ms(slot->timeout_ms, host_read_hints_ms && slot->target_idx >= 0 && slot->target_idx < n_targets ? host_read_hints_ms[slot->target_idx] : 0);
    dbg_service_trace("send-done", slot->ip, slot->item->port, IPPROTO_TCP, "slot=%d fd=%d sent=%u", slot->slot_id, slot->fd, (unsigned)slot->tx_off);
  } else {
    if (epoll_add_or_mod_ptr(ep, slot->fd, slot, EPOLLOUT | EPOLLERR | EPOLLHUP) != 0) {
      dbg_service_trace("epoll-arm-fail", slot->ip, slot->item->port, IPPROTO_TCP, "slot=%d fd=%d errno=%d state=send-partial", slot->slot_id, slot->fd, errno);
      return 0;
    }
    slot->epoll_registered = 1;
    slot->state = TCP_SLOT_SEND;
    dbg_service_trace("send-partial", slot->ip, slot->item->port, IPPROTO_TCP, "slot=%d fd=%d sent=%u total=%u", slot->slot_id, slot->fd, (unsigned)slot->tx_off, (unsigned)slot->tx_len);
  }
  return 1;
}
static int tcp_scan_slot_start_vendor_fallback(tcp_scan_slot_t *slot, int ep, const RemotePorts *rp, uint32_t *host_read_hints_ms, int n_targets) {
  if (!slot || !slot->item || !slot->item->is_vendor_probe || !slot->item->vp) return 0;
  tcp_scan_slot_close_web_owner(slot);
  if (slot->fd >= 0) tcp_scan_slot_close(ep, slot);
  int immediate_ok = 0;
  int fd = tcp_connect_single_nb(slot->ip, slot->item->port, &immediate_ok);
  if (fd < 0) return 0;
  uint64_t started_ms = now_ms();
  slot->fd = fd;
  slot->started_ms = started_ms;
  slot->service_started_ms = started_ms;
  slot->connect_done_ms = immediate_ok ? started_ms : 0;
  slot->deadline_ms = started_ms + (uint64_t)slot->timeout_ms;
  slot->connect_mode = TCP_CONNECT_MODE_VENDOR_FALLBACK;
  slot->match_started_ms = slot->finished = slot->epoll_registered = slot->write_shutdown = slot->tx_len = slot->tx_off = 0;
  if (immediate_ok) {
    slot->state = TCP_SLOT_READY;
    dbg_service_trace("vendor-connect-ok", slot->ip, slot->item->port, IPPROTO_TCP, "slot=%d fd=%d immediate=1", slot->slot_id, slot->fd);
    if (!tcp_scan_slot_start_plain_send(slot, ep, rp, host_read_hints_ms, n_targets)) {
      tcp_scan_slot_close(ep, slot);
      slot->connect_mode = TCP_CONNECT_MODE_NORMAL;
      slot->state = TCP_SLOT_FREE;
      return 0;
    }
    return 1;
  }
  {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLOUT | EPOLLERR | EPOLLHUP;
    ev.data.ptr = slot;
    if (epoll_ctl(ep, EPOLL_CTL_ADD, slot->fd, &ev) != 0) {
      tcp_scan_slot_close(ep, slot);
      return 0;
    }
    slot->epoll_registered = 1;
  }
  slot->state = TCP_SLOT_CONNECT;
  dbg_service_trace("vendor-connect-start", slot->ip, slot->item->port, IPPROTO_TCP, "slot=%d fd=%d timeout_ms=%d immediate=%d", slot->slot_id, slot->fd, slot->timeout_ms, immediate_ok);
  return 1;
}
static int tcp_scan_slot_start_vendor_or_fallback(tcp_scan_slot_t *slot, int ep, const RemotePorts *rp, Service *list, int *out_n, uint32_t *host_read_hints_ms, int n_targets) {
  if (tcp_scan_slot_start_vendor_fallback(slot, ep, rp, host_read_hints_ms, n_targets)) {
    slot->web.active = 0;
    return 1;
  }
  tcp_scan_slot_publish_tcp_fallback(slot, list, out_n);
  slot->web.active = 0;
  tcp_scan_slot_mark_done(slot, ep);
  return 0;
}
static void tcp_scan_slot_finish_web_success(tcp_scan_slot_t *slot, int ep, Service *list, int *out_n, uint32_t *host_read_hints_ms, int n_targets) {
  uint64_t ended_ms;
  tcp_scan_update_host_read_hint(host_read_hints_ms, n_targets, slot->target_idx, slot->match_started_ms, now_ms());
  add_service_unique(list, out_n, slot->ip, slot->item->port, slot->item->port, slot->web.out.final_type, (char *)((slot->web.out.final_type == SRV_HTTPS) ? "https" : "http"));
  if (slot->web.out.svc_hint[0]) service_set_hint(list, *out_n, slot->ip, slot->item->port, slot->web.out.final_type, slot->web.out.svc_hint);
  ended_ms = now_ms();
  dbg_service_found("web", slot->ip, slot->item->port, slot->web.out.final_type, slot->web.out.final_type == SRV_HTTPS ? "https" : "http", slot->web.out.svc_hint, tcp_scan_total_ms(slot, ended_ms), tcp_scan_connect_ms(slot), tcp_scan_match_ms(slot, ended_ms));
  slot->web.active = 0;
  tcp_scan_slot_mark_done(slot, ep);
}
static void tcp_scan_slot_finish_web_timeout(tcp_scan_slot_t *slot, int ep, Service *list, int *out_n) {
  slot->web.active = 0;
  tcp_scan_slot_mark_done(slot, ep);
  tcp_scan_slot_publish_tcp_fallback(slot, list, out_n);
}
static void tcp_scan_slot_finish_web(tcp_scan_slot_t *slot, int ep, const RemotePorts *rp, Service *list, int *out_n, uint32_t *host_read_hints_ms, int n_targets) {
  dbg_service_trace("web-finish", slot->ip, slot->item->port, IPPROTO_TCP, "final_type=%s read_timed_out=%d io_timeout_ms=%d", slot->web.out.final_type == SRV_HTTPS ? "https" : (slot->web.out.final_type == SRV_HTTP ? "http" : "unknown"), slot->web.read_timed_out, web_probe_effective_io_timeout_ms(&slot->web));
  if (slot->web.out.final_type == SRV_HTTP || slot->web.out.final_type == SRV_HTTPS) {
    tcp_scan_slot_finish_web_success(slot, ep, list, out_n, host_read_hints_ms, n_targets);
    return;
  }
  if (slot->web.read_timed_out) {
    tcp_scan_slot_finish_web_timeout(slot, ep, list, out_n);
    return;
  }
  tcp_scan_slot_close_web_owner(slot);
  (void)tcp_scan_slot_start_vendor_or_fallback(slot, ep, rp, list, out_n, host_read_hints_ms, n_targets);
}
static void tcp_scan_slot_start_web(tcp_scan_slot_t *slot, int ep, const RemotePorts *rp, const char *public_name, Service *list, int *out_n, uint32_t *host_read_hints_ms, int n_targets) {
  int started = 0;
  slot->match_started_ms = 0;
  memset(&slot->web, 0, sizeof(slot->web));
  slot->web.fd = -1;
  slot->web.port = slot->item->port;
  slot->web.stop_after_http = tcp_probe_stop_after_http_remote((uint16_t)slot->item->port, rp);
  slot->web.step = WEB_STEP_HTTP_IP;
  slot->web.phase = WEB_PHASE_IDLE;
  slot->web.out.redirect_host[0] = 0;
  slot->web.io_timeout_ms = tcp_scan_host_read_timeout_ms(web_probe_io_timeout_ms(), host_read_hints_ms && slot->target_idx >= 0 && slot->target_idx < n_targets ? host_read_hints_ms[slot->target_idx] : 0);
  if (slot->fd >= 0) {
    started = web_probe_prepare_step_connected(&slot->web, slot->fd, slot->ip, public_name);
    if (started) {
      tcp_scan_slot_transfer_fd_to_web(slot);
      if (epoll_add_or_mod_ptr(ep, slot->web.fd, slot, slot->web.phase == WEB_PHASE_READ ? (EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP) : (EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0) {
        dbg_service_trace("web-arm-fail", slot->ip, slot->item->port, IPPROTO_TCP, "slot=%d fd=%d errno=%d step=%d phase=%d reused_fd=1", slot->slot_id, slot->web.fd, errno, slot->web.step, slot->web.phase);
        tcp_scan_slot_close_web_owner(slot);
      } else {
        slot->web.active = 1;
        slot->state = TCP_SLOT_WEB;
        dbg_service_trace("web-start", slot->ip, slot->item->port, IPPROTO_TCP, "slot=%d fd=%d step=%d phase=%d reused_fd=1", slot->slot_id, slot->web.fd, slot->web.step, slot->web.phase);
        return;
      }
    }
    if (slot->fd >= 0) {
      hard_close(slot->fd);
      slot->fd = -1;
    }
  }
  if (web_probe_prepare_step(&slot->web, slot->ip, public_name)) {
    if (epoll_add_or_mod_ptr(ep, slot->web.fd, slot, slot->web.phase == WEB_PHASE_READ ? (EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP) : (EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0) {
      dbg_service_trace("web-arm-fail", slot->ip, slot->item->port, IPPROTO_TCP, "slot=%d fd=%d errno=%d step=%d phase=%d reused_fd=0", slot->slot_id, slot->web.fd, errno, slot->web.step, slot->web.phase);
      tcp_scan_slot_close_web_owner(slot);
    } else {
      slot->web.active = 1;
      slot->state = TCP_SLOT_WEB;
      dbg_service_trace("web-start", slot->ip, slot->item->port, IPPROTO_TCP, "slot=%d fd=%d step=%d phase=%d reused_fd=0", slot->slot_id, slot->web.fd, slot->web.step, slot->web.phase);
      return;
    }
  }
  (void)tcp_scan_slot_start_vendor_or_fallback(slot, ep, rp, list, out_n, host_read_hints_ms, n_targets);
}
void tcp_scan_slot_publish_connected(tcp_scan_slot_t *slot, int ep, const RemotePorts *rp, const char *public_name, Service *list, int *out_n, uint32_t *host_read_hints_ms, int n_targets) {
  if (slot->connect_mode == TCP_CONNECT_MODE_NORMAL && is_web_candidate_port(slot->item->port, rp)) {
    tcp_scan_slot_start_web(slot, ep, rp, public_name, list, out_n, host_read_hints_ms, n_targets);
    return;
  }
  if (!tcp_scan_slot_start_plain_send(slot, ep, rp, host_read_hints_ms, n_targets)) {
    tcp_scan_slot_finalize_nonweb_result(slot, ep, list, out_n);
    return;
  }
  slot->connect_mode = TCP_CONNECT_MODE_NORMAL;
}
int tcp_scan_find_free_slot(tcp_scan_slot_t *slots,int max_inflight) {
  if (!slots) return -1;
  for (int i = 0; i < max_inflight; i++) {
    if (slots[i].state == TCP_SLOT_FREE) return i;
  }
  return -1;
}
int tcp_scan_prepare_slot(tcp_scan_slot_t *slot, int ep, const ScanTarget *target, PlanItem *item, int *out_err) {
  if (!slot || !target || !item) return 0;
  if (out_err) *out_err = 0;
  slot->acc[0] = slot->acc_len = 0;
  slot->ip = target->ip;
  slot->item = item;
  slot->timeout_ms = scan_connect_timeout_ms();
  if (target->timeout_ms > slot->timeout_ms) slot->timeout_ms = target->timeout_ms;
  if (slot->timeout_ms <= 0) slot->timeout_ms = 1000;

  int immediate_ok = 0;
  slot->fd = tcp_connect_single_nb(slot->ip, slot->item->port, &immediate_ok);
  if (slot->fd < 0) {
    if (out_err) *out_err = errno;
    tcp_scan_slot_reset(slot, ep);
    return 0;
  }
  slot->started_ms = now_ms();
  slot->service_started_ms = slot->started_ms;
  slot->connect_done_ms = immediate_ok ? slot->started_ms : 0;
  slot->deadline_ms = slot->started_ms + (uint64_t)slot->timeout_ms;
  slot->match_started_ms = slot->finished = slot->epoll_registered = slot->write_shutdown = 0;
  slot->state = immediate_ok ? TCP_SLOT_READY : TCP_SLOT_CONNECT;
  dbg_service_trace("connect-start", slot->ip, slot->item->port, IPPROTO_TCP, "slot=%d fd=%d timeout_ms=%d immediate=%d", slot->slot_id, slot->fd, slot->timeout_ms, immediate_ok);
  if (!immediate_ok) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLOUT | EPOLLERR | EPOLLHUP;
    ev.data.ptr = slot;
    if (epoll_ctl(ep, EPOLL_CTL_ADD, slot->fd, &ev) != 0) {
      if (out_err) *out_err = errno;
      tcp_scan_slot_reset(slot, ep);
      return 0;
    }
    slot->epoll_registered = 1;
  }
  return 1;
}
static void tcp_scan_slot_finish_plain_without_response(tcp_scan_slot_t *slot, int ep, Service *list, int *out_n) {
  if (!slot) return;
  if (slot->state == TCP_SLOT_CONNECT) {
    tcp_scan_slot_mark_done(slot, ep);
    slot->connect_mode = TCP_CONNECT_MODE_NORMAL;
    return;
  }
  tcp_scan_slot_finalize_nonweb_result(slot, ep, list, out_n);
  slot->connect_mode = TCP_CONNECT_MODE_NORMAL;
}
static void tcp_scan_handle_web_timeout(tcp_scan_slot_t *slot, int ep, const RemotePorts *prp, const char *public_name, Service *list, int *out_n, uint32_t *host_read_hints_ms, int n_targets) {
  if (!slot || slot->state != TCP_SLOT_WEB || !slot->web.active) return;
  dbg_service_trace("web-timeout", slot->ip, slot->item->port, IPPROTO_TCP, "step=%d phase=%d io_timeout_ms=%d", slot->web.step, slot->web.phase, web_probe_effective_io_timeout_ms(&slot->web));
  if (web_probe_handle_timeout(&slot->web, ep, slot, slot->ip, public_name, &slot->match_started_ms)) return;
  tcp_scan_slot_finish_web(slot, ep, prp, list, out_n, host_read_hints_ms, n_targets);
}
void tcp_scan_handle_slot_timeout(tcp_scan_slot_t *slot, int ep, const RemotePorts *prp, const char *public_name, Service *list, int *out_n, uint32_t *host_read_hints_ms, int n_targets) {
  if (!slot || slot->state == TCP_SLOT_FREE || slot->state == TCP_SLOT_DONE || slot->state == TCP_SLOT_READY) return;
  if (slot->state == TCP_SLOT_WEB && slot->web.active) {
    tcp_scan_handle_web_timeout(slot, ep, prp, public_name, list, out_n, host_read_hints_ms, n_targets);
    return;
  }
  if (slot->state == TCP_SLOT_CONNECT) {
    dbg_service_trace("timeout", slot->ip, slot->item->port, IPPROTO_TCP, "slot=%d fd=%d state=connect timeout_ms=%d", slot->slot_id, slot->fd, slot->timeout_ms);
    tcp_scan_slot_mark_done(slot, ep);
    return;
  }
  if (slot->fd < 0) {
    slot->state = TCP_SLOT_DONE;
    return;
  }
  dbg_service_trace("timeout", slot->ip, slot->item->port, IPPROTO_TCP, "slot=%d fd=%d state=%d timeout_ms=%d", slot->slot_id, slot->fd, (int)slot->state, slot->timeout_ms);
  tcp_scan_slot_finish_plain_without_response(slot, ep, list, out_n);
}
int tcp_scan_slot_timeout_left(const tcp_scan_slot_t *slot, uint64_t now) {
  int left;
  if (!slot) return -1;
  if (slot->state == TCP_SLOT_WEB && slot->web.active) {
    int phase_timeout = slot->web.phase == WEB_PHASE_CONNECT ? web_probe_connect_timeout_ms() : web_probe_effective_io_timeout_ms(&slot->web);
    left = phase_timeout - (int)(now - slot->web.step_started_ms);
    if (left < 0) left = 0;
    return left;
  }
  if (slot->fd < 0) return -1;
  if (slot->deadline_ms > 0) {
    if (now >= slot->deadline_ms) return 0;
    left = (int)(slot->deadline_ms - now);
  } else {
    left = slot->timeout_ms - (int)(now - slot->started_ms);
  }
  if (left < 0) left = 0;
  return left;
}
int tcp_scan_slot_is_pending(const tcp_scan_slot_t *slot) {
  if (!slot) return 0;
  if (slot->state == TCP_SLOT_FREE || slot->state == TCP_SLOT_DONE || slot->state == TCP_SLOT_READY) return 0;
  if (slot->state == TCP_SLOT_WEB && slot->web.active) return 1;
  return slot->fd >= 0;
}
void tcp_scan_handle_pending_timeouts(tcp_scan_slot_t *slots, int max_inflight, int ep, const RemotePorts *prp, const char *public_name, Service *list, int *out_n, uint32_t *host_read_hints_ms, int n_targets) {
  uint64_t now = now_ms();
  for (int i = 0; i < max_inflight; i++) {
    tcp_scan_slot_t *slot = &slots[i];
    if (!tcp_scan_slot_is_pending(slot)) continue;
    int left = tcp_scan_slot_timeout_left(slot, now);
    if (left < 0) {
      slot->state = TCP_SLOT_DONE;
      continue;
    }
    if (left <= 0) tcp_scan_handle_slot_timeout(slot, ep, prp, public_name, list, out_n, host_read_hints_ms, n_targets);
  }
}
static void tcp_scan_handle_plain_read(tcp_scan_slot_t *slot, int ep, const RemotePorts *prp, Service *list, int *out_n, uint32_t *host_read_hints_ms, int n_targets) {
  if (!slot || slot->finished || slot->state != TCP_SLOT_READ || slot->fd < 0) return;
  for (;;) {
    char buf[512];
    ssize_t r = recv(slot->fd, buf, sizeof(buf), 0);
    if (r < 0) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) break;
      dbg_service_trace("read-error", slot->ip, slot->item->port, IPPROTO_TCP, "errno=%d", errno);
      dbg_service_trace("read-eof", slot->ip, slot->item->port, IPPROTO_TCP, "acc_len=%u", (unsigned)slot->acc_len);
      tcp_scan_slot_finish_plain_without_response(slot, ep, list, out_n);
      break;
    }
    if (r == 0) {
      tcp_scan_slot_finish_plain_without_response(slot, ep, list, out_n);
      break;
    }
    if (slot->acc_len == 0) tcp_scan_update_host_read_hint(host_read_hints_ms, n_targets, slot->target_idx, slot->match_started_ms, now_ms());
    uint16_t cur = slot->acc_len;
    uint16_t space = 1023;
    if (cur < space) {
      size_t cpy = (size_t)r;
      if (cpy > (size_t)(space - cur)) cpy = (size_t)(space - cur);
      memcpy(&slot->acc[cur], buf, cpy);
      cur = (uint16_t)(cur + (uint16_t)cpy);
      slot->acc[cur] = 0;
      slot->acc_len = cur;
    }
    dbg_service_trace("read-data", slot->ip, slot->item->port, IPPROTO_TCP, "chunk=%d acc=%u", (int)r, (unsigned)slot->acc_len);
    if (slot->acc_len >= 1023) break;
  }
  if (slot->state == TCP_SLOT_DONE) return;
  if (slot->acc_len == 0) {
    dbg_service_trace("read-empty", slot->ip, slot->item->port, IPPROTO_TCP, "no_response=1");
    tcp_scan_slot_finish_plain_without_response(slot, ep, list, out_n);
    return;
  }
  dbg_service_trace("match", slot->ip, slot->item->port, IPPROTO_TCP, "acc_len=%u", (unsigned)slot->acc_len);
  tcp_probe_publish_service_result(slot, prp, list, out_n);
  tcp_scan_slot_mark_done(slot, ep);
}
static int tcp_scan_handle_plain_connect_phase(tcp_scan_slot_t *slot, int ep, uint32_t events, const RemotePorts *prp, const char *public_name, Service *list, int *out_n, uint32_t *host_read_hints_ms, int n_targets) {
  if (!slot || slot->state != TCP_SLOT_CONNECT) return 0;
  if (!(events & (EPOLLOUT | EPOLLERR | EPOLLHUP))) return 1;
  int err = 0;
  socklen_t elen = sizeof(err);
  if (getsockopt(slot->fd, SOL_SOCKET, SO_ERROR, (char *)&err, &elen) != 0) err = errno;
  if (err != 0) {
    dbg_service_trace("connect-fail", slot->ip, slot->item->port, IPPROTO_TCP, "err=%d", err);
    tcp_scan_slot_mark_done(slot, ep);
    return 1;
  }
  slot->connect_done_ms = now_ms();
  slot->state = TCP_SLOT_READY;
  dbg_service_trace("connect-ok", slot->ip, slot->item->port, IPPROTO_TCP, "slot=%d fd=%d connect_ms=%u events=0x%x", slot->slot_id, slot->fd, tcp_scan_connect_ms(slot), events);
  tcp_scan_slot_publish_connected(slot, ep, prp, public_name, list, out_n, host_read_hints_ms, n_targets);
  if (slot->state == TCP_SLOT_WEB && slot->web.active) {
    if (web_probe_handle_event(&slot->web, ep, slot, events, slot->ip, public_name, &slot->match_started_ms)) return 1;
    tcp_scan_slot_finish_web(slot, ep, prp, list, out_n, host_read_hints_ms, n_targets);
    return 1;
  }
  if (slot->state == TCP_SLOT_DONE || slot->state == TCP_SLOT_READY) return 1;
  return 0;
}
static int tcp_scan_handle_plain_send_phase(tcp_scan_slot_t *slot, int ep, uint32_t events, Service *list, int *out_n) {
  if (!slot || slot->state != TCP_SLOT_SEND) return 0;
  if (events & (EPOLLERR | EPOLLHUP)) {
    tcp_scan_slot_finish_plain_without_response(slot, ep, list, out_n);
    return 1;
  }
  if (!(events & EPOLLOUT)) return 1;
  size_t off = slot->tx_off;
  int rc = tcp_send_all(slot->fd, slot->tx_buf, slot->tx_len, &off);
  if (off > 0 && slot->tx_off == 0) slot->match_started_ms = now_ms();
  slot->tx_off = (uint16_t)off;
  if (rc < 0) {
    dbg_service_trace("send-fail", slot->ip, slot->item->port, IPPROTO_TCP, "sent=%u total=%u errno=%d", (unsigned)slot->tx_off, (unsigned)slot->tx_len, errno);
    tcp_scan_slot_finish_plain_without_response(slot, ep, list, out_n);
    return 1;
  }
  if (slot->tx_off < slot->tx_len) return 1;
  if (!slot->write_shutdown) {
    shutdown(slot->fd, SHUT_WR);
    slot->write_shutdown = 1;
  }
  if (epoll_add_or_mod_ptr(ep, slot->fd, slot, EPOLLIN | EPOLLERR | EPOLLHUP) != 0) {
    dbg_service_trace("epoll-arm-fail", slot->ip, slot->item->port, IPPROTO_TCP, "slot=%d fd=%d errno=%d state=send-done-event", slot->slot_id, slot->fd, errno);
    tcp_scan_slot_finish_plain_without_response(slot, ep, list, out_n);
    return 1;
  }
  slot->epoll_registered = 1;
  slot->state = TCP_SLOT_READ;
  dbg_service_trace("send-done", slot->ip, slot->item->port, IPPROTO_TCP, "slot=%d fd=%d sent=%u", slot->slot_id, slot->fd, (unsigned)slot->tx_off);
  return 1;
}
static void tcp_scan_handle_plain_event(tcp_scan_slot_t *slot, int ep, uint32_t events, const RemotePorts *prp, const char *public_name, Service *list, int *out_n, uint32_t *host_read_hints_ms, int n_targets) {
  if (!slot || slot->finished || slot->state == TCP_SLOT_FREE || slot->state == TCP_SLOT_DONE || slot->fd < 0) return;
  if (slot->state == TCP_SLOT_CONNECT) {
    if (tcp_scan_handle_plain_connect_phase(slot, ep, events, prp, public_name, list, out_n, host_read_hints_ms, n_targets)) return;
  }
  if (slot->state == TCP_SLOT_SEND) {
    if (tcp_scan_handle_plain_send_phase(slot, ep, events, list, out_n)) {
      if (slot->state != TCP_SLOT_READ) return;
    }
  }
  if (slot->state != TCP_SLOT_READ) return;
  if (!(events & (EPOLLIN | EPOLLERR | EPOLLHUP))) return;
  tcp_scan_handle_plain_read(slot, ep, prp, list, out_n, host_read_hints_ms, n_targets);
}
static void tcp_scan_handle_web_event(tcp_scan_slot_t *slot, int ep, uint32_t events, const RemotePorts *prp, const char *public_name, Service *list, int *out_n, uint32_t *host_read_hints_ms, int n_targets) {
  if (!slot || slot->finished || slot->state != TCP_SLOT_WEB || !slot->web.active || slot->web.fd < 0) return;
  dbg_service_trace("web-event", slot->ip, slot->item->port, IPPROTO_TCP, "events=0x%x step=%d phase=%d", events, slot->web.step, slot->web.phase);
  if (web_probe_handle_event(&slot->web, ep, slot, events, slot->ip, public_name, &slot->match_started_ms)) return;
  tcp_scan_slot_finish_web(slot, ep, prp, list, out_n, host_read_hints_ms, n_targets);
}
int tcp_scan_wait_for_events(int ep, tcp_scan_slot_t *slots, int max_inflight, int wait_ms, const RemotePorts *prp, const char *public_name, Service *list, int *out_n, uint32_t *host_read_hints_ms, int n_targets, int max_services) {
  struct epoll_event events[64];
  int nev = epoll_wait(ep, events, (int)(sizeof(events) / sizeof(events[0])), wait_ms);
  if (nev < 0) {
    if (errno == EINTR) return 0;
    return -1;
  }
  if (nev == 0) return 0;
  for (int k = 0; k < nev; k++) {
    tcp_scan_slot_t *slot = (tcp_scan_slot_t *)events[k].data.ptr;
    if (!slot) continue;
    if (slot->finished) continue;
    if (slot->state == TCP_SLOT_WEB) {
      if (!slot->web.active || slot->web.fd < 0) continue;
    } else {
      if (slot->fd < 0) continue;
    }
    dbg_service_trace("event", slot->ip, slot->item ? slot->item->port : 0, IPPROTO_TCP, "slot=%d fd=%d events=0x%x state=%d", slot->slot_id, slot->fd >= 0 ? slot->fd : slot->web.fd, events[k].events, (int)slot->state);
    if (slot->state == TCP_SLOT_WEB) {
      tcp_scan_handle_web_event(slot, ep, events[k].events, prp, public_name, list, out_n, host_read_hints_ms, n_targets);
    } else {
      tcp_scan_handle_plain_event(slot, ep, events[k].events, prp, public_name, list, out_n, host_read_hints_ms, n_targets);
    }
    if (*out_n >= max_services) {
      tcp_scan_cleanup_unused_ready_slots(slots, max_inflight, ep);
      return 1;
    }
  }
  return 0;
}

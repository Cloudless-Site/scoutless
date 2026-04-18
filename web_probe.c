#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include "probes.h"
#include "scan.h"
#include "scan_internal.h"
#include "util.h"
#include "runtime.h"
#include "web_probe_internal.h"

static void web_probe_close_fd(web_probe_ctx_t *ctx, int ep);
static int web_probe_finish_step(web_probe_ctx_t *ctx, int success, int timed_out, const char *ip_str, const char *public_name);

static void web_probe_assert_ctx(const web_probe_ctx_t *ctx) {
  if (!ctx) return;
  SCOUT_ASSERT(ctx->fd >= -1);
  SCOUT_ASSERT(ctx->phase >= WEB_PHASE_IDLE && ctx->phase <= WEB_PHASE_READ);
  SCOUT_ASSERT(ctx->step >= WEB_STEP_HTTP_IP && ctx->step <= WEB_STEP_DONE);
  if (!ctx->active) {
    SCOUT_ASSERT(ctx->fd < 0);
    SCOUT_ASSERT(ctx->phase == WEB_PHASE_IDLE || ctx->step == WEB_STEP_DONE);
  }
  if (ctx->fd >= 0) SCOUT_ASSERT(ctx->active);
  if (ctx->phase == WEB_PHASE_IDLE) SCOUT_ASSERT(ctx->fd < 0 || ctx->reuse_connected_fd);
}

int is_web_candidate_port(int port, const RemotePorts *rp) {
  return tcp_probe_is_web_candidate_remote((uint16_t)port, rp);
}
static int web_probe_step_is_http(web_probe_step_t step) {
  return step == WEB_STEP_HTTP_PUBLIC || step == WEB_STEP_HTTP_IP;
}

static int web_probe_step_is_tls(web_probe_step_t step) {
  return step == WEB_STEP_TLS_IP || step == WEB_STEP_TLS_PUBLIC;
}

static size_t web_probe_escape_ascii(const unsigned char *buf, size_t len, char *out, size_t cap) {
  size_t i;
  size_t o;
  if (!out || cap == 0) return 0;
  out[0] = 0;
  if (!buf || len == 0) return 0;
  o = 0;
  for (i = 0; i < len && o + 1 < cap; i++) {
    unsigned char c;
    c = buf[i];
    if (c == '\r') {
      if (o + 2 >= cap) break;
      out[o++] = '\\';
      out[o++] = 'r';
      continue;
    }
    if (c == '\n') {
      if (o + 2 >= cap) break;
      out[o++] = '\\';
      out[o++] = 'n';
      continue;
    }
    if (c == '\t') {
      if (o + 2 >= cap) break;
      out[o++] = '\\';
      out[o++] = 't';
      continue;
    }
    if (c == '\\') {
      if (o + 2 >= cap) break;
      out[o++] = '\\';
      out[o++] = '\\';
      continue;
    }
    if (c == '"') {
      if (o + 2 >= cap) break;
      out[o++] = '\\';
      out[o++] = '"';
      continue;
    }
    if (isprint(c)) {
      out[o++] = (char)c;
      continue;
    }
    out[o++] = '.';
  }
  out[o] = 0;
  return o;
}
static void web_probe_debug_start(const web_probe_ctx_t *ctx, const char *ip_str, int reused_fd) {
  uint64_t now;
  uint64_t remain;
  if (!ctx || !g_debug) return;
  if (!g_debug_services_all && !debug_service_filter_match(ip_str, ctx->port, IPPROTO_TCP)) return;
  now = now_ms();
  remain = ctx->step_started_ms > now ? ctx->step_started_ms - now : 0;
  dbg_service_trace("web", ip_str, ctx->port, IPPROTO_TCP, "kind=start fd=%d reused_fd=%d step=%d phase=%d tx_len=%zu tx_off=%zu rx_len=%zu deadline_left=%llu", ctx->fd, reused_fd, (int)ctx->step, (int)ctx->phase, ctx->tx_len, ctx->tx_off, ctx->rx_len, (unsigned long long)remain);
}
static void web_probe_debug_event(const web_probe_ctx_t *ctx, const char *ip_str, uint32_t events) {
  if (!ctx || !g_debug) return;
  if (!g_debug_services_all && !debug_service_filter_match(ip_str, ctx->port, IPPROTO_TCP)) return;
  dbg_service_trace("web", ip_str, ctx->port, IPPROTO_TCP, "kind=event events=0x%x in=%d out=%d hup=%d rdhup=%d err=%d fd=%d step=%d phase=%d tx_off=%zu tx_len=%zu rx_len=%zu peer_closed=%d", events, (events & EPOLLIN) != 0, (events & EPOLLOUT) != 0, (events & EPOLLHUP) != 0, (events & EPOLLRDHUP) != 0, (events & EPOLLERR) != 0, ctx->fd, (int)ctx->step, (int)ctx->phase, ctx->tx_off, ctx->tx_len, ctx->rx_len, ctx->peer_closed);
}
static void web_probe_debug_finish(const web_probe_ctx_t *ctx, const char *ip_str, const char *reason) {
  if (!ctx || !g_debug) return;
  if (!g_debug_services_all && !debug_service_filter_match(ip_str, ctx->port, IPPROTO_TCP)) return;
  dbg_service_trace("web", ip_str, ctx->port, IPPROTO_TCP, "kind=finish reason=%s final_type=%d read_timed_out=%d tx_off=%zu tx_len=%zu rx_len=%zu peer_closed=%d", reason ? reason : "", (int)ctx->out.final_type, ctx->read_timed_out, ctx->tx_off, ctx->tx_len, ctx->rx_len, ctx->peer_closed);
}
static void web_probe_debug_read_data(const web_probe_ctx_t *ctx, const char *ip_str, const unsigned char *buf, size_t len) {
  char ascii[512];
  if (!ctx || !g_debug) return;
  if (!g_debug_services_all && !debug_service_filter_match(ip_str, ctx->port, IPPROTO_TCP)) return;
  web_probe_escape_ascii(buf, len, ascii, sizeof(ascii));
  dbg_service_trace("web", ip_str, ctx->port, IPPROTO_TCP, "kind=read-data fd=%d step=%d phase=%d chunk_len=%zu rx_len=%zu ascii=\"%s\"", ctx->fd, (int)ctx->step, (int)ctx->phase, len, ctx->rx_len, ascii);
}
static uint32_t web_probe_epoll_events(const web_probe_ctx_t *ctx) {
  if (!ctx) return EPOLLERR | EPOLLHUP | EPOLLRDHUP;
  if (ctx->phase == WEB_PHASE_READ) return EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
  return EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
}
static void web_probe_close(int ep, web_probe_ctx_t *ctx) {
  int fd;
  if (!ctx) return;
  fd = ctx->fd;
  if (fd < 0) return;
  if (ep >= 0) {
    if (epoll_ctl(ep, EPOLL_CTL_DEL, fd, NULL) != 0) {
      if (errno != ENOENT && errno != EBADF) {
      }
    }
  }
  close(fd);
  ctx->fd = -1;
}
static int web_probe_arm_current_step(web_probe_ctx_t *ctx, int ep, void *epoll_ptr) {
  if (!ctx || ctx->fd < 0) return 0;
  if (epoll_add_or_mod_ptr(ep, ctx->fd, epoll_ptr, web_probe_epoll_events(ctx)) != 0) {
    ctx->active = 0;
    web_probe_close(ep, ctx);
    return 0;
  }
  ctx->active = 1;
  return 1;
}
static int web_probe_restart_or_finish(web_probe_ctx_t *ctx, int ep, void *epoll_ptr, const char *ip_str, const char *public_name, uint64_t *match_started_ms) {
  if (!ctx) return 0;
  if (web_probe_prepare_step(ctx, ip_str, public_name)) {
    if (match_started_ms) *match_started_ms = 0;
    return web_probe_arm_current_step(ctx, ep, epoll_ptr);
  }
  return 0;
}
static int web_probe_continue_after_finish(web_probe_ctx_t *ctx, int ep, void *epoll_ptr, const char *ip_str, const char *public_name, uint64_t *match_started_ms) {
  int fd;
  if (!ctx) return 0;
  if (!web_probe_finish_step(ctx, ctx->recognized, 0, ip_str, public_name)) {
    web_probe_close_fd(ctx, ep);
    return 0;
  }
  if (ctx->reuse_connected_fd && !ctx->peer_closed && ctx->fd >= 0) {
    fd = ctx->fd;
    ctx->fd = -1;
    ctx->active = 0;
    if (web_probe_prepare_step_connected(ctx, fd, ip_str, public_name)) {
      if (match_started_ms) *match_started_ms = 0;
      return web_probe_arm_current_step(ctx, ep, epoll_ptr);
    }
    close(fd);
  }
  web_probe_close_fd(ctx, ep);
  return web_probe_restart_or_finish(ctx, ep, epoll_ptr, ip_str, public_name, match_started_ms);
}
static void web_probe_close_fd(web_probe_ctx_t *ctx, int ep) {
  if (ctx) ctx->active = 0;
  web_probe_close(ep, ctx);
}
static void web_probe_finish_http_step(web_probe_ctx_t *ctx) {
  if (!ctx) return;
  if (ctx->step == WEB_STEP_HTTP_PUBLIC) {
    safe_strncpy(ctx->hp_public.host_value, ctx->step_name, sizeof(ctx->hp_public.host_value));
    finalize_http_probe_reply((const char *)ctx->rx_buf, &ctx->hp_public);
    if (ctx->hp_public.redirect_host[0]) safe_strncpy(ctx->out.redirect_host, ctx->hp_public.redirect_host, sizeof(ctx->out.redirect_host));
    return;
  }
  if (ctx->step == WEB_STEP_HTTP_IP) {
    safe_strncpy(ctx->hp_ip.host_value, ctx->step_name, sizeof(ctx->hp_ip.host_value));
    finalize_http_probe_reply((const char *)ctx->rx_buf, &ctx->hp_ip);
    if (ctx->hp_ip.redirect_host[0]) safe_strncpy(ctx->out.redirect_host, ctx->hp_ip.redirect_host, sizeof(ctx->out.redirect_host));
  }
}
static void web_probe_finish_tls_step(web_probe_ctx_t *ctx) {
  if (!ctx) return;
  if (ctx->step == WEB_STEP_TLS_PUBLIC) finalize_tls_probe_reply(ctx->rx_buf, ctx->rx_len, ctx->step_name, &ctx->tp_public);
  else if (ctx->step == WEB_STEP_TLS_IP) finalize_tls_probe_reply(ctx->rx_buf, ctx->rx_len, ctx->step_name, &ctx->tp_ip);
}
static void web_probe_finish_current_step(web_probe_ctx_t *ctx) {
  if (!ctx) return;
  if (ctx->step == WEB_STEP_HTTP_IP || ctx->step == WEB_STEP_HTTP_PUBLIC) {
    web_probe_finish_http_step(ctx);
    return;
  }
  if (ctx->step == WEB_STEP_TLS_IP || ctx->step == WEB_STEP_TLS_PUBLIC) web_probe_finish_tls_step(ctx);
}
static void web_probe_prepare_http_name(web_probe_ctx_t *ctx, const char *ip_str, const char *public_name) {
  if (!ctx) return;
  if (ctx->step == WEB_STEP_HTTP_PUBLIC) safe_strncpy(ctx->step_name, public_name, sizeof(ctx->step_name));
  else if (ctx->step == WEB_STEP_HTTP_IP) safe_strncpy(ctx->step_name, ip_str, sizeof(ctx->step_name));
}
static void web_probe_prepare_tls_name(web_probe_ctx_t *ctx, const char *ip_str, const char *public_name) {
  if (!ctx) return;
  if (ctx->step == WEB_STEP_TLS_IP) safe_strncpy(ctx->step_name, ip_str, sizeof(ctx->step_name));
  else if (ctx->step == WEB_STEP_TLS_PUBLIC) safe_strncpy(ctx->step_name, public_name, sizeof(ctx->step_name));
}
static int web_probe_prepare_http_request(web_probe_ctx_t *ctx) {
  if (!ctx) return 0;
  if (!ctx->http_try_with_host) {
    if (!ctx->step_name[0]) return 0;
    ctx->tx_len = (size_t)snprintf(ctx->tx_buf, sizeof(ctx->tx_buf), "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Scoutless/2.0\r\n\r\n", ctx->step_name);
  } else {
    if (!ctx->step_name[0]) return 0;
    ctx->tx_len = (size_t)snprintf(ctx->tx_buf, sizeof(ctx->tx_buf), "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Scoutless/2.0\r\n\r\n", ctx->step_name);
  }
  if (ctx->tx_len == 0 || ctx->tx_len >= sizeof(ctx->tx_buf)) return 0;
  return 1;
}
static int web_probe_prepare_tls_request(web_probe_ctx_t *ctx) {
  if (!ctx) return 0;
  ctx->tx_len = build_tls_client_hello((unsigned char *)ctx->tx_buf, sizeof(ctx->tx_buf), ctx->step_name[0] ? ctx->step_name : NULL);
  if (ctx->tx_len == 0) return 0;
  return 1;
}
static int web_probe_prepare_step_common(web_probe_ctx_t *ctx, const char *ip_str, const char *public_name) {
  if (!ctx || !ip_str) return 0;
  if (ctx->step == WEB_STEP_DONE) return 0;
  ctx->tx_len = 0;
  ctx->tx_off = 0;
  ctx->rx_len = 0;
  ctx->recognized = 0;
  ctx->read_timed_out = 0;
  ctx->reuse_connected_fd = 0;
  ctx->peer_closed = 0;
  ctx->step_name[0] = 0;
  if (web_probe_step_is_http(ctx->step)) {
    if (ctx->step == WEB_STEP_HTTP_IP) ctx->http_try_with_host = 0;
    else if (ctx->step == WEB_STEP_HTTP_PUBLIC) ctx->http_try_with_host = 1;
    web_probe_prepare_http_name(ctx, ip_str, public_name);
    if (!web_probe_prepare_http_request(ctx)) return 0;
  } else if (web_probe_step_is_tls(ctx->step)) {
    web_probe_prepare_tls_name(ctx, ip_str, public_name);
    if (!web_probe_prepare_tls_request(ctx)) return 0;
  } else {
    return 0;
  }
  return 1;
}
int web_probe_prepare_step(web_probe_ctx_t *ctx, const char *ip_str, const char *public_name) {
  web_probe_assert_ctx(ctx);
  int immediate_ok = 0;
  if (ctx && ctx->step == WEB_STEP_HTTP_IP) {
    web_probe_clear_final_candidate(ctx);
    ctx->http_try_with_host = 0;
  }
  if (!web_probe_prepare_step_common(ctx, ip_str, public_name)) return 0;
  uint64_t t_connect_start;
  ctx->fd = tcp_connect_single_nb(ip_str, ctx->port, &immediate_ok);
  if (ctx->fd < 0) return 0;
  ctx->phase = immediate_ok ? WEB_PHASE_SEND : WEB_PHASE_CONNECT;
  t_connect_start = now_ms();
  ctx->step_started_ms = t_connect_start;
  web_probe_debug_start(ctx, ip_str, 0);
  return 1;
}
int web_probe_prepare_step_connected(web_probe_ctx_t *ctx, int fd, const char *ip_str, const char *public_name) {
  web_probe_assert_ctx(ctx);
  if (ctx && ctx->step == WEB_STEP_HTTP_IP) {
    web_probe_clear_final_candidate(ctx);
    ctx->http_try_with_host = 0;
  }
  if (!web_probe_prepare_step_common(ctx, ip_str, public_name)) return 0;
  if (fd < 0) return 0;
  uint64_t t_connect_end;
  ctx->fd = fd;
  ctx->phase = WEB_PHASE_SEND;
  t_connect_end = now_ms();
  ctx->step_started_ms = t_connect_end;
  web_probe_debug_start(ctx, ip_str, 1);
  return 1;
}
static int web_probe_finish_step(web_probe_ctx_t *ctx, int success, int timed_out, const char *ip_str, const char *public_name) {
  web_probe_assert_ctx(ctx);
  web_step_result_t result;
  web_probe_step_t next_step;
  int garbage;
  if (!ctx) return 0;
  garbage = 0;
  if (!success && ctx->rx_len > 0) {
    if (ctx->step == WEB_STEP_HTTP_IP || ctx->step == WEB_STEP_HTTP_PUBLIC) garbage = parse_http_status((const char *)ctx->rx_buf) == 0;
    else if (ctx->step == WEB_STEP_TLS_IP || ctx->step == WEB_STEP_TLS_PUBLIC) garbage = tls_probe_reply_kind(ctx->rx_buf, ctx->rx_len) == TLS_PROBE_REPLY_NONE;
  }
  if (success) web_probe_finish_current_step(ctx);
  result = web_probe_classify_result(ctx, timed_out, garbage);
  if (result == WEB_STEP_RESULT_STRONG) {
    web_probe_candidate_t current_candidate;
    web_probe_clear_weak_candidate(ctx);
    if (web_probe_make_current_candidate(ctx, &current_candidate)) web_probe_commit_candidate(ctx, &current_candidate);
    else ctx->step = WEB_STEP_DONE;
  } else if (result == WEB_STEP_RESULT_WEAK) {
    web_probe_store_weak_candidate(ctx);
    next_step = web_probe_next_step_for_result(ctx, result, ip_str, public_name);
    if (ctx->step == WEB_STEP_HTTP_IP && next_step == WEB_STEP_HTTP_PUBLIC && !ctx->peer_closed && web_probe_http_allows_reuse(&ctx->hp_ip, ctx->rx_buf, ctx->rx_len)) ctx->reuse_connected_fd = 1;
    if (next_step == WEB_STEP_DONE) web_probe_promote_weak(ctx);
    else ctx->step = next_step;
  } else if (result == WEB_STEP_RESULT_TIMEOUT) {
    if (ctx->weak_candidate.active) web_probe_promote_weak(ctx);
    else ctx->step = WEB_STEP_DONE;
  } else {
    if (ctx->weak_candidate.active) web_probe_promote_weak(ctx);
    else {
      next_step = web_probe_next_step_for_result(ctx, result, ip_str, public_name);
      ctx->step = next_step;
    }
  }
  if (ctx->step == WEB_STEP_DONE) finalize_web_probe_result(ctx, ip_str);
  web_probe_assert_ctx(ctx);
  return ctx->step != WEB_STEP_DONE;
}

int web_probe_handle_timeout(web_probe_ctx_t *ctx, int ep, void *epoll_ptr, const char *ip_str, const char *public_name, uint64_t *match_started_ms) {
  web_probe_assert_ctx(ctx);
  int success;
  if (!ctx || !ctx->active) return 0;
  success = 0;
  if (ctx->phase == WEB_PHASE_READ) {
    success = web_probe_buffer_recognized(ctx->step, ctx->rx_buf, ctx->rx_len);
    ctx->read_timed_out = success ? 0 : 1;
  }
  web_probe_close_fd(ctx, ep);
  if (web_probe_finish_step(ctx, success, 1, ip_str, public_name)) {
    web_probe_debug_finish(ctx, ip_str, "timeout");
    return web_probe_restart_or_finish(ctx, ep, epoll_ptr, ip_str, public_name, match_started_ms);
  }
  web_probe_debug_finish(ctx, ip_str, "timeout");
  return 0;
}
static void web_probe_handle_connect_phase(web_probe_ctx_t *ctx, int ep, void *epoll_ptr, int *finished, int *saw_err, const char **finish_reason) {
  int err;
  socklen_t elen;
  uint64_t t_connect_end;
  if (!ctx || !finished || *finished || ctx->phase != WEB_PHASE_CONNECT) return;
  err = 0;
  elen = sizeof(err);
  if (getsockopt(ctx->fd, SOL_SOCKET, SO_ERROR, (char *)&err, &elen) != 0) err = errno;
  if (err != 0) {
    *saw_err = 1;
    *finish_reason = "epoll_error";
    *finished = 1;
    return;
  }
  ctx->phase = WEB_PHASE_SEND;
  t_connect_end = now_ms();
  ctx->step_started_ms = t_connect_end;
  if (epoll_mod_ptr(ep, ctx->fd, epoll_ptr, EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLRDHUP) != 0) {
    *saw_err = 1;
    *finish_reason = "epoll_error";
    *finished = 1;
  }
}
static void web_probe_note_first_send(const web_probe_ctx_t *ctx, uint64_t *match_started_ms) {
  uint64_t t_first_byte;
  if (!ctx || !match_started_ms || ctx->tx_off != 0) return;
  t_first_byte = now_ms();
  *match_started_ms = t_first_byte;
}
static void web_probe_handle_send_phase(web_probe_ctx_t *ctx, int ep, void *epoll_ptr, uint32_t events, const char *ip_str, uint64_t *match_started_ms, int *finished, int *saw_err, const char **finish_reason) {
  if (!ctx || !finished || *finished || ctx->phase != WEB_PHASE_SEND) return;
  if ((events & (EPOLLHUP | EPOLLRDHUP | EPOLLERR)) || !(events & EPOLLOUT)) return;
  while (ctx->tx_off < ctx->tx_len) {
    int send_flags;
    ssize_t wr;
    send_flags = 0;
#ifdef MSG_NOSIGNAL
    send_flags |= MSG_NOSIGNAL;
#endif
    wr = send(ctx->fd, ctx->tx_buf + ctx->tx_off, ctx->tx_len - ctx->tx_off, send_flags);
    if (wr < 0) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        dbg_service_trace("web", ip_str, ctx->port, IPPROTO_TCP, "kind=send state=eagain fd=%d step=%d phase=%d tx_off=%zu tx_len=%zu", ctx->fd, (int)ctx->step, (int)ctx->phase, ctx->tx_off, ctx->tx_len);
        break;
      }
      *finish_reason = "send_error";
      *finished = 1;
      break;
    }
    if (wr == 0) {
      *finish_reason = "send_error";
      *finished = 1;
      break;
    }
    dbg_service_trace("web", ip_str, ctx->port, IPPROTO_TCP, "kind=send bytes=%zd fd=%d step=%d phase=%d tx_off_before=%zu tx_len=%zu", wr, ctx->fd, (int)ctx->step, (int)ctx->phase, ctx->tx_off, ctx->tx_len);
    web_probe_note_first_send(ctx, match_started_ms);
    ctx->tx_off += (size_t)wr;
    dbg_service_trace("web", ip_str, ctx->port, IPPROTO_TCP, "kind=send-progress fd=%d step=%d phase=%d tx_off=%zu tx_len=%zu", ctx->fd, (int)ctx->step, (int)ctx->phase, ctx->tx_off, ctx->tx_len);
  }
  if (*finished || ctx->tx_off < ctx->tx_len) return;
  dbg_service_trace("web", ip_str, ctx->port, IPPROTO_TCP, "kind=send state=complete fd=%d step=%d phase=%d", ctx->fd, (int)ctx->step, (int)ctx->phase);
  ctx->phase = WEB_PHASE_READ;
  ctx->step_started_ms = now_ms();
  if (epoll_mod_ptr(ep, ctx->fd, epoll_ptr, EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP) != 0) {
    *saw_err = 1;
    *finish_reason = "epoll_error";
    *finished = 1;
  }
}
static void web_probe_finalize_read_phase(web_probe_ctx_t *ctx, int *finished, int *recognized, const char **finish_reason) {
  if (!ctx || !finished || !recognized || !*finished) return;
  if (!*recognized) *recognized = web_probe_buffer_useful(ctx->step, ctx->rx_buf, ctx->rx_len);
  ctx->recognized = *recognized;
  if (*recognized) *finish_reason = "parse_match";
  else if (!*finish_reason && ctx->rx_len == 0) *finish_reason = "no_data";
  else if (!*finish_reason) *finish_reason = "parse_no_match";
}
static void web_probe_handle_read_phase(web_probe_ctx_t *ctx, uint32_t events, const char *ip_str, int *finished, int *recognized, int *saw_hup, int *saw_rdhup, int *saw_err, const char **finish_reason) {
  if (!ctx || !finished || !recognized || !saw_hup || !saw_rdhup || !saw_err || *finished || ctx->phase != WEB_PHASE_READ) return;
  if (!(events & (EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP))) return;
  *saw_hup = (events & EPOLLHUP) != 0;
  *saw_rdhup = (events & EPOLLRDHUP) != 0;
  *saw_err = (events & EPOLLERR) != 0;
  if (*saw_hup || *saw_rdhup) ctx->peer_closed = 1;
  if (*saw_hup || *saw_rdhup) ctx->phase = WEB_PHASE_READ;
  for (;;) {
    ssize_t r;
    if (ctx->rx_len + 1 >= sizeof(ctx->rx_buf)) {
      *finish_reason = "parse_no_match";
      *finished = 1;
      break;
    }
    r = recv(ctx->fd, ctx->rx_buf + ctx->rx_len, sizeof(ctx->rx_buf) - ctx->rx_len - 1, 0);
    if (r < 0) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        dbg_service_trace("web", ip_str, ctx->port, IPPROTO_TCP, "kind=read state=eagain fd=%d step=%d phase=%d rx_len=%zu", ctx->fd, (int)ctx->step, (int)ctx->phase, ctx->rx_len);
        break;
      }
      *finish_reason = "read_error";
      *finished = 1;
      break;
    }
    if (r == 0) {
      ctx->peer_closed = 1;
      *finish_reason = ctx->rx_len > 0 ? "eof" : "eof_no_data";
      *finished = 1;
      dbg_service_trace("web", ip_str, ctx->port, IPPROTO_TCP, "kind=read state=eof fd=%d step=%d phase=%d rx_len=%zu", ctx->fd, (int)ctx->step, (int)ctx->phase, ctx->rx_len);
      break;
    }
    ctx->rx_len += (size_t)r;
    ctx->rx_buf[ctx->rx_len] = 0;
    dbg_service_trace("web", ip_str, ctx->port, IPPROTO_TCP, "kind=read bytes=%zd fd=%d step=%d phase=%d rx_len=%zu", r, ctx->fd, (int)ctx->step, (int)ctx->phase, ctx->rx_len);
    web_probe_debug_read_data(ctx, ip_str, ctx->rx_buf + ctx->rx_len - (size_t)r, (size_t)r);
    if (web_probe_buffer_recognized(ctx->step, ctx->rx_buf, ctx->rx_len)) {
      *finished = 1;
      *recognized = 1;
      break;
    }
  }
  if ((*saw_hup || *saw_rdhup || *saw_err) && !*finished) {
    *finished = 1;
    if (ctx->rx_len == 0) {
      if (*saw_rdhup) *finish_reason = "hup_before_data";
      else if (*saw_hup) *finish_reason = "hup_before_data";
      else *finish_reason = "epoll_error";
    } else if (*saw_rdhup) *finish_reason = "rdhup_after_data";
    else if (*saw_hup) *finish_reason = "eof";
    else *finish_reason = "epoll_error";
  }
  web_probe_finalize_read_phase(ctx, finished, recognized, finish_reason);
}
int web_probe_handle_event(web_probe_ctx_t *ctx, int ep, void *epoll_ptr, uint32_t events, const char *ip_str, const char *public_name, uint64_t *match_started_ms) {
  web_probe_assert_ctx(ctx);
  int finished;
  int recognized;
  int saw_hup;
  int saw_rdhup;
  int saw_err;
  const char *finish_reason;
  if (!ctx || !ctx->active || ctx->fd < 0) return 0;
  finished = 0;
  recognized = 0;
  saw_hup = 0;
  saw_rdhup = 0;
  saw_err = 0;
  finish_reason = NULL;
  web_probe_debug_event(ctx, ip_str, events);
  web_probe_handle_connect_phase(ctx, ep, epoll_ptr, &finished, &saw_err, &finish_reason);
  web_probe_handle_send_phase(ctx, ep, epoll_ptr, events, ip_str, match_started_ms, &finished, &saw_err, &finish_reason);
  web_probe_handle_read_phase(ctx, events, ip_str, &finished, &recognized, &saw_hup, &saw_rdhup, &saw_err, &finish_reason);
  if (!finished) return 1;
  if (web_probe_continue_after_finish(ctx, ep, epoll_ptr, ip_str, public_name, match_started_ms)) {
    web_probe_debug_finish(ctx, ip_str, finish_reason);
    return 1;
  }
  web_probe_debug_finish(ctx, ip_str, finish_reason);
  return 0;
}

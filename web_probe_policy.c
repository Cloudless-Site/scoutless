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

void web_probe_promote_weak(web_probe_ctx_t *ctx) {
  if (!ctx || !ctx->weak_candidate.active) return;
  if (ctx->weak_candidate.step == WEB_STEP_HTTP_IP) ctx->hp_ip.accepted = 1;
  else if (ctx->weak_candidate.step == WEB_STEP_HTTP_PUBLIC) ctx->hp_public.accepted = 1;
  else if (ctx->weak_candidate.step == WEB_STEP_TLS_IP) ctx->tp_ip.accepted = 1;
  else if (ctx->weak_candidate.step == WEB_STEP_TLS_PUBLIC) ctx->tp_public.accepted = 1;
  web_probe_commit_candidate(ctx, &ctx->weak_candidate);
  web_probe_clear_weak_candidate(ctx);
}
void finalize_web_probe_result(web_probe_ctx_t *ctx, const char *ip_str) {
  const web_probe_candidate_t *candidate;
  WebProbeResult *out;
  int port;
  if (!ctx) return;
  out = &ctx->out;
  port = ctx->port;
  memset(out, 0, sizeof(*out));
  candidate = ctx->final_candidate.active ? &ctx->final_candidate : NULL;
  if (candidate && candidate->type == SRV_HTTP) {
    out->http_ok = 1;
    out->http_status = candidate->status;
    out->final_type = SRV_HTTP;
    safe_strncpy(out->host_value, candidate->value, sizeof(out->host_value));
    if (candidate->redirect_host[0]) safe_strncpy(out->redirect_host, candidate->redirect_host, sizeof(out->redirect_host));
  } else if (candidate && candidate->type == SRV_HTTPS) {
    out->https_ok = 1;
    out->final_type = SRV_HTTPS;
    safe_strncpy(out->sni_value, candidate->value, sizeof(out->sni_value));
  } else {
    out->final_type = SRV_TCP;
  }
  if (!out->redirect_host[0] && ctx->hp_ip.redirect_host[0]) safe_strncpy(out->redirect_host, ctx->hp_ip.redirect_host, sizeof(out->redirect_host));
  if (!out->redirect_host[0] && ctx->hp_public.redirect_host[0]) safe_strncpy(out->redirect_host, ctx->hp_public.redirect_host, sizeof(out->redirect_host));
  make_web_hint(out->svc_hint, sizeof(out->svc_hint), out->final_type, out->host_value[0] ? out->host_value : NULL, out->sni_value[0] ? out->sni_value : NULL);
  if (g_debug && (g_debug_services_all || debug_service_filter_match(ip_str, port, IPPROTO_TCP))) {
    char http_s[32];
    char https_s[32];
    if (out->http_ok) snprintf(http_s, sizeof(http_s), "%d", out->http_status);
    else safe_strncpy(http_s, "fail", sizeof(http_s));
    if (out->https_ok) safe_strncpy(https_s, "ok", sizeof(https_s));
    else safe_strncpy(https_s, "fail", sizeof(https_s));
    dbg_service_trace("web", ip_str, port, IPPROTO_TCP, "kind=result http=%s https=%s final_type=%d", http_s, https_s, (int)out->final_type);
    if (out->redirect_host[0]) dbg_service_trace("web", ip_str, port, IPPROTO_TCP, "kind=result redirect_host=%s", out->redirect_host);
    if (out->svc_hint[0]) dbg_service_trace("web", ip_str, port, IPPROTO_TCP, "kind=result svc_hint=%s", out->svc_hint);
  }
}
static int web_probe_has_public_name(const char *ip_str, const char *public_name) {
  if (!public_name || !*public_name) return 0;
  if (ip_str && strcmp(public_name, ip_str) == 0) return 0;
  return 1;
}
static int http_probe_is_accepted(const HttpProbe *hp) {
  if (!hp) return 0;
  return hp->score >= 2 || hp->accepted;
}
static int http_probe_is_strong(const HttpProbe *hp) {
  if (!hp || !hp->parsed) return 0;
  if (hp->score == HTTP_PROBE_SCORE_GOOD) return 1;
  return 0;
}
static int http_probe_is_weak(const HttpProbe *hp) {
  if (!hp || !hp->parsed) return 0;
  return !http_probe_is_strong(hp);
}
static int tls_is_modern_enough(const TlsProbe *tp) {
  if (!tp || !tp->ok) return 0;
  if (tp->proto_major != 3) return 0;
  return tp->proto_minor >= 3;
}
static int tls_probe_is_strong(const TlsProbe *tp) {
  return tls_is_modern_enough(tp);
}
static int tls_probe_is_weak(const TlsProbe *tp) {
  if (!tp) return 0;
  return (tp->ok || tp->alert) && !tls_probe_is_strong(tp);
}
static web_step_result_t web_probe_http_result(const HttpProbe *hp, int timed_out, int garbage) {
  if (timed_out) return WEB_STEP_RESULT_TIMEOUT;
  if (!hp || !hp->parsed) {
    if (garbage) return WEB_STEP_RESULT_GARBAGE;
    return WEB_STEP_RESULT_FAIL;
  }
  if (http_probe_is_strong(hp)) return WEB_STEP_RESULT_STRONG;
  if (http_probe_is_weak(hp)) return WEB_STEP_RESULT_WEAK;
  return WEB_STEP_RESULT_FAIL;
}
static web_step_result_t web_probe_tls_result(const TlsProbe *tp, int timed_out, int garbage) {
  if (timed_out) return WEB_STEP_RESULT_TIMEOUT;
  if (!tp || (!tp->ok && !tp->alert)) {
    if (garbage) return WEB_STEP_RESULT_GARBAGE;
    return WEB_STEP_RESULT_FAIL;
  }
  if (tls_probe_is_strong(tp)) return WEB_STEP_RESULT_STRONG;
  if (tls_probe_is_weak(tp)) return WEB_STEP_RESULT_WEAK;
  return WEB_STEP_RESULT_FAIL;
}
web_step_result_t web_probe_classify_result(const web_probe_ctx_t *ctx, int timed_out, int garbage) {
  if (!ctx) return WEB_STEP_RESULT_FAIL;
  if (ctx->step == WEB_STEP_HTTP_IP) return web_probe_http_result(&ctx->hp_ip, timed_out, garbage);
  if (ctx->step == WEB_STEP_HTTP_PUBLIC) return web_probe_http_result(&ctx->hp_public, timed_out, garbage);
  if (ctx->step == WEB_STEP_TLS_IP) return web_probe_tls_result(&ctx->tp_ip, timed_out, garbage);
  if (ctx->step == WEB_STEP_TLS_PUBLIC) return web_probe_tls_result(&ctx->tp_public, timed_out, garbage);
  return WEB_STEP_RESULT_FAIL;
}
int web_probe_make_http_candidate(const HttpProbe *hp, web_probe_step_t step, web_probe_candidate_t *out) {
  if (!out) return 0;
  memset(out, 0, sizeof(*out));
  if (!hp || !http_probe_is_accepted(hp) || !hp->host_value[0]) return 0;
  out->active = 1;
  out->step = step;
  out->type = SRV_HTTP;
  out->status = hp->status;
  safe_strncpy(out->value, hp->host_value, sizeof(out->value));
  if (hp->redirect_host[0]) safe_strncpy(out->redirect_host, hp->redirect_host, sizeof(out->redirect_host));
  return 1;
}
static int web_probe_make_tls_candidate(const TlsProbe *tp, web_probe_step_t step, web_probe_candidate_t *out) {
  if (!out) return 0;
  memset(out, 0, sizeof(*out));
  if (!tp || (!tls_is_modern_enough(tp) && !tp->accepted) || !tp->sni_value[0]) return 0;
  out->active = 1;
  out->step = step;
  out->type = SRV_HTTPS;
  safe_strncpy(out->value, tp->sni_value, sizeof(out->value));
  return 1;
}
int web_probe_make_current_candidate(const web_probe_ctx_t *ctx, web_probe_candidate_t *out) {
  if (!ctx || !out) return 0;
  if (ctx->step == WEB_STEP_HTTP_IP) return web_probe_make_http_candidate(&ctx->hp_ip, WEB_STEP_HTTP_IP, out);
  if (ctx->step == WEB_STEP_HTTP_PUBLIC) return web_probe_make_http_candidate(&ctx->hp_public, WEB_STEP_HTTP_PUBLIC, out);
  if (ctx->step == WEB_STEP_TLS_IP) return web_probe_make_tls_candidate(&ctx->tp_ip, WEB_STEP_TLS_IP, out);
  if (ctx->step == WEB_STEP_TLS_PUBLIC) return web_probe_make_tls_candidate(&ctx->tp_public, WEB_STEP_TLS_PUBLIC, out);
  memset(out, 0, sizeof(*out));
  return 0;
}
void web_probe_clear_final_candidate(web_probe_ctx_t *ctx) {
  if (!ctx) return;
  memset(&ctx->final_candidate, 0, sizeof(ctx->final_candidate));
}
void web_probe_commit_candidate(web_probe_ctx_t *ctx, const web_probe_candidate_t *candidate) {
  if (!ctx || !candidate || !candidate->active) return;
  ctx->final_candidate = *candidate;
  ctx->step = WEB_STEP_DONE;
}
void web_probe_clear_weak_candidate(web_probe_ctx_t *ctx) {
  if (!ctx) return;
  memset(&ctx->weak_candidate, 0, sizeof(ctx->weak_candidate));
}
void web_probe_store_weak_candidate(web_probe_ctx_t *ctx) {
  if (!ctx) return;
  web_probe_clear_weak_candidate(ctx);
  ctx->weak_candidate.active = 1;
  ctx->weak_candidate.step = ctx->step;
  if (ctx->step == WEB_STEP_HTTP_IP) {
    ctx->weak_candidate.type = SRV_HTTP;
    ctx->weak_candidate.status = ctx->hp_ip.status;
    safe_strncpy(ctx->weak_candidate.value, ctx->hp_ip.host_value, sizeof(ctx->weak_candidate.value));
    safe_strncpy(ctx->weak_candidate.redirect_host, ctx->hp_ip.redirect_host, sizeof(ctx->weak_candidate.redirect_host));
    return;
  }
  if (ctx->step == WEB_STEP_HTTP_PUBLIC) {
    ctx->weak_candidate.type = SRV_HTTP;
    ctx->weak_candidate.status = ctx->hp_public.status;
    safe_strncpy(ctx->weak_candidate.value, ctx->hp_public.host_value, sizeof(ctx->weak_candidate.value));
    safe_strncpy(ctx->weak_candidate.redirect_host, ctx->hp_public.redirect_host, sizeof(ctx->weak_candidate.redirect_host));
    return;
  }
  if (ctx->step == WEB_STEP_TLS_IP) {
    ctx->weak_candidate.type = SRV_HTTPS;
    safe_strncpy(ctx->weak_candidate.value, ctx->tp_ip.sni_value, sizeof(ctx->weak_candidate.value));
    return;
  }
  if (ctx->step == WEB_STEP_TLS_PUBLIC) {
    ctx->weak_candidate.type = SRV_HTTPS;
    safe_strncpy(ctx->weak_candidate.value, ctx->tp_public.sni_value, sizeof(ctx->weak_candidate.value));
    return;
  }
  web_probe_clear_weak_candidate(ctx);
}
void make_web_hint(char *out, size_t cap, ServiceType t, const char *host, const char *sni) {
  if (!out || cap == 0) return;
  out[0] = 0;
  if (t == SRV_HTTP) safe_strncpy(out, "/svc/http", cap);
  else if (t == SRV_HTTPS) safe_strncpy(out, "/svc/https", cap);
  if (out[0] == 0) return;
  if (t == SRV_HTTP) {
    if (host && *host) {
      size_t n = strlen(out);
      snprintf(out + n, cap - n, "?host=%s", host);
    }
    return;
  }
  if (t != SRV_HTTPS) return;
  if (sni && *sni) {
    size_t n = strlen(out);
    snprintf(out + n, cap - n, "?sni=%s", sni);
  }
}
web_probe_step_t web_probe_next_step_for_result(const web_probe_ctx_t *ctx, web_step_result_t result, const char *ip_str, const char *public_name) {
  if (!ctx) return WEB_STEP_DONE;
  if (result == WEB_STEP_RESULT_TIMEOUT) return WEB_STEP_DONE;
  if (result == WEB_STEP_RESULT_STRONG) return WEB_STEP_DONE;
  switch (ctx->step) {
    case WEB_STEP_HTTP_IP:
      if (result == WEB_STEP_RESULT_WEAK || result == WEB_STEP_RESULT_FAIL) {
        if (web_probe_has_public_name(ip_str, public_name)) return WEB_STEP_HTTP_PUBLIC;
        if (ctx->stop_after_http) return WEB_STEP_DONE;
        return WEB_STEP_TLS_IP;
      }
      if (result == WEB_STEP_RESULT_GARBAGE) {
        if (ctx->stop_after_http) return WEB_STEP_DONE;
        return WEB_STEP_TLS_IP;
      }
      return WEB_STEP_DONE;
    case WEB_STEP_HTTP_PUBLIC:
      if (result == WEB_STEP_RESULT_WEAK || result == WEB_STEP_RESULT_FAIL || result == WEB_STEP_RESULT_GARBAGE) {
        if (ctx->stop_after_http) return WEB_STEP_DONE;
        return WEB_STEP_TLS_IP;
      }
      return WEB_STEP_DONE;
    case WEB_STEP_TLS_IP:
      if (result == WEB_STEP_RESULT_WEAK || result == WEB_STEP_RESULT_FAIL) {
        if (web_probe_has_public_name(ip_str, public_name)) return WEB_STEP_TLS_PUBLIC;
        return WEB_STEP_DONE;
      }
      return WEB_STEP_DONE;
    case WEB_STEP_TLS_PUBLIC:
    default:
      return WEB_STEP_DONE;
  }
}

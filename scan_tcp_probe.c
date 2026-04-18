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
#include "scan.h"
#include "discover_policy.h"
#include "scan_internal.h"
#include "scan_tcp_internal.h"

void tcp_scan_update_host_read_hint(uint32_t *host_read_hints_ms, int n_targets, int target_idx, uint64_t match_started_ms, uint64_t now) {
  if (!host_read_hints_ms || target_idx < 0 || target_idx >= n_targets) return;
  if (match_started_ms == 0 || now <= match_started_ms) return;
  uint32_t delta_ms = tcp_scan_elapsed_ms(match_started_ms, now);
  if (delta_ms == 0) return;
  if (host_read_hints_ms[target_idx] == 0 || delta_ms < host_read_hints_ms[target_idx]) host_read_hints_ms[target_idx] = delta_ms;
}
int tcp_scan_host_read_timeout_ms(int base_timeout_ms, uint32_t hint_ms) {
  if (base_timeout_ms <= 0) return base_timeout_ms;
  if (hint_ms == 0) return base_timeout_ms;
  int timeout_ms = (int)(hint_ms * 3U) + 150;
  if (timeout_ms < 250) timeout_ms = 250;
  if (timeout_ms > base_timeout_ms) timeout_ms = base_timeout_ms;
  return timeout_ms;
}
ServiceType default_tcp_type_for_port(int port, const char **out_name) {
  const tcp_probe_def_t *pd = tcp_probe_find((uint16_t)port);
  const char *nm = (pd && pd->name) ? pd->name : NULL;
  tcp_web_policy_t policy = tcp_probe_web_policy((uint16_t)port);
  if (out_name) *out_name = nm ? nm : "unknown";
  if (policy == TCP_WEB_POLICY_HTTP_ONLY) return SRV_HTTP;
  if (policy == TCP_WEB_POLICY_TLS_ONLY || policy == TCP_WEB_POLICY_HTTP_TLS) return SRV_HTTPS;
  if (nm) {
    if (strcmp(nm, "http") == 0) return SRV_HTTP;
    if (strcmp(nm, "https") == 0) return SRV_HTTPS;
  }
  return SRV_TCP;
}
static int tcp_probe_copy_vendor(unsigned char *out, size_t cap, const struct vendor_probe *vp) {
  if (!out || !vp) return -1;
  if (vp->send_is_hex && vp->send_hex_len) {
    if (vp->send_hex_len > cap) return -1;
    memcpy(out, vp->send_hex, vp->send_hex_len);
    return (int)vp->send_hex_len;
  }
  if (!vp->send_text[0]) return 0;
  size_t n = strlen(vp->send_text);
  if (n > cap) return -1;
  memcpy(out, vp->send_text, n);
  return (int)n;
}
static int tcp_probe_build_http(unsigned char *out, size_t cap, const char *host) {
  const char *use_host = (host && host[0]) ? host : "127.0.0.1";
  size_t req_len = (size_t)snprintf((char *)out, cap, "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: ServiceScanner/1.0\r\n\r\n", use_host);
  if (req_len == 0 || req_len >= cap) return -1;
  return (int)req_len;
}
static int tcp_probe_build_tls_hello(unsigned char *out, size_t cap) {
  static const unsigned char ch[] = { 0x16,0x03,0x01,0x00,0x2e,0x01,0x00,0x00,0x2a,0x03,0x03, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x02,0x00,0x2f,0x01,0x00 };
  if (sizeof(ch) > cap) return -1;
  memcpy(out, ch, sizeof(ch));
  return (int)sizeof(ch);
}
static int tcp_probe_build_default(unsigned char *out, size_t cap, int port) {
  const tcp_probe_def_t *pd = tcp_probe_find((uint16_t)port);
  if (pd) {
    if (pd->probe_kind == PROBE_STATIC_PAYLOAD && pd->payload) {
      size_t len = pd->payload_len ? (size_t)pd->payload_len : strlen((const char *)pd->payload);
      if (len > cap) return -1;
      memcpy(out, pd->payload, len);
      return (int)len;
    }
    if (pd->probe_kind == PROBE_BUILDER && pd->build_fn) {
      struct sockaddr_in dst = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port) };
      int n = pd->build_fn((char *)out, cap, &dst, port);
      if (n <= 0 || (size_t)n > cap) return -1;
      return n;
    }
  }
  if (cap == 0) return -1;
  out[0] = 0;
  return 1;
}
int tcp_probe_build_request(unsigned char *out, size_t cap, const char *host, int port, const PlanItem *it, const RemotePorts *rp) {
  tcp_web_policy_t web_policy;
  if (it && it->is_vendor_probe && it->vp) return tcp_probe_copy_vendor(out, cap, it->vp);
  web_policy = tcp_probe_web_policy_remote((uint16_t)port, rp);
  if (web_policy == TCP_WEB_POLICY_HTTP_ONLY || web_policy == TCP_WEB_POLICY_HTTP_TLS)
    return tcp_probe_build_http(out, cap, host);
  if (web_policy == TCP_WEB_POLICY_TLS_ONLY)
    return tcp_probe_build_tls_hello(out, cap);
  return tcp_probe_build_default(out, cap, port);
}
static ServiceInfoType service_type_from_probe_name(const char *name) {
  if (!name) return SERVICE_UNKNOWN;
  if (strcmp(name, "http") == 0) return SERVICE_HTTP;
  if (strcmp(name, "https") == 0) return SERVICE_HTTPS;
  return SERVICE_UNKNOWN;
}
void analyze_tcp_response(int port, const char *buf, size_t len, ServiceInfo *si) {
  memset(si, 0, sizeof(*si));
  safe_strncpy(si->banner, buf, sizeof(si->banner));
  const tcp_probe_def_t *pd = tcp_probe_find((uint16_t)port);
  if (!strncmp(buf, "SSH-", 4)) {
    si->type = SERVICE_SSH; strcpy(si->name, "ssh"); si->confidence = 0.95f; return;
  }
  if (len >= 6 && (unsigned char)buf[0] == 0x16 && ((unsigned char)buf[1] == 0x03 || (unsigned char)buf[1] == 0x02) && (unsigned char)buf[5] == 0x02) {
    si->type = SERVICE_HTTPS; strcpy(si->name, "https"); si->confidence = 0.95f; return;
  }
  if (len > 0 && buf[0] == '+' && contains_ci_n(buf, len, "PONG")) {
    si->type = SERVICE_REDIS; strcpy(si->name, "redis"); si->confidence = 0.95f; return;
  }
  if (pd && pd->name && !strcmp(pd->name,"mongodb") && len > 16 && buf[12] == 0x01 && buf[13] == 0x00) {
    si->type = SERVICE_MONGODB; strcpy(si->name,"mongodb"); si->confidence = 0.95f; return;
  }
  if (pd && pd->name && !strcmp(pd->name,"postgresql") && len == 1 && (buf[0] == 'S' || buf[0] == 'N')) {
    si->type = SERVICE_POSTGRESQL; strcpy(si->name,"postgresql"); si->confidence = 0.95f; return;
  }
  if (len > 5 && buf[4] == 0x0a && (contains_ci_n(buf, len, "mysql_native_password") || contains_ci_n(buf, len, "mariadb") || contains_ci_n(buf + 5, len - 5, "8.0.") || contains_ci_n(buf + 5, len - 5, "5.7."))) {
    si->type = SERVICE_MYSQL; strcpy(si->name,"mysql"); si->confidence = 0.95f; return;
  }
  match_signatures(si->banner, si);
  if (si->type != SERVICE_UNKNOWN) return;
  if (pd && pd->match_kind != MATCH_NONE) {
    if (pd->match_kind == MATCH_PREFIX && pd->match_data) {
      size_t ml = strlen(pd->match_data);
      if (len >= ml && !memcmp(buf, pd->match_data, ml)) {
        strcpy(si->name, pd->name ? pd->name : "tcp");
        si->type = service_type_from_probe_name(pd->name);
        si->confidence = 0.80f; return;
      }
    } else if (pd->match_kind == MATCH_SUBSTR && pd->match_data) {
      if (contains_ci_n(buf, len, pd->match_data)) {
        strcpy(si->name, pd->name ? pd->name : "tcp");
        si->type = service_type_from_probe_name(pd->name);
        si->confidence = 0.80f; return;
      }
    }
  }
  if (contains_ci_n(buf, len, "HTTP/")) {
    si->type = SERVICE_HTTP; strcpy(si->name,"http"); si->confidence = 0.85f; return;
  }
  ServiceInfoType iot = detect_iot_protocol((const unsigned char *)buf, len, port);
  if (iot != SERVICE_UNKNOWN) {
    si->type = iot;
    strcpy(si->name, service_to_string(iot));
    si->confidence = 0.85f; return;
  }
  if (pd && pd->name) {
    strcpy(si->name, pd->name);
    si->type = tcp_probe_web_policy((uint16_t)port) == TCP_WEB_POLICY_TLS_ONLY ? SERVICE_HTTPS : SERVICE_UNKNOWN;
    si->confidence = 0.60f;
  }
}


#pragma once
#include <stddef.h>
#include <stdint.h>
typedef enum {
  PROBE_NONE = 0,
  PROBE_STATIC_PAYLOAD = 1,
  PROBE_BUILDER = 2,
} probe_kind_t;
typedef enum {
  MATCH_NONE = 0,
  MATCH_SUBSTR = 1,
  MATCH_PREFIX = 2,
} match_kind_t;
enum {
  PROBE_F_TLS_HINT      = 1u << 0,
  PROBE_F_EXPECT_BINARY = 1u << 1,
  PROBE_F_BANNER_ONLY   = 1u << 2,
  PROBE_F_WEB_GET       = 1u << 3,
};
struct sockaddr_in;
typedef struct RemotePorts RemotePorts;
typedef int (*probe_build_fn_t)(char *out, size_t cap, const struct sockaddr_in *dst, int port);
typedef struct {
  uint16_t port;
  const char *name;
  const char *label_prefix;
  probe_kind_t probe_kind;
  const unsigned char *payload;
  uint16_t payload_len;
  probe_build_fn_t build_fn;
  match_kind_t match_kind;
  const char *match_data;
  uint32_t flags;
} tcp_probe_def_t;
typedef struct {
  uint16_t port;
  const char *name;
  const char *label_prefix;
  probe_kind_t probe_kind;
  const unsigned char *payload;
  uint16_t payload_len;
  probe_build_fn_t build_fn;
  match_kind_t match_kind;
  const char *match_data;
  uint32_t flags;
} udp_probe_def_t;
extern const tcp_probe_def_t tcp_probes[];
extern const size_t tcp_probes_len;
extern const udp_probe_def_t udp_probes[];
extern const size_t udp_probes_len;
typedef enum {
  TCP_WEB_POLICY_NONE = 0,
  TCP_WEB_POLICY_HTTP_ONLY = 1,
  TCP_WEB_POLICY_HTTP_TLS = 2,
  TCP_WEB_POLICY_TLS_ONLY = 3
} tcp_web_policy_t;
const tcp_probe_def_t *tcp_probe_find(uint16_t port);
const udp_probe_def_t *udp_probe_find(uint16_t port);
tcp_web_policy_t tcp_probe_web_policy(uint16_t port);
tcp_web_policy_t tcp_probe_web_policy_remote(uint16_t port, const RemotePorts *rp);
int tcp_probe_is_web_candidate_remote(uint16_t port, const RemotePorts *rp);
int tcp_probe_stop_after_http_remote(uint16_t port, const RemotePorts *rp);

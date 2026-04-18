#pragma once
#include <stddef.h>
#include <stdint.h>
#include "vendor.h"
#include "web_probe.h"
typedef enum {
  HTTP_PROBE_SCORE_NONE = 0,
  HTTP_PROBE_SCORE_WEAK = 1,
  HTTP_PROBE_SCORE_PARTIAL = 2,
  HTTP_PROBE_SCORE_OK = 3,
  HTTP_PROBE_SCORE_GOOD = 4,
  HTTP_PROBE_SCORE_REDIRECT_HTTPS = 5
} http_probe_score_t;
typedef enum {
  TLS_PROBE_REPLY_NONE = 0,
  TLS_PROBE_REPLY_SERVER_HELLO = 1,
  TLS_PROBE_REPLY_ALERT = 2
} tls_probe_reply_t;
typedef struct {
  int parsed;
  int status;
  int score;
  int accepted;
  int redirect_https;
  char host_value[128];
  char redirect_host[128];
} HttpProbe;
typedef struct {
  int ok;
  int alert;
  int accepted;
  int proto_major;
  int proto_minor;
  char sni_value[128];
  char alpn[32];
} TlsProbe;
typedef enum {
  WEB_STEP_HTTP_IP = 1,
  WEB_STEP_HTTP_PUBLIC = 2,
  WEB_STEP_TLS_IP = 3,
  WEB_STEP_TLS_PUBLIC = 4,
  WEB_STEP_DONE = 5
} web_probe_step_t;
typedef enum {
  WEB_PHASE_IDLE = 0,
  WEB_PHASE_CONNECT = 1,
  WEB_PHASE_SEND = 2,
  WEB_PHASE_READ = 3
} web_probe_phase_t;
typedef struct {
  int active;
  web_probe_step_t step;
  ServiceType type;
  int status;
  char value[128];
  char redirect_host[128];
} web_probe_candidate_t;
typedef struct {
  int active;
  int fd;
  int port;
  web_probe_step_t step;
  web_probe_phase_t phase;
  uint64_t step_started_ms;
  int io_timeout_ms;
  int recognized;
  int stop_after_http;
  int read_timed_out;
  int reuse_connected_fd;
  int peer_closed;
  int http_try_with_host;
  char step_name[128];
  char tx_buf[512];
  size_t tx_len;
  size_t tx_off;
  unsigned char rx_buf[1024];
  size_t rx_len;
  HttpProbe hp_public;
  HttpProbe hp_ip;
  TlsProbe tp_public;
  TlsProbe tp_ip;
  web_probe_candidate_t weak_candidate;
  web_probe_candidate_t final_candidate;
  WebProbeResult out;
} web_probe_ctx_t;
typedef enum {
  WEB_STEP_RESULT_FAIL = 0,
  WEB_STEP_RESULT_STRONG = 1,
  WEB_STEP_RESULT_WEAK = 2,
  WEB_STEP_RESULT_GARBAGE = 3,
  WEB_STEP_RESULT_TIMEOUT = 4
} web_step_result_t;
int web_probe_connect_timeout_ms(void);
int web_probe_io_timeout_ms(void);
int web_probe_effective_io_timeout_ms(const web_probe_ctx_t *ctx);
int is_web_candidate_port(int port, const RemotePorts *rp);
int parse_http_status(const char *buf);
int web_probe_prepare_step(web_probe_ctx_t *ctx, const char *ip_str, const char *public_name);
int web_probe_prepare_step_connected(web_probe_ctx_t *ctx, int fd, const char *ip_str, const char *public_name);
int web_probe_handle_event(web_probe_ctx_t *ctx, int ep, void *epoll_ptr, uint32_t events, const char *ip_str, const char *public_name, uint64_t *match_started_ms);
int web_probe_handle_timeout(web_probe_ctx_t *ctx, int ep, void *epoll_ptr, const char *ip_str, const char *public_name, uint64_t *match_started_ms);
size_t build_tls_client_hello(unsigned char *out, size_t cap, const char *sni);
void finalize_http_probe_reply(const char *buf, HttpProbe *out);
void finalize_tls_probe_reply(const unsigned char *buf, size_t len, const char *sni, TlsProbe *out);
int web_probe_buffer_recognized(web_probe_step_t step, const unsigned char *buf, size_t len);
int web_probe_buffer_useful(web_probe_step_t step, const unsigned char *buf, size_t len);
int web_probe_http_allows_reuse(const HttpProbe *hp, const unsigned char *buf, size_t len);
tls_probe_reply_t tls_probe_reply_kind(const unsigned char *buf, size_t len);
void make_web_hint(char *out, size_t cap, ServiceType t, const char *host, const char *sni);
void web_probe_commit_candidate(web_probe_ctx_t *ctx, const web_probe_candidate_t *candidate);
void web_probe_clear_weak_candidate(web_probe_ctx_t *ctx);
void web_probe_store_weak_candidate(web_probe_ctx_t *ctx);
void web_probe_clear_final_candidate(web_probe_ctx_t *ctx);
web_step_result_t web_probe_classify_result(const web_probe_ctx_t *ctx, int timed_out, int garbage);
int web_probe_make_http_candidate(const HttpProbe *hp, web_probe_step_t step, web_probe_candidate_t *out);
int web_probe_make_current_candidate(const web_probe_ctx_t *ctx, web_probe_candidate_t *out);
web_probe_step_t web_probe_next_step_for_result(const web_probe_ctx_t *ctx, web_step_result_t result, const char *ip_str, const char *public_name);
void finalize_web_probe_result(web_probe_ctx_t *ctx, const char *ip_str);
void web_probe_promote_weak(web_probe_ctx_t *ctx);

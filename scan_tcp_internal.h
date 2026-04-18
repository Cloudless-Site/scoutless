#pragma once
#include "scan.h"
#include "scan_internal.h"
#include "proto.h"
#include "web_probe_internal.h"
typedef struct {
  int any_pending;
  int has_ready;
  int wait_ms;
} tcp_scan_wait_state_t;
typedef enum {
  TCP_CONNECT_MODE_NORMAL = 0,
  TCP_CONNECT_MODE_VENDOR_FALLBACK
} tcp_connect_mode_t;
typedef struct {
  tcp_slot_state_t state;
  int fd;
  char acc[1024];
  uint16_t acc_len;
  uint64_t started_ms;
  uint64_t service_started_ms;
  uint64_t match_started_ms;
  uint64_t connect_done_ms;
  uint64_t deadline_ms;
  int timeout_ms;
  int target_idx;
  const char *ip;
  const PlanItem *item;
  int slot_id;
  uint8_t connect_mode;
  uint8_t finished;
  uint8_t epoll_registered;
  uint8_t write_shutdown;
  unsigned char tx_buf[640];
  uint16_t tx_len;
  uint16_t tx_off;
  web_probe_ctx_t web;
} tcp_scan_slot_t;
int tcp_scan_find_free_slot(tcp_scan_slot_t *slots,int max_inflight);
void tcp_scan_slot_publish_connected_result(tcp_scan_slot_t *slot, Service *list, int *out_n);
void tcp_scan_slot_publish_connected(tcp_scan_slot_t *slot, int ep, const RemotePorts *rp, const char *public_name, Service *list, int *out_n, uint32_t *host_read_hints_ms, int n_targets);
void tcp_scan_handle_slot_timeout(tcp_scan_slot_t *slot, int ep, const RemotePorts *prp, const char *public_name, Service *list, int *out_n, uint32_t *host_read_hints_ms, int n_targets);
void tcp_scan_reclaim_done_slots(tcp_scan_slot_t *slots, int max_inflight, int ep);
void tcp_scan_handle_pending_timeouts(tcp_scan_slot_t *slots, int max_inflight, int ep, const RemotePorts *prp, const char *public_name, Service *list, int *out_n, uint32_t *host_read_hints_ms, int n_targets);
int tcp_scan_wait_for_events(int ep, tcp_scan_slot_t *slots, int max_inflight, int wait_ms, const RemotePorts *prp, const char *public_name, Service *list, int *out_n, uint32_t *host_read_hints_ms, int n_targets, int max_services);
void tcp_scan_slot_mark_done(tcp_scan_slot_t *slot, int ep);
int tcp_scan_slot_timeout_left(const tcp_scan_slot_t *slot, uint64_t now);
int tcp_scan_prepare_slot(tcp_scan_slot_t *slot, int ep, const ScanTarget *target, PlanItem *item, int *out_err);
int tcp_scan_slot_is_pending(const tcp_scan_slot_t *slot);
void tcp_scan_slot_reset(tcp_scan_slot_t *slot, int ep);
uint32_t tcp_scan_elapsed_ms(uint64_t started_ms, uint64_t ended_ms);
void tcp_scan_publish_ready_slots(tcp_scan_slot_t *slots, int max_inflight, int ep, const RemotePorts *rp, const char *public_name, Service *list, int *out_n, uint32_t *host_read_hints_ms, int n_targets, int max_services);
void tcp_scan_cleanup_unused_ready_slots(tcp_scan_slot_t *slots, int max_inflight, int ep);
void analyze_tcp_response(int port, const char *buf, size_t len, ServiceInfo *si);
int tcp_probe_build_request(unsigned char *out, size_t cap, const char *host, int port, const PlanItem *it, const RemotePorts *rp);
void tcp_scan_update_host_read_hint(uint32_t *host_read_hints_ms, int n_targets, int target_idx, uint64_t match_started_ms, uint64_t now);
int tcp_scan_host_read_timeout_ms(int base_timeout_ms, uint32_t hint_ms);
ServiceType default_tcp_type_for_port(int port, const char **out_name);

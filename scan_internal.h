#pragma once
static inline int scan_next_pair(int *port_idx, int *host_idx, int n_ports, int n_hosts, int *out_port_idx, int *out_host_idx) {
  if (!port_idx || !host_idx || !out_port_idx || !out_host_idx) return 0;
  if (*port_idx < 0 || *host_idx < 0 || n_ports <= 0 || n_hosts <= 0) return 0;
  if (*port_idx >= n_ports) return 0;
  *out_port_idx = *port_idx;
  *out_host_idx = *host_idx;
  (*host_idx)++;
  if (*host_idx >= n_hosts) {
    *host_idx = 0;
    (*port_idx)++;
  }
  return 1;
}
static inline int scan_has_more_pairs(int port_idx, int host_idx, int n_ports, int n_hosts) {
  if (n_ports <= 0 || n_hosts <= 0) return 0;
  if (port_idx < 0 || host_idx < 0) return 0;
  if (port_idx >= n_ports) return 0;
  return 1;
}
int tcp_connect_single_nb(const char *ip_str, int port, int *immediate_ok);
typedef enum {
  TCP_SLOT_FREE = 0,
  TCP_SLOT_CONNECT,
  TCP_SLOT_READY,
  TCP_SLOT_SEND,
  TCP_SLOT_READ,
  TCP_SLOT_WEB,
  TCP_SLOT_DONE
} tcp_slot_state_t;

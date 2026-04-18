#pragma once
#include <stddef.h>
#include "scoutless.h"
#define MAX_REMOTE_PORTS 128
struct vendor_probe {
  int   proto;
  int   port;
  ServiceType forced_type;
  int   force;
  float conf;
  int   wait_ms;
  int   send_is_hex;
  char  send_text[256];
  unsigned char send_hex[256];
  size_t send_hex_len;
  char  expect_substr[128];
  size_t expect_hex_len;
  unsigned char expect_hex[128];
  int   expect_is_hex;
};
typedef struct RemotePorts {
  int tcp_allow[MAX_REMOTE_PORTS];
  int udp_allow[MAX_REMOTE_PORTS];
  int tcp_force[MAX_REMOTE_PORTS];
  int udp_force[MAX_REMOTE_PORTS];
  int tcp_http[MAX_REMOTE_PORTS];
  int tcp_https[MAX_REMOTE_PORTS];
  int n_tcp_allow, n_udp_allow, n_tcp_force, n_udp_force;
  int n_tcp_http,  n_tcp_https;
  struct vendor_probe probes[MAX_REMOTE_PORTS];
  int n_probes;
} RemotePorts;
int remote_ports_has(const int *arr, int n, int port);
void remote_ports_add(int *arr, int *n, int port);
int vendor_probe_expect_match(const struct vendor_probe *vp, const char *buf, size_t len);

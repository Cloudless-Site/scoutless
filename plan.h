#pragma once
#include <stddef.h>
#include "scoutless.h"
#include "vendor.h"
#define PLAN_MAX_PORTS 512
#define PLAN_MAX_PROBES 512
typedef struct PlanItem {
  int         proto;
  int         port;
  ServiceType forced;
  int         force_publish;
  int         is_vendor_probe;
  const struct vendor_probe *vp;
} PlanItem;
typedef struct UdpPlanItem {
  int         port;
  ServiceType forced;
  int         force_publish;
  int         is_vendor_probe;
  const struct vendor_probe *vp;
} UdpPlanItem;
typedef struct {
  int proto;
  int port;
  char name[64];
  ServiceType type;
  int force_publish;
  int has_probe;
  int send_is_hex;
  char send_text[256];
  unsigned char send_hex[256];
  size_t send_hex_len;
  int expect_is_hex;
  unsigned char expect_hex[128];
  size_t expect_hex_len;
  char expect_substr[128];
} PlanPort;
typedef struct {
  PlanPort ports[PLAN_MAX_PORTS];
  int n_ports;
  int loaded;
} ScanPlan;
int plan_load(const char *path, ScanPlan *out);
void plan_build(const ScanPlan *plan, PlanItem *tcp_flat, PlanItem **tcp_ptrs, int *tcp_n, UdpPlanItem *udp_items, int *udp_n, struct vendor_probe *probe_store, int probe_store_cap);

#define _POSIX_C_SOURCE 200809L
#include "scoutless.h"
#include "runtime.h"
#include "discover_run.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"
#include "util_net.h"
#include "plan.h"
int g_debug = 0;
uint64_t g_discovery_started_ms = 0;
char g_probe_public_domain[128] = "g-12345.cloudless.site";
uint32_t g_runtime_burst_override = 0;
uint32_t g_runtime_epoll_override = 0;
uint32_t g_runtime_pacing_override_us = 0;
int g_debug_services_all = 0;
int g_tcp_liveness_disabled = 0;
int g_icmp_liveness_disabled = 0;

static void slugify_name(char *dst, size_t dst_sz, const char *src) {
  if (!dst || dst_sz == 0) return;
  dst[0] = 0;
  if (!src || !*src) return;
  size_t j = 0;
  for (size_t i = 0; src[i] && j + 1 < dst_sz; i++) {
    unsigned char c = (unsigned char)src[i];
    if (c >= 'A' && c <= 'Z') c = (unsigned char)(c - 'A' + 'a');
    if ((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'||c=='_') dst[j++]=(char)c;
    else if (c==' '||c=='\t'||c=='\r'||c=='\n') dst[j++]='-';
    else dst[j++]='_';
  }
  dst[j] = 0;
  size_t w = 0;
  for (size_t r = 0; dst[r]; r++) {
    if (dst[r]=='-' && w>0 && dst[w-1]=='-') continue;
    dst[w++] = dst[r];
  }
  dst[w] = 0;
}
static const char *scheme_from_type(ServiceType t) {
  switch (t) {
    case SRV_HTTP:  return "http";
    case SRV_HTTPS: return "https";
    case SRV_UDP:   return "udp";
    case SRV_TCP:
    default:        return "tcp";
  }
}
static int service_type_rank(ServiceType t) {
  switch (t) {
    case SRV_HTTPS: return 0;
    case SRV_HTTP: return 1;
    case SRV_TCP: return 2;
    case SRV_UDP: return 3;
    default: return 4;
  }
}
static int service_ip_key(const char *ip, uint32_t *out) {
  struct in_addr addr;
  if (!ip || !out) return 0;
  if (inet_pton(AF_INET, ip, &addr) != 1) return 0;
  *out = ntohl(addr.s_addr);
  return 1;
}
static int compare_service_ip(const char *ipa_str, const char *ipb_str) {
  uint32_t ipa = 0;
  uint32_t ipb = 0;
  int has_ipa = service_ip_key(ipa_str, &ipa);
  int has_ipb = service_ip_key(ipb_str, &ipb);
  if (has_ipa && has_ipb) {
    if (ipa < ipb) return -1;
    if (ipa > ipb) return 1;
    return 0;
  }
  return strcmp(ipa_str, ipb_str);
}
static int compare_services(const void *a, const void *b) {
  const Service *sa = (const Service *)a;
  const Service *sb = (const Service *)b;
  int ip_cmp = compare_service_ip(sa->ip, sb->ip);
  int rank_a = service_type_rank(sa->type);
  int rank_b = service_type_rank(sb->type);
  if (ip_cmp != 0) return ip_cmp;
  if (rank_a < rank_b) return -1;
  if (rank_a > rank_b) return 1;
  if (sa->local_port < sb->local_port) return -1;
  if (sa->local_port > sb->local_port) return 1;
  return strcmp(sa->name, sb->name);
}
static void print_pseudo_url(const Service *s) {
  const char *scheme;
  char slug[96];
  if (!s) return;
  scheme = scheme_from_type(s->type);
  if (s->type == SRV_HTTP)
    safe_strncpy(slug, "http", sizeof(slug));
  else if (s->type == SRV_HTTPS)
    safe_strncpy(slug, "https", sizeof(slug));
  else
    slugify_name(slug, sizeof(slug), s->name);
  if (s->svc_hint[0])
    printf("%s://%s:%d%s\n", scheme, s->ip, s->local_port, s->svc_hint);
  else if (slug[0])
    printf("%s://%s:%d/svc/%s\n", scheme, s->ip, s->local_port, slug);
  else
    printf("%s://%s:%d\n", scheme, s->ip, s->local_port);
}
static void scoutless_apply_network_overrides(const char *gateway_override,
                                              const char *local_ip_override,
                                              int cidr_override) {
  if (gateway_override) util_set_gateway_override(gateway_override);
  if (local_ip_override) util_set_local_ip_override(local_ip_override);
  if (cidr_override >= 0) util_set_cidr_override(cidr_override);
}
static int scoutless_load_debug_service_filter(const char *debug_services_path) {
  if (!debug_services_path) return 1;
  if (debug_service_filter_load(debug_services_path) < 0) {
    fprintf(stderr, "debug-services-file: cannot open %s\n", debug_services_path);
    return 0;
  }
  g_debug = 1;
  return 1;
}
static void scoutless_apply_runtime_overrides(uint32_t burst_override,
                                              uint32_t epoll_override,
                                              uint32_t pacing_override_us) {
  g_runtime_burst_override = burst_override;
  g_runtime_epoll_override = epoll_override;
  g_runtime_pacing_override_us = pacing_override_us;
}
static void scoutless_parse_args(int argc, char **argv,
                                 const char **plan_path,
                                 const char **gateway_override,
                                 const char **local_ip_override,
                                 int *cidr_override,
                                 const char **debug_services_path,
                                 uint32_t *burst_override,
                                 uint32_t *epoll_override,
                                 uint32_t *pacing_override_us,
                                 int *force_large_net) {
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i],"--debug"))
      g_debug = 3;
    else if (!strcmp(argv[i],"--plan") && i+1 < argc)
      *plan_path = argv[++i];
    else if (!strcmp(argv[i],"--public-domain") && i+1 < argc)
      safe_strncpy(g_probe_public_domain, argv[++i], sizeof(g_probe_public_domain));
    else if (!strcmp(argv[i],"--gateway") && i + 1 < argc)
      *gateway_override = argv[++i];
    else if (!strcmp(argv[i],"--ip") && i + 1 < argc)
      *local_ip_override = argv[++i];
    else if (!strcmp(argv[i],"--cidr") && i + 1 < argc)
      *cidr_override = (int)strtol(argv[++i], NULL, 10);
    else if (!strcmp(argv[i],"--debug-services-file") && i + 1 < argc)
      *debug_services_path = argv[++i];
    else if (!strcmp(argv[i],"--disable-tcp-liveness"))
      g_tcp_liveness_disabled = 1;
    else if (!strcmp(argv[i],"--disable-icmp-liveness"))
      g_icmp_liveness_disabled = 1;
    else if (!strcmp(argv[i],"--debug-services-all"))
      g_debug = g_debug_services_all = 1;
    else if (!strcmp(argv[i],"--deeper")) {
      *burst_override = 32;
      *epoll_override = 32;
      *pacing_override_us = 20000;
    } else if (!strcmp(argv[i],"--aggressive")) {
      *burst_override = 1024;
      *epoll_override = 1024;
      *pacing_override_us = 2;
    }
    else if (!strcmp(argv[i],"--burst") && i + 1 < argc)
      *burst_override = (uint32_t)strtoul(argv[++i], NULL, 10);
    else if (!strcmp(argv[i],"--epoll") && i + 1 < argc)
      *epoll_override = (uint32_t)strtoul(argv[++i], NULL, 10);
    else if (!strcmp(argv[i],"--pacing") && i + 1 < argc)
      *pacing_override_us = (uint32_t)strtoul(argv[++i], NULL, 10);
    else if (!strcmp(argv[i],"--force-large-net"))
      *force_large_net = 1;
  }
}
static int scoutless_try_load_plan(const char *plan_path,
                                   ScanPlan *plan,
                                   PlanItem *tcp_flat,
                                   PlanItem **tcp_ptrs,
                                   int *tcp_n,
                                   UdpPlanItem *udp_items,
                                   int *udp_n,
                                   struct vendor_probe *vp_store) {
  int has_plan = 0;
  memset(plan, 0, sizeof(*plan));
  if (!plan_path) return 0;
  has_plan = plan_load(plan_path, plan);
  if (has_plan && plan->n_ports == 0) {
    fprintf(stderr, "plan: missing ports\n");
    has_plan = 0;
  }
  if (has_plan)
    plan_build(plan, tcp_flat, tcp_ptrs, tcp_n, udp_items, udp_n, vp_store, PLAN_MAX_PROBES);
  return has_plan;
}
static void scoutless_print_services(Service *services, int srv_count) {
  qsort(services, (size_t)srv_count, sizeof(services[0]), compare_services);
  for (int i = 0; i < srv_count; i++)
    print_pseudo_url(&services[i]);
}
int main(int argc, char **argv) {
  const char *plan_path = NULL;
  const char *gateway_override = NULL;
  const char *local_ip_override = NULL;
  const char *debug_services_path = NULL;
  int cidr_override = -1;
  uint32_t burst_override = 0;
  uint32_t epoll_override = 0;
  uint32_t pacing_override_us = 0;
  int force_large_net = 0;
  ScanPlan plan;
  PlanItem *tcp_flat;
  PlanItem **tcp_ptrs;
  UdpPlanItem *udp_items;
  struct vendor_probe *vp_store;
  int tcp_n = 0;
  int udp_n = 0;
  int has_plan;
  RemotePorts rp;
  Service services[MAX_SERVICES];
  int srv_count;
  scoutless_parse_args(argc, argv, &plan_path, &gateway_override, &local_ip_override,
                       &cidr_override, &debug_services_path, &burst_override,
                       &epoll_override, &pacing_override_us, &force_large_net);
  scoutless_apply_network_overrides(gateway_override, local_ip_override, cidr_override);
  if (!scoutless_load_debug_service_filter(debug_services_path)) return 1;
  scoutless_apply_runtime_overrides(burst_override, epoll_override, pacing_override_us);
  tcp_flat = calloc(PLAN_MAX_PORTS, sizeof(*tcp_flat));
  tcp_ptrs = calloc(PLAN_MAX_PORTS, sizeof(*tcp_ptrs));
  udp_items = calloc(PLAN_MAX_PORTS, sizeof(*udp_items));
  vp_store = calloc(PLAN_MAX_PROBES, sizeof(*vp_store));
  if (!tcp_flat || !tcp_ptrs || !udp_items || !vp_store) {
    free(vp_store);
    free(udp_items);
    free(tcp_ptrs);
    free(tcp_flat);
    return 1;
  }
  has_plan = scoutless_try_load_plan(plan_path, &plan, tcp_flat, tcp_ptrs, &tcp_n, udp_items, &udp_n, vp_store);
  memset(&rp, 0, sizeof(rp));
  srv_count = run_discovery(services, &rp,
                            has_plan ? tcp_ptrs : NULL, has_plan ? tcp_n : 0,
                            has_plan ? udp_items : NULL, has_plan ? udp_n : 0,
                            force_large_net);
  scoutless_print_services(services, srv_count);
  free(vp_store);
  free(udp_items);
  free(tcp_ptrs);
  free(tcp_flat);
  return 0;
}

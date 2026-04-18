#include "util.h"
#include "util_net.h"
#include <netinet/tcp.h>
#include "scoutless.h"
#include "discover_net.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <resolv.h>
#include <stdarg.h>
#include <strings.h>
#ifdef __ANDROID__
#include <sys/system_properties.h>
#endif
static char g_gateway_override[64];
static char g_local_ip_override[64];
static int g_cidr_override = -1;

int iface_rank(const char *iface) {
  if (!iface || !*iface) return 0;
  if (strncmp(iface, "wlan", 4) == 0) return 1000;
  if (strncmp(iface, "wifi", 4) == 0) return 850;
  if (strncmp(iface, "wlp1s0", 4) == 0) return 850;
  if (strncmp(iface, "eth", 3) == 0) return 800;
  if (strncmp(iface, "enp7s0", 3) == 0) return 800;
  if (strncmp(iface, "en", 2) == 0) return 760;
  if (strncmp(iface, "bridge", 6) == 0) return 450;
  if (strncmp(iface, "br", 2) == 0) return 420;
  if (strncmp(iface, "rmnet", 5) == 0) return 80;
  if (strncmp(iface, "ccmni", 5) == 0) return 70;
  if (strncmp(iface, "tun", 3) == 0) return 20;
  if (strncmp(iface, "ppp", 3) == 0) return 20;
  return 100;
}
static uint32_t read_default_gateway_route(char *iface_out, size_t iface_out_sz) {
  uint32_t best_gw = 0;
  int best_score = -100000;
  FILE *f = fopen("/proc/net/route", "r");
  if (iface_out && iface_out_sz) iface_out[0] = 0;
  if (!f) return 0;
  char line[256];
  while (fgets(line, sizeof(line), f)) {
    char iface[64];
    unsigned int dest;
    unsigned int gateway;
    unsigned int flags;
    unsigned int metric;
    if (sscanf(line, "%63s %x %x %x %*s %*s %u", iface, &dest, &gateway, &flags, &metric) != 5) continue;
    if (dest != 0 || gateway == 0) continue;
    if (!(flags & 0x2u)) continue;
    int score = iface_rank(iface) - (int)metric;
    if (score <= best_score) continue;
    best_score = score;
    best_gw = ntohl((uint32_t)gateway);
    if (iface_out && iface_out_sz) safe_strncpy(iface_out, iface, iface_out_sz);
  }
  fclose(f);
  return best_gw;
}
uint32_t get_default_gateway_iface(char *iface, size_t iface_sz) {
  uint32_t gw = read_default_gateway_route(iface, iface_sz);
#ifdef __ANDROID__
  if (gw == 0) {
    char prop_val[PROP_VALUE_MAX];
    const char *keys[] = {"dhcp.wlan0.gateway", "dhcp.eth0.gateway", "net.wlan0.gw", "net.eth0.gw"};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
      struct in_addr ia;
      if (__system_property_get(keys[i], prop_val) <= 0) continue;
      if (inet_pton(AF_INET, prop_val, &ia) != 1) continue;
      gw = ntohl(ia.s_addr);
      break;
    }
  }
#endif
  return gw;
}
uint32_t get_default_gateway(void) {
  struct in_addr ia;
  char ip_str[64];
  unsigned int a;
  unsigned int b;
  unsigned int c;
  unsigned int d;
  if (g_gateway_override[0]) {
    if (inet_pton(AF_INET, g_gateway_override, &ia) == 1) return ntohl(ia.s_addr);
    return 0;
  }
  ia.s_addr = htonl(get_default_gateway_iface(NULL, 0));
  if (ia.s_addr != 0) return ntohl(ia.s_addr);
  if (get_local_ip(ip_str, sizeof(ip_str)) == 0) {
    if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
      char gw_str[64];
      snprintf(gw_str, sizeof(gw_str), "%u.%u.%u.1", a, b, c);
      if (inet_pton(AF_INET, gw_str, &ia) == 1) return ntohl(ia.s_addr);
    }
  }
  return 0;
}
static uint32_t parse_resolv_conf_dns(void) {
  uint32_t dns = 0;
  FILE *f = fopen("/etc/resolv.conf", "r");
  if (!f) return 0;
  char line[256];
  while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "nameserver", 10) != 0) continue;
    {
      char ip_str[64];
      struct in_addr ia;
      if (sscanf(line + 10, " %63s", ip_str) != 1) continue;
      if (inet_pton(AF_INET, ip_str, &ia) != 1) continue;
      dns = ntohl(ia.s_addr);
      break;
    }
  }
  fclose(f);
  return dns;
}
uint32_t get_local_dns(void) {
  uint32_t dns;
  dns = parse_resolv_conf_dns();
  if (dns) return dns;
#ifdef __ANDROID__
  {
    char prop_val[PROP_VALUE_MAX];
    const char *keys[] = {"net.dns1", "net.dns2", "dhcp.wlan0.dns1", "dhcp.eth0.dns1"};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
      struct in_addr ia;
      if (__system_property_get(keys[i], prop_val) <= 0) continue;
      if (inet_pton(AF_INET, prop_val, &ia) != 1) continue;
      dns = ntohl(ia.s_addr);
      if (dns) return dns;
    }
  }
#endif
  return 0;
}
void util_set_gateway_override(const char *ip) {
  if (!ip || !ip[0]) return;
  safe_strncpy(g_gateway_override, ip, sizeof(g_gateway_override));
}
void util_set_local_ip_override(const char *ip) {
  if (!ip || !ip[0]) return;
  safe_strncpy(g_local_ip_override, ip, sizeof(g_local_ip_override));
}
void util_set_cidr_override(int cidr) {
  if (cidr < 0 || cidr > 32) return;
  g_cidr_override = cidr;
}
int util_get_local_ip_override(char *dst, size_t dst_sz) {
  if (!dst || dst_sz == 0) return 0;
  dst[0] = 0;
  if (!g_local_ip_override[0]) return 0;
  safe_strncpy(dst, g_local_ip_override, dst_sz);
  return 1;
}
int util_get_cidr_override(void) {
  return g_cidr_override;
}
int get_local_ip(char *dst, size_t dst_sz) {
  if (!dst || dst_sz == 0) return -1;
  dst[0] = 0;
  uint32_t netmask;
  uint32_t ip;
  if (!get_local_network(NULL, &ip, &netmask)) return -1;
  (void)netmask;
  struct in_addr ia;
  ia.s_addr = htonl(ip);
  if (!inet_ntop(AF_INET, &ia, dst, (socklen_t)dst_sz)) return -1;
  return 0;
}

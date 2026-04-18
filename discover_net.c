#include "discover_net.h"
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include "util.h"
#include "util_net.h"
static int ipv4_is_private(uint32_t ip) {
  if ((ip & 0xFF000000u) == 0x0A000000u) return 1;
  if ((ip & 0xFFF00000u) == 0xAC100000u) return 1;
  if ((ip & 0xFFFF0000u) == 0xC0A80000u) return 1;
  return 0;
}
static int get_local_network_ioctl(const char *iface, uint32_t *ip, uint32_t *netmask) {
  if (!iface || !*iface || !ip || !netmask) return 0;
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) return 0;
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name) - 1);
  if (ioctl(fd, SIOCGIFADDR, &ifr) != 0) {
    close(fd);
    return 0;
  }
  struct sockaddr_in *sa = (struct sockaddr_in *)&ifr.ifr_addr;
  *ip = ntohl(sa->sin_addr.s_addr);
  if (ioctl(fd, SIOCGIFNETMASK, &ifr) != 0) {
    close(fd);
    return 0;
  }
  sa = (struct sockaddr_in *)&ifr.ifr_netmask;
  *netmask = ntohl(sa->sin_addr.s_addr);
  close(fd);
  return *ip != 0 && *netmask != 0;
}
static uint32_t cidr_to_netmask(int cidr) {
  if (cidr <= 0) return 0;
  if (cidr >= 32) return 0xFFFFFFFFu;
  return 0xFFFFFFFFu << (32 - cidr);
}
int get_local_network(char *iface, uint32_t *ip, uint32_t *netmask) {
  if (!ip || !netmask) return 0;
  *ip = 0; *netmask = 0;
  if (iface) iface[0] = 0;

  int cidr_override = util_get_cidr_override();

  char ip_override[64]; ip_override[0] = 0;
  int have_override = util_get_local_ip_override(ip_override, sizeof(ip_override)) || cidr_override >= 0;
  char route_iface[64]; route_iface[0] = 0;
  uint32_t gw = get_default_gateway_iface(route_iface, sizeof(route_iface));

  int found = 0;
  struct ifaddrs *ifaddr = NULL;
  if (getifaddrs(&ifaddr) != 0) {
    if (get_local_network_ioctl(route_iface, ip, netmask)) {
      if (iface) {
        strncpy(iface, route_iface, 63);
        iface[63] = 0;
      }
      found = 1;
    }
    goto apply_overrides;
  }
  int best_score = -1000000;
  for (struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
    if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
    if (ifa->ifa_flags & IFF_LOOPBACK) continue;
    if (!(ifa->ifa_flags & IFF_UP)) continue;
    if (strncmp(ifa->ifa_name, "rmnet", 5) == 0) continue;
    if (strncmp(ifa->ifa_name, "dummy", 5) == 0) continue;
    if (strncmp(ifa->ifa_name, "p2p", 3) == 0) continue;

    struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
    struct sockaddr_in *nm = (struct sockaddr_in *)ifa->ifa_netmask;
    if (!sa || !nm) continue;
    uint32_t ip_n = (uint32_t)sa->sin_addr.s_addr;
    uint32_t nm_n = (uint32_t)nm->sin_addr.s_addr;
    if (ip_n == 0 || nm_n == 0) continue;
    uint32_t ip_h = ntohl(ip_n);
    uint32_t nm_h = ntohl(nm_n);
    int score = iface_rank(ifa->ifa_name);
    if (ifa->ifa_flags & IFF_RUNNING) score += 80;
    if (nm_h != 0xFFFFFFFFu) score += 60;
    if (ipv4_is_private(ip_h)) score += 40;
    if (route_iface[0] && strcmp(route_iface, ifa->ifa_name) == 0) score += 900;
    if (gw && ((gw & nm_h) == (ip_h & nm_h))) score += 500;
    if (score <= best_score) continue;
    best_score = score;
    *ip = ip_h; *netmask = nm_h;
    if (iface) {
      strncpy(iface, ifa->ifa_name, 63);
      iface[63] = 0;
    }
  }
  freeifaddrs(ifaddr);
  if (best_score >= 0) found = 1;
  else if (get_local_network_ioctl(route_iface, ip, netmask)) {
    if (iface) {
      strncpy(iface, route_iface, 63);
      iface[63] = 0;
    }
    found = 1;
  }
apply_overrides:
  if (have_override) {
    if (ip_override[0]) {
      struct in_addr ia;
      if (inet_pton(AF_INET, ip_override, &ia) == 1) *ip = ntohl(ia.s_addr);
      else *ip = 0;
    }
    if (cidr_override >= 0 && cidr_override <= 32) *netmask = cidr_to_netmask(cidr_override);
    if (iface && iface[0] == 0) {
      if (route_iface[0]) {
        strncpy(iface, route_iface, 63);
        iface[63] = 0;
      } else {
        strncpy(iface, "override", 63);
        iface[63] = 0;
      }
    }
    if (*ip != 0 && *netmask != 0) return 1;
    return 0;
  }
  return found;
}

#include "scoutless.h"
#include "scan.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/ip_icmp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include "probes.h"
#include "util.h"
#include "discover.h"
#include "discover_net.h"
#include "discover_policy.h"
#include "discover_targets.h"
#include "discover_hosts.h"
#include "discover_hosts_internal.h"

static const char g_ssdp_msearch[] = "M-SEARCH * HTTP/1.1\r\n" "HOST: 239.255.255.250:1900\r\n" "MAN: \"ssdp:discover\"\r\n" "MX: 1\r\n" "ST: ssdp:all\r\n\r\n";
static const char g_wsd_probe[] = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" "<e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\" " "xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
  "xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\">" "<e:Header>" "<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>"
  "<w:MessageID>uuid:00000000-0000-0000-0000-000000000000</w:MessageID>" "<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>" "</e:Header>" "<e:Body><d:Probe/></e:Body></e:Envelope>";
static const unsigned char DISCOVERY_MDNS_Q[] = { 0x00,0x00, 0x00,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x09,'_','s','e','r','v','i','c','e','s', 0x07,'_','d','n','s','-','s','d',
  0x04,'_','u','d','p', 0x05,'l','o','c','a','l', 0x00, 0x00,0x0c, 0x00,0x01 };
static const unsigned char DISCOVERY_LLMNR_Q[] = { 0x00,0x00, 0x00,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x09,'_','s','e','r','v','i','c','e','s', 0x07,'_','d','n','s','-','s','d',
  0x04,'_','u','d','p', 0x05,'l','o','c','a','l', 0x00, 0x00,0x0c, 0x00,0x01 };
static const unsigned char DISCOVERY_NBNS_Q[] = { 0x12,0x34, 0x00,0x10, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x20, 'C','K','A','A','A','A','A','A','A','A','A','A','A','A','A','A',
  'A','A','A','A','A','A','A','A','A','A','A','A','A','A','A','A', 0x00, 0x00,0x20, 0x00,0x01 };

static int discovery_multicast_open_socket(uint32_t iface_ip, int is_broadcast) {
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0) return -1;
  int yes = 1;
  (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  if (is_broadcast) (void)setsockopt(s, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));
  struct sockaddr_in sa = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(iface_ip ? iface_ip : INADDR_ANY),.sin_port = htons(0) };
  if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
      close(s);
      return -1;
    }
  }
  (void)set_nonblock_fd(s);
  return s;
}
static void discovery_multicast_set_opts(int s, uint32_t iface_ip) {
  unsigned char ttl = 255;
  unsigned char loop = 0;
  struct in_addr ia;
  ia.s_addr = htonl(iface_ip);
  (void)setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
  (void)setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));
  if (iface_ip != 0) (void)setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, &ia, sizeof(ia));
}
static void discovery_multicast_join(int s, const char *group_ip, uint32_t iface_ip) {
  struct ip_mreq m = { .imr_interface.s_addr = htonl(iface_ip ? iface_ip : INADDR_ANY) };
  if (inet_pton(AF_INET, group_ip, &m.imr_multiaddr) != 1) return;
  (void)setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &m, sizeof(m));
}
static int discovery_multicast_send(int s, const char *dst_ip, int dst_port, const void *buf, size_t len) {
  struct sockaddr_in dst = { .sin_family = AF_INET, .sin_port = htons((uint16_t)dst_port) };
  if (inet_pton(AF_INET, dst_ip, &dst.sin_addr) != 1) return -1;
  ssize_t wr = sendto(s, buf, len, 0, (struct sockaddr *)&dst, sizeof(dst));
  return wr < 0 ? -1 : 0;
}
uint64_t discovery_probe_earliest_deadline(const DiscoveryPassiveProbe *probes, const uint64_t *deadlines, int n_probes) {
  if (!probes || !deadlines || n_probes <= 0) return 0;
  uint64_t deadline = 0;
  for (int i = 0; i < n_probes; i++) {
    if (probes[i].s < 0 || deadlines[i] == 0) continue;
    if (deadline == 0 || deadlines[i] < deadline) deadline = deadlines[i];
  }
  return deadline;
}
void discovery_close_fd_from_epoll(int ep, int *fd) {
  if (!fd || *fd < 0) return;
  if (ep >= 0) {
    if (epoll_ctl(ep, EPOLL_CTL_DEL, *fd, NULL) != 0) {
      if (errno != ENOENT && errno != EBADF) {
      }
    }
  }
  close(*fd);
  *fd = -1;
}
void discovery_close_expired_passive(int ep, DiscoveryPassiveProbe *probes, const uint64_t *deadlines, int n_probes, uint64_t now) {
  if (!probes || !deadlines || n_probes <= 0) return;
  for (int i = 0; i < n_probes; i++) {
    if (probes[i].s < 0) continue;
    if (deadlines[i] == 0 || now < deadlines[i]) continue;
    discovery_close_fd_from_epoll(ep, &probes[i].s);
  }
}
void discovery_drain_passive_probe_events(const DiscoveryContext *ctx, DiscoveryTarget *targets, int *n_targets, DiscoveryPassiveProbe *probes, int n_probes, int tag) {
  if (!ctx || !targets || !n_targets || !probes) return;
  if (tag < 0 || tag >= n_probes || probes[tag].s < 0) return;
  int drain_budget = DISCOVERY_DRAIN_BUDGET;
  while (drain_budget-- > 0) {
    unsigned char buf[2048];
    struct sockaddr_in src;
    socklen_t slen = sizeof(src);
    ssize_t rd = recvfrom(probes[tag].s, buf, sizeof(buf), 0, (struct sockaddr *)&src, &slen);
    if (rd < 0) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) break;
      break;
    }
    if (rd > 0) (void)discovery_try_add_target_from_ip(ctx, targets, n_targets, &src.sin_addr, DISCOVERY_TARGET_FROM_PASSIVE, "multicast");
  }
}
int discovery_run_initial_multicast_icmp_step(const DiscoveryContext *ctx, DiscoveryTarget *targets, int *n_targets) {
  if (!ctx || !targets || !n_targets || *n_targets <= 0) return 0;
  ScanProbeJob *jobs = calloc(MAX_SMART_TARGETS, sizeof(*jobs));
  if (!jobs) return 0;

  int ep = epoll_create1(0);
  if (ep < 0) {
    free(jobs);
    return 0;
  }
  int uses_dgram = 0;
  int icmp_sock = discovery_icmp_open_socket(&uses_dgram);
  if (icmp_sock >= 0) {
    struct epoll_event ev;
    (void)set_nonblock_fd(icmp_sock);
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
    ev.data.u32 = 100;
    if (epoll_ctl(ep, EPOLL_CTL_ADD, icmp_sock, &ev) != 0) discovery_close_fd_from_epoll(ep, &icmp_sock);
  }
  DiscoveryPassiveProbe probes[5];
  probes[0] = (DiscoveryPassiveProbe){ .port = 1900, .dst_ip = "239.255.255.250", .payload = g_ssdp_msearch,    .payload_len = strlen(g_ssdp_msearch),    .timeout_ms = discovery_ssdp_timeout_ms(),      .is_broadcast = 0 };
  probes[1] = (DiscoveryPassiveProbe){ .port = 5353, .dst_ip = "224.0.0.251",     .payload = DISCOVERY_MDNS_Q,  .payload_len = sizeof(DISCOVERY_MDNS_Q),  .timeout_ms = discovery_multicast_timeout_ms(), .is_broadcast = 0 };
  probes[2] = (DiscoveryPassiveProbe){ .port = 3702, .dst_ip = "239.255.255.250", .payload = g_wsd_probe,       .payload_len = strlen(g_wsd_probe),       .timeout_ms = discovery_multicast_timeout_ms(), .is_broadcast = 0 };
  probes[3] = (DiscoveryPassiveProbe){ .port = 5355, .dst_ip = "224.0.0.252",     .payload = DISCOVERY_LLMNR_Q, .payload_len = sizeof(DISCOVERY_LLMNR_Q), .timeout_ms = discovery_multicast_timeout_ms(), .is_broadcast = 0 };
  probes[4] = (DiscoveryPassiveProbe){ .port = 137,  .dst_ip = "255.255.255.255", .payload = DISCOVERY_NBNS_Q,  .payload_len = sizeof(DISCOVERY_NBNS_Q),  .timeout_ms = discovery_multicast_timeout_ms(), .is_broadcast = 1 };
  for (int i = 0; i < 5; i++) {
    probes[i].s = discovery_multicast_open_socket(ctx->ip, probes[i].is_broadcast);
    if (probes[i].s < 0) continue;
    if (!probes[i].is_broadcast) discovery_multicast_set_opts(probes[i].s, ctx->ip);
    probes[i].tag = "multicast";

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
    ev.data.u32 = (uint32_t)i;
    if (epoll_ctl(ep, EPOLL_CTL_ADD, probes[i].s, &ev) != 0) {
      discovery_close_fd_from_epoll(ep, &probes[i].s);
      continue;
    }
  }
  if (probes[0].s >= 0) discovery_multicast_join(probes[0].s, "239.255.255.250", ctx->ip);
  if (probes[1].s >= 0) discovery_multicast_join(probes[1].s, "224.0.0.251", ctx->ip);
  if (probes[2].s >= 0) discovery_multicast_join(probes[2].s, "239.255.255.250", ctx->ip);
  if (probes[3].s >= 0) discovery_multicast_join(probes[3].s, "224.0.0.252", ctx->ip);

  uint64_t probe_deadlines[5] = {0};
  for (int i = 0; i < 5; i++) {
    if (probes[i].s < 0) continue;
    (void)discovery_multicast_send(probes[i].s, probes[i].dst_ip, probes[i].port, probes[i].payload, probes[i].payload_len);
    probe_deadlines[i] = now_ms() + (uint64_t)probes[i].timeout_ms;
  }
  int pending = discovery_collect_pending_jobs(targets, *n_targets, jobs);
  int alive = discovery_run_icmp_probe_loop(ctx, targets, n_targets, jobs, pending, ep, icmp_sock, uses_dgram, probes, probe_deadlines, 5);
  for (int i = 0; i < 5; i++)
    discovery_close_fd_from_epoll(ep, &probes[i].s);
  discovery_close_fd_from_epoll(ep, &icmp_sock);
  close(ep);
  free(jobs);
  return alive;
}

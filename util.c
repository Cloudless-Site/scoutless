#include "util.h"
#include "runtime.h"
#include <netinet/tcp.h>
#include "scoutless.h"
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
typedef struct {
  char ip[64];
  int port;
  int proto;
} debug_service_filter_entry_t;
static debug_service_filter_entry_t g_debug_service_filters[512];
static int g_debug_service_filters_n;
uint64_t now_us(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
  }
  return (uint64_t)ts.tv_sec * 1000000ULL + ((uint64_t)ts.tv_nsec / 1000ULL);
}
uint64_t now_ms(void) {
  return now_us() / 1000ULL;
}
void scout_invariant_failed(const char *expr, const char *file, int line) {
  fprintf(stderr, "invariant failed: %s at %s:%d\n", expr ? expr : "?", file ? file : "?", line);
  abort();
}
uint32_t debug_elapsed_total_ms(void) {
  uint64_t now;
  if (g_discovery_started_ms == 0) return 0;
  now = now_ms();
  if (now <= g_discovery_started_ms) return 0;
  if (now - g_discovery_started_ms > 0xffffffffULL) return 0xffffffffU;
  return (uint32_t)(now - g_discovery_started_ms);
}
static char *trim_ws(char *s) {
  char *e;
  if (!s) return s;
  while (*s && isspace((unsigned char)*s)) s++;
  e = s + strlen(s);
  while (e > s && isspace((unsigned char)e[-1])) e--;
  *e = 0;
  return s;
}
int debug_service_filter_load(const char *path) {
  FILE *f;
  char line[256];
  g_debug_service_filters_n = 0;
  if (!path || !*path) return 0;
  f = fopen(path, "r");
  if (!f) return -1;
  while (fgets(line, sizeof(line), f)) {
    char *s;
    char *c2;
    char *c1;
    char *ip;
    char *port_s;
    char *proto_s;
    long port;
    int proto;
    if (g_debug_service_filters_n >= (int)(sizeof(g_debug_service_filters) / sizeof(g_debug_service_filters[0]))) break;
    s = trim_ws(line);
    if (!*s) continue;
    c2 = strrchr(s, ':');
    if (!c2) continue;
    *c2++ = 0;
    c1 = strrchr(s, ':');
    if (!c1) continue;
    *c1++ = 0;
    ip = trim_ws(s);
    port_s = trim_ws(c1);
    proto_s = trim_ws(c2);
    if (!*ip || !*port_s || !*proto_s) continue;
    port = strtol(port_s, NULL, 10);
    if (port <= 0 || port > 65535) continue;
    if (!strcasecmp(proto_s, "tcp")) proto = IPPROTO_TCP;
    else if (!strcasecmp(proto_s, "udp")) proto = IPPROTO_UDP;
    else continue;
    safe_strncpy(g_debug_service_filters[g_debug_service_filters_n].ip, ip, sizeof(g_debug_service_filters[g_debug_service_filters_n].ip));
    g_debug_service_filters[g_debug_service_filters_n].port = (int)port;
    g_debug_service_filters[g_debug_service_filters_n].proto = proto;
    g_debug_service_filters_n++;
  }
  fclose(f);
  return g_debug_service_filters_n;
}
int debug_service_filter_match(const char *ip, int port, int proto) {
  int i;
  if (!ip || !*ip || port <= 0) return 0;
  if (g_debug_service_filters_n <= 0) return 0;
  for (i = 0; i < g_debug_service_filters_n; i++) {
    if (g_debug_service_filters[i].port != port) continue;
    if (g_debug_service_filters[i].proto != proto) continue;
    if (strcmp(g_debug_service_filters[i].ip, ip) != 0) continue;
    return 1;
  }
  return 0;
}
int debug_service_filter_match_ip(const char *ip) {
  int i;
  if (!ip || !*ip) return 0;
  if (g_debug_service_filters_n <= 0) return 0;
  for (i = 0; i < g_debug_service_filters_n; i++) {
    if (strcmp(g_debug_service_filters[i].ip, ip) != 0) continue;
    return 1;
  }
  return 0;
}
void dbg_service_trace(const char *phase, const char *ip, int port, int proto, const char *fmt, ...) {
  va_list ap;
  if (!g_debug) return;
  if (!g_debug_services_all && !debug_service_filter_match(ip, port, proto)) return;
  fprintf(stderr, "[svc-debug][%s][%s] %s:%d", phase ? phase : "?", proto == IPPROTO_UDP ? "udp" : "tcp", ip ? ip : "", port);
  if (fmt && *fmt) {
    fputc(' ', stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
  }
  fputc('\n', stderr);
}
void dbg_host_trace(const char *phase, const char *src, const char *ip, const char *fmt, ...) {
  va_list ap;
  if (!g_debug) return;
  if (!g_debug_services_all && !debug_service_filter_match_ip(ip)) return;
  fprintf(stderr, "[host-debug][%s][%s] %s", phase ? phase : "?", src ? src : "host", ip ? ip : "");
  if (fmt && *fmt) {
    fputc(' ', stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
  }
  fputc('\n', stderr);
}
void dbg_service_found(const char *src, const char *ip, int port, int t, const char *name, const char *hint, uint32_t total_ms, uint32_t connect_ms, uint32_t match_ms) {
  int proto;
  (void)hint;
  (void)t;
  if (!g_debug || !ip || !name) return;
  proto = src && !strncmp(src, "udp", 3) ? IPPROTO_UDP : IPPROTO_TCP;
  if (g_debug_service_filters_n > 0 && !g_debug_services_all && !debug_service_filter_match(ip, port, proto)) return;
  if (connect_ms || match_ms)
    fprintf(stderr, "[%s] %s:%d connect=%u match=%u time=%u\n", name, ip, port, connect_ms, match_ms, total_ms);
  else
    fprintf(stderr, "[%s] %s:%d time=%u\n", name, ip, port, total_ms);
}
void sleep_ms(int ms) {
  if (ms <= 0) return;
  struct timespec ts;
  ts.tv_sec  = ms / 1000;
  ts.tv_nsec = (long)(ms % 1000) * 1000000L;
  (void)nanosleep(&ts, NULL);
}
void sleep_us(int us) {
  if (us <= 0) return;
  struct timespec ts;
  ts.tv_sec  = (time_t)(us / 1000000);
  ts.tv_nsec = (long)(us % 1000000) * 1000L;
  (void)nanosleep(&ts, NULL);
}
int is_hard_unreach(int err) {
  return (err == ENETUNREACH || err == EHOSTUNREACH || err == ENETDOWN);
}
int set_nonblock_fd(int fd) {
  int fl = fcntl(fd, F_GETFL, 0);
  if (fl < 0) return -1;
  if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) return -1;
  return 0;
}
int contains_ci_n(const char *hay, size_t hlen, const char *needle) {
  size_t nlen;
  if (!hay || !needle || !*needle) return 0;
  nlen = strlen(needle);
  if (nlen == 0 || hlen < nlen) return 0;
  for (size_t off = 0; off + nlen <= hlen; off++) {
    size_t i = 0;
    while (i < nlen && tolower((unsigned char)hay[off + i]) == tolower((unsigned char)needle[i])) i++;
    if (i == nlen) return 1;
  }
  return 0;
}
void safe_strncpy(char *dst, const char *src, size_t dst_sz) {
  if (!dst || dst_sz == 0) return;
  if (!src) { dst[0] = 0; return; }
  size_t n = strnlen(src, dst_sz - 1);
  memcpy(dst, src, n);
  dst[n] = 0;
}
static int name_is_weak(const char *s) {
  if (!s || !*s) return 1;
  if (strcmp(s, "unknown") == 0) return 1;
  return 0;
}
int add_service_unique(Service *list, int *io_n, const char *ip_str, int lport,
                        int rport, ServiceType t, char *name) {
  (void)rport;
  if (!list || !io_n || !ip_str) return 0;
  int n = *io_n;
  if (n < 0) n = 0;
  for (int i = 0; i < n; i++) {
    if (list[i].local_port != lport) continue;
    if (strcmp(list[i].ip, ip_str) != 0) continue;
    if (list[i].type != t) continue;
    if (name && *name && name_is_weak(list[i].name) &&
        strcmp(list[i].name, name) != 0) {
      strncpy(list[i].name, name, sizeof(list[i].name) - 1);
      list[i].name[sizeof(list[i].name) - 1] = 0;
      return 1;
    }
    return 0;
  }
  if (n >= MAX_SERVICES) return 0;
  Service *s = &list[n];
  memset(s, 0, sizeof(*s));
  strncpy(s->ip, ip_str, sizeof(s->ip) - 1);
  s->ip[sizeof(s->ip) - 1] = 0;
  s->local_port  = lport;
  s->type        = t;
  if (name && *name) {
    strncpy(s->name, name, sizeof(s->name) - 1);
    s->name[sizeof(s->name) - 1] = 0;
  }
  *io_n = n + 1;
  return 1;
}

void service_set_hint(Service *list, int n, const char *ip_str, int lport, ServiceType t, const char *hint) {
  if (!list || n <= 0 || !ip_str || !hint || !*hint) return;
  for (int i = 0; i < n; i++) {
    if (list[i].local_port != lport) continue;
    if (list[i].type != t) continue;
    if (strcmp(list[i].ip, ip_str) != 0) continue;
    if (list[i].svc_hint[0] == 0 || strlen(hint) >= strlen(list[i].svc_hint)) {
      strncpy(list[i].svc_hint, hint, sizeof(list[i].svc_hint) - 1);
      list[i].svc_hint[sizeof(list[i].svc_hint) - 1] = 0;
    }
    return;
  }
}
void service_clear_hint(Service *list, int n, const char *ip_str, int lport, ServiceType t) {
  if (!list || n <= 0 || !ip_str) return;
  for (int i = 0; i < n; i++) {
    if (list[i].local_port != lport) continue;
    if (list[i].type != t) continue;
    if (strcmp(list[i].ip, ip_str) != 0) continue;
    list[i].svc_hint[0] = 0;
    return;
  }
}
int epoll_add_or_mod_ptr(int ep, int fd, void *ptr, uint32_t events) {
  struct epoll_event ev;
  memset(&ev, 0, sizeof(ev));
  ev.events = events;
  ev.data.ptr = ptr;
  if (epoll_ctl(ep, EPOLL_CTL_MOD, fd, &ev) == 0) return 0;
  if (errno == ENOENT) return epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev);
  return -1;
}
int epoll_mod_ptr(int ep, int fd, void *ptr, uint32_t events) {
  struct epoll_event ev;
  memset(&ev, 0, sizeof(ev));
  ev.events = events;
  ev.data.ptr = ptr;
  return epoll_ctl(ep, EPOLL_CTL_MOD, fd, &ev);
}
void set_nodelay(int fd) {
  int one = 1;
  setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));
  struct linger sl = { .l_linger = 0, .l_onoff = 1 };
  setsockopt(fd,SOL_SOCKET,SO_LINGER,&sl,sizeof(sl));
}
void hard_close(int fd) {
  close(fd);
}

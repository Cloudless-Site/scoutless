#include "scoutless.h"
#include "plan.h"
#include "util.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
static char *trim(char *s) {
  while (isspace((unsigned char)*s)) s++;
  char *e = s + strlen(s);
  while (e > s && isspace((unsigned char)*(e-1))) e--;
  *e = 0;
  return s;
}
static int is_hex_string(const char *s) {
  int n = 0;
  int has_space = 0;
  for (const char *p = s; *p; p++) {
    if (isspace((unsigned char)*p)) { has_space = 1; continue; }
    if (!isxdigit((unsigned char)*p)) return 0;
    n++;
  }
  return n > 0 && (has_space || n % 2 == 0);
}
static int parse_hex(const char *src, unsigned char *buf, size_t cap) {
  int n = 0;
  while (*src) {
    while (isspace((unsigned char)*src)) src++;
    if (!*src) break;
    char hi = *src++;
    while (isspace((unsigned char)*src)) src++;
    if (!*src) return -1;
    char lo = *src++;
    char tmp[3] = { hi, lo, 0 };
    char *end;
    long val = strtol(tmp, &end, 16);
    if (end != tmp + 2) return -1;
    if ((size_t)n >= cap) return -1;
    buf[n++] = (unsigned char)val;
  }
  return n;
}
static ServiceType parse_srvtype(const char *s) {
  if (!s || !*s)          return SRV_TCP;
  if (!strcmp(s,"http"))  return SRV_HTTP;
  if (!strcmp(s,"https")) return SRV_HTTPS;
  if (!strcmp(s,"udp"))   return SRV_UDP;
  return SRV_TCP;
}
static int plan_tokenize_line(const char *s, char **tok, int cap, char *buf, size_t buf_sz) {
  safe_strncpy(buf, s, buf_sz);
  int ntok = 0;
  char *p = buf;
  while (ntok < cap) {
    while (isspace((unsigned char)*p)) p++;
    if (!*p) break;
    tok[ntok++] = p;
    while (*p && !isspace((unsigned char)*p)) p++;
    if (*p) *p++ = 0;
  }
  return ntok;
}
static int plan_parse_port_header(const char **tok, int ntok, int lineno, ScanPlan *out, PlanPort **cur) {
  if (ntok < 4) {
    fprintf(stderr, "plan:%d: %s port name type required\n", lineno, tok[0]);
    *cur = NULL;
    return 1;
  }
  int proto = (!strcmp(tok[0],"tcp")) ? IPPROTO_TCP : IPPROTO_UDP;
  int port = atoi(tok[1]);
  if (port <= 0 || port > 65535) {
    fprintf(stderr, "plan:%d: bad port '%s'\n", lineno, tok[1]);
    *cur = NULL;
    return 1;
  }
  if (out->n_ports >= PLAN_MAX_PORTS) {
    fprintf(stderr, "plan:%d: too many ports (max %d)\n", lineno, PLAN_MAX_PORTS);
    *cur = NULL;
    return 1;
  }
  *cur = &out->ports[out->n_ports++];
  memset(*cur, 0, sizeof(**cur));
  (*cur)->proto = proto; (*cur)->port = port;
  safe_strncpy((*cur)->name, tok[2], sizeof((*cur)->name));
  (*cur)->type = parse_srvtype(tok[3]);
  for (int i = 4; i < ntok; i++)
    if (!strcmp(tok[i],"force_publish")) (*cur)->force_publish = 1;
  return 1;
}
static const char *plan_skip_token_rest(const char *s, const char *name, size_t name_len) {
  const char *rest = strstr(s, name);
  if (rest) rest += name_len;
  while (rest && isspace((unsigned char)*rest)) rest++;
  return rest;
}
static int plan_parse_send_text(const char *s, int lineno, PlanPort *cur) {
  if (!cur) {
    fprintf(stderr,"plan:%d: send_text without port\n",lineno);
    return 1;
  }
  const char *rest = plan_skip_token_rest(s, "send_text", 9);
  if (!rest || !*rest) {
    fprintf(stderr,"plan:%d: send_text dummy\n",lineno);
    return 1;
  }
  size_t wi = 0;
  char tmp[256];
  for (const char *c = rest; *c && wi + 1 < sizeof(tmp); c++) {
    if (*c == '\\' && *(c+1) == 'r') { tmp[wi++] = '\r'; c++; }
    else if (*c == '\\' && *(c+1) == 'n') { tmp[wi++] = '\n'; c++; }
    else tmp[wi++] = *c;
  }
  tmp[wi] = 0;
  safe_strncpy(cur->send_text, tmp, sizeof(cur->send_text));
  cur->send_is_hex = 0;
  cur->has_probe = 1;
  return 1;
}
static int plan_parse_send_hex(const char *s, int lineno, PlanPort *cur) {
  if (!cur) {
    fprintf(stderr,"plan:%d: send_hex without port\n",lineno);
    return 1;
  }
  const char *rest = plan_skip_token_rest(s, "send_hex", 8);
  if (!rest || !*rest) {
    fprintf(stderr,"plan:%d: send_hex dummy\n",lineno);
    return 1;
  }
  int nb = parse_hex(rest, cur->send_hex, sizeof(cur->send_hex));
  if (nb < 0) {
    fprintf(stderr,"plan:%d: invalid send_hex\n",lineno);
    return 1;
  }
  cur->send_hex_len = (size_t)nb;
  cur->send_is_hex = 1;
  cur->has_probe = 1;
  return 1;
}
static int plan_parse_expect_substr(const char *s, int lineno, PlanPort *cur) {
  if (!cur) {
    fprintf(stderr,"plan:%d: expect_substr without port\n",lineno);
    return 1;
  }
  const char *rest = plan_skip_token_rest(s, "expect_substr", 13);
  if (!rest || !*rest) {
    fprintf(stderr,"plan:%d: expect_substr dummy\n",lineno);
    return 1;
  }
  cur->has_probe = 1;
  if (is_hex_string(rest)) {
    int nb = parse_hex(rest, cur->expect_hex, sizeof(cur->expect_hex));
    if (nb < 0) {
      fprintf(stderr,"plan:%d: expect_substr invalid hex\n",lineno);
      return 1;
    }
    cur->expect_hex_len = (size_t)nb;
    cur->expect_is_hex = 1;
  } else {
    safe_strncpy(cur->expect_substr, rest, sizeof(cur->expect_substr));
    cur->expect_is_hex = 0;
  }
  return 1;
}
static void plan_parse_line(const char *s, int lineno, ScanPlan *out, PlanPort **cur) {
  char buf[1024];
  char *tok[8];
  int ntok = plan_tokenize_line(s, tok, 8, buf, sizeof(buf));
  if (ntok == 0) return;
  if (!strcmp(tok[0],"tcp") || !strcmp(tok[0],"udp")) {
    plan_parse_port_header((const char **)tok, ntok, lineno, out, cur);
    return;
  }
  if (!strcmp(tok[0],"send_text")) {
    plan_parse_send_text(s, lineno, *cur);
    return;
  }
  if (!strcmp(tok[0],"send_hex")) {
    plan_parse_send_hex(s, lineno, *cur);
    return;
  }
  if (!strcmp(tok[0],"expect_substr")) {
    plan_parse_expect_substr(s, lineno, *cur);
    return;
  }
  fprintf(stderr, "plan:%d: unknown token '%s'\n", lineno, tok[0]);
}
int plan_load(const char *path, ScanPlan *out) {
  if (!path || !out) return 0;
  memset(out, 0, sizeof(*out));
  FILE *f = fopen(path, "r");
  if (!f) {
    fprintf(stderr, "plan: cannot open '%s'\n", path);
    return 0;
  }
  int lineno = 0;
  char line[1024];
  PlanPort *cur = NULL;
  while (fgets(line, sizeof(line), f)) 
    plan_parse_line(trim(line), lineno++, out, &cur);
  out->loaded = 1;
  fclose(f);
  return 1;
}
static const struct vendor_probe *make_vp(const PlanPort *pp, struct vendor_probe *store, int *used, int cap) {
  if (!pp->has_probe || *used >= cap) return NULL;
  struct vendor_probe *vp = &store[(*used)++];
  memset(vp, 0, sizeof(*vp));
  vp->proto        = pp->proto;
  vp->port         = pp->port;
  vp->forced_type  = pp->type;
  vp->force        = pp->force_publish;
  vp->send_is_hex  = pp->send_is_hex;
  vp->send_hex_len = pp->send_hex_len;
  memcpy(vp->send_hex, pp->send_hex, pp->send_hex_len);
  safe_strncpy(vp->send_text, pp->send_text, sizeof(vp->send_text));
  vp->expect_is_hex  = pp->expect_is_hex;
  vp->expect_hex_len = pp->expect_hex_len;
  memcpy(vp->expect_hex, pp->expect_hex, pp->expect_hex_len);
  safe_strncpy(vp->expect_substr, pp->expect_substr, sizeof(vp->expect_substr));
  return vp;
}
void plan_build(const ScanPlan *plan, PlanItem *tcp_flat, PlanItem **tcp_ptrs, int *tcp_n, UdpPlanItem *udp_items, int *udp_n, struct vendor_probe *probe_store, int probe_store_cap) {
  if (!plan || !tcp_flat || !tcp_ptrs || !tcp_n || !udp_items || !udp_n) return;
  *tcp_n = 0;
  *udp_n = 0;
  int vp_used = 0;
  for (int i = 0; i < plan->n_ports; i++) {
    const PlanPort *pp = &plan->ports[i];
    const struct vendor_probe *vp = make_vp(pp, probe_store, &vp_used, probe_store_cap);
    if (pp->proto == IPPROTO_UDP) {
      if (*udp_n >= PLAN_MAX_PORTS) continue;
      UdpPlanItem *ui = &udp_items[*udp_n];
      memset(ui, 0, sizeof(*ui));
      ui->port            = pp->port;
      ui->forced          = pp->type;
      ui->force_publish   = pp->force_publish;
      ui->is_vendor_probe = (vp != NULL) ? 1 : 0;
      ui->vp              = vp;
      (*udp_n)++;
    } else {
      if (*tcp_n >= PLAN_MAX_PORTS) continue;
      PlanItem *ti = &tcp_flat[*tcp_n];
      tcp_ptrs[*tcp_n] = ti;
      memset(ti, 0, sizeof(*ti));
      ti->proto           = IPPROTO_TCP;
      ti->port            = pp->port;
      ti->forced          = pp->type;
      ti->force_publish   = pp->force_publish;
      ti->is_vendor_probe = (vp != NULL) ? 1 : 0;
      ti->vp              = vp;
      (*tcp_n)++;
    }
  }
}

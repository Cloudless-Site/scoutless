#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include "probes.h"
#include "scan.h"
#include "scan_internal.h"
#include "util.h"
#include "web_probe_internal.h"
static int parse_tls_alpn(const unsigned char *buf, size_t len, char *out, size_t cap);

static int is_ip_literal(const char *s) {
  struct in_addr ia;
  if (!s || !*s) return 0;
  return inet_pton(AF_INET, s, &ia) == 1;
}
int parse_http_status(const char *buf) {
  const char *sp;
  if (!buf || strncmp(buf, "HTTP/", 5) != 0) return 0;
  sp = strchr(buf, ' ');
  if (!sp) return 0;
  return atoi(sp + 1);
}
static int extract_header_value(const char *buf, const char *name, char *out, size_t cap) {
  const char *p;
  size_t nlen;
  size_t blen;
  const char *end;
  if (!buf || !name || !out || cap == 0) return 0;
  out[0] = 0;
  blen = strlen(buf);
  end = buf + blen;
  p = strstr(buf, "\r\n");
  if (!p) return 0;
  p += 2;
  nlen = strlen(name);
  while (p < end && *p) {
    const char *e = strstr(p, "\r\n");
    if (!e) e = end;
    if (e == p) break;
    if (strncasecmp(p, name, nlen) == 0 && p + nlen < e && p[nlen] == ':') {
      const char *v = p + nlen + 1;
      while (v < e && (*v == ' ' || *v == '\t')) v++;
      size_t n = (size_t)(e - v);
      if (n >= cap) n = cap - 1;
      memcpy(out, v, n);
      out[n] = 0;
      return out[0] != 0;
    }
    if (e >= end) break;
    p = e + 2;
  }
  return 0;
}
static int extract_url_host(const char *url, char *out, size_t cap) {
  const char *p;
  const char *e;
  size_t n;
  if (!url || !out || cap == 0) return 0;
  out[0] = 0;
  if (strncasecmp(url, "http://", 7) == 0) p = url + 7;
  else if (strncasecmp(url, "https://", 8) == 0) p = url + 8;
  else return 0;
  e = p;
  while (*e && *e != '/' && *e != ':' && *e != ';' && *e != '?') e++;
  n = (size_t)(e - p);
  if (n == 0) return 0;
  if (n >= cap) n = cap - 1;
  memcpy(out, p, n);
  out[n] = 0;
  return 1;
}
tls_probe_reply_t tls_probe_reply_kind(const unsigned char *buf, size_t len) {
  if (!buf || len == 0) return TLS_PROBE_REPLY_NONE;
  if (len >= 11 && buf[0] == 0x16 && (buf[1] == 0x03 || buf[1] == 0x02) && buf[5] == 0x02) return TLS_PROBE_REPLY_SERVER_HELLO;
  if (len >= 2 && buf[0] == 0x15) return TLS_PROBE_REPLY_ALERT;
  return TLS_PROBE_REPLY_NONE;
}
static int web_probe_headers_complete(const unsigned char *buf, size_t len) {
  if (!buf || len < 4) return 0;
  for (size_t i = 3; i < len; i++) {
    if (buf[i - 3] == '\r' && buf[i - 2] == '\n' && buf[i - 1] == '\r' && buf[i] == '\n') return 1;
  }
  return 0;
}
int web_probe_buffer_recognized(web_probe_step_t step, const unsigned char *buf, size_t len) {
  if (!buf || len == 0) return 0;
  if (step == WEB_STEP_HTTP_IP || step == WEB_STEP_HTTP_PUBLIC) {
    if (parse_http_status((const char *)buf) == 0) return 0;
    return web_probe_headers_complete(buf, len);
  }
  return tls_probe_reply_kind(buf, len) != TLS_PROBE_REPLY_NONE;
}
int web_probe_buffer_useful(web_probe_step_t step, const unsigned char *buf, size_t len) {
  if (!buf || len == 0) return 0;
  if (step == WEB_STEP_HTTP_IP || step == WEB_STEP_HTTP_PUBLIC) return parse_http_status((const char *)buf) != 0;
  return tls_probe_reply_kind(buf, len) != TLS_PROBE_REPLY_NONE;
}
static int http_status_score(int status, int redirect_https) {
  if (status == 200 || status == 204 || status == 401 || status == 403) return HTTP_PROBE_SCORE_GOOD;
  if (status == 301 || status == 302 || status == 307 || status == 308) return redirect_https ? HTTP_PROBE_SCORE_REDIRECT_HTTPS : HTTP_PROBE_SCORE_GOOD;
  if (status == 404 || status == 405) return HTTP_PROBE_SCORE_OK;
  if (status >= 100 && status < 500 && status != 400 && status != 421) return HTTP_PROBE_SCORE_PARTIAL;
  if (status >= 500 && status < 600) return HTTP_PROBE_SCORE_WEAK;
  return HTTP_PROBE_SCORE_NONE;
}
void finalize_http_probe_reply(const char *buf, HttpProbe *out) {
  char location[256];
  int status;
  if (!out || !buf) return;
  status = parse_http_status(buf);
  if (status == 0) return;
  out->parsed = 1;
  out->status = status;
  out->score = http_status_score(status, 0);
  location[0] = 0;
  if (extract_header_value(buf, "Location", location, sizeof(location))) {
    if (strncasecmp(location, "https://", 8) == 0) out->redirect_https = 1;
    if (extract_url_host(location, out->redirect_host, sizeof(out->redirect_host)) && out->redirect_https) out->score = http_status_score(status, 1);
  }
}
void finalize_tls_probe_reply(const unsigned char *buf, size_t len, const char *sni, TlsProbe *out) {
  tls_probe_reply_t kind;
  if (!out || !buf) return;
  kind = tls_probe_reply_kind(buf, len);
  if (sni && *sni) safe_strncpy(out->sni_value, sni, sizeof(out->sni_value));
  if (kind == TLS_PROBE_REPLY_SERVER_HELLO) {
    out->ok = 1;
    out->proto_major = buf[9];
    out->proto_minor = buf[10];
    (void)parse_tls_alpn(buf, len, out->alpn, sizeof(out->alpn));
    return;
  }
  if (kind == TLS_PROBE_REPLY_ALERT) out->alert = 1;
}

int web_probe_http_allows_reuse(const HttpProbe *hp, const unsigned char *buf, size_t len) {
  char connection[64];
  if (!hp || !hp->parsed) return 0;
  if (!web_probe_headers_complete(buf, len)) return 0;
  connection[0] = 0;
  (void)extract_header_value((const char *)buf, "Connection", connection, sizeof(connection));
  if (connection[0] && strcasecmp(connection, "close") == 0) return 0;
  return 1;
}
static void write_u16be(unsigned char *p, uint16_t v) {
  p[0] = (unsigned char)((v >> 8) & 0xff);
  p[1] = (unsigned char)(v & 0xff);
}
static void write_u24be(unsigned char *p, uint32_t v) {
  p[0] = (unsigned char)((v >> 16) & 0xff);
  p[1] = (unsigned char)((v >> 8) & 0xff);
  p[2] = (unsigned char)(v & 0xff);
}
size_t build_tls_client_hello(unsigned char *out, size_t cap, const char *sni) {
  unsigned char *p0 = out;
  unsigned char *p = out;
  unsigned char *hs;
  unsigned char *ext_len_p;
  unsigned char *ext_start;
  static uint64_t hello_counter = 0;
  uint64_t seed;
  if (!out || cap < 128) return 0;
  p += 5;
  hs = p;
  *p++ = 0x01;
  p += 3;
  *p++ = 0x03;
  *p++ = 0x03;
  hello_counter++;
  seed = now_ms() ^ (hello_counter * 0x9e3779b97f4a7c15ULL);
  for (int i = 0; i < 32; i++) *p++ = (unsigned char)(((seed >> ((i & 7) * 8)) & 0xff) ^ (uint64_t)(i * 17 + 29));
  *p++ = 0x00;
  write_u16be(p, 8);
  p += 2;
  *p++ = 0x00;
  *p++ = 0x2f;
  *p++ = 0x00;
  *p++ = 0x35;
  *p++ = 0xc0;
  *p++ = 0x2f;
  *p++ = 0xc0;
  *p++ = 0x2b;
  *p++ = 0x01;
  *p++ = 0x00;
  ext_len_p = p;
  p += 2;
  ext_start = p;
  if (sni && *sni && !is_ip_literal(sni)) {
    size_t sl = strlen(sni);
    if (sl <= 65527 && (size_t)(p - p0) + sl + 64 <= cap) {
      write_u16be(p, 0x0000);
      p += 2;
      write_u16be(p, (uint16_t)(sl + 5));
      p += 2;
      write_u16be(p, (uint16_t)(sl + 3));
      p += 2;
      *p++ = 0x00;
      write_u16be(p, (uint16_t)sl);
      p += 2;
      memcpy(p, sni, sl);
      p += sl;
    }
  }
  write_u16be(p, 0x000b);
  p += 2;
  write_u16be(p, 4);
  p += 2;
  *p++ = 3;
  *p++ = 0;
  *p++ = 1;
  *p++ = 2;
  write_u16be(p, 0x000a);
  p += 2;
  write_u16be(p, 8);
  p += 2;
  write_u16be(p, 6);
  p += 2;
  write_u16be(p, 0x0017);
  p += 2;
  write_u16be(p, 0x0018);
  p += 2;
  write_u16be(p, 0x0019);
  p += 2;
  write_u16be(p, 0x000d);
  p += 2;
  write_u16be(p, 8);
  p += 2;
  write_u16be(p, 6);
  p += 2;
  write_u16be(p, 0x0403);
  p += 2;
  write_u16be(p, 0x0503);
  p += 2;
  write_u16be(p, 0x0201);
  p += 2;
  write_u16be(p, 0x0010);
  p += 2;
  write_u16be(p, 14);
  p += 2;
  write_u16be(p, 12);
  p += 2;
  *p++ = 2;
  *p++ = 'h';
  *p++ = '2';
  *p++ = 8;
  memcpy(p, "http/1.1", 8);
  p += 8;
  write_u16be(ext_len_p, (uint16_t)(p - ext_start));
  out[0] = 0x16;
  out[1] = 0x03;
  out[2] = 0x01;
  write_u16be(out + 3, (uint16_t)(p - p0 - 5));
  write_u24be(hs + 1, (uint32_t)(p - hs - 4));
  return (size_t)(p - p0);
}
static int parse_tls_alpn(const unsigned char *buf, size_t len, char *out, size_t cap) {
  size_t pos;
  size_t end;
  if (!buf || len < 48 || !out || cap == 0) return 0;
  out[0] = 0;
  if (buf[0] != 0x16 || buf[5] != 0x02) return 0;
  pos = 9;
  if (pos + 34 > len) return 0;
  pos += 2;
  pos += 32;
  if (pos + 1 > len) return 0;
  if (pos + 1 + buf[pos] + 3 > len) return 0;
  pos += 1 + buf[pos];
  pos += 2;
  pos += 1;
  if (pos + 2 > len) return 0;
  end = pos + 2 + ((size_t)buf[pos] << 8 | (size_t)buf[pos + 1]);
  pos += 2;
  if (end > len) end = len;
  while (pos + 4 <= end) {
    uint16_t et = (uint16_t)(((uint16_t)buf[pos] << 8) | buf[pos + 1]);
    uint16_t el = (uint16_t)(((uint16_t)buf[pos + 2] << 8) | buf[pos + 3]);
    pos += 4;
    if (pos + el > end) break;
    if (et == 0x0010 && el >= 3) {
      size_t lp = pos + 2;
      size_t pl;
      if (lp >= pos + el) break;
      pl = buf[lp];
      if (lp + 1 + pl <= pos + el) {
        if (pl >= cap) pl = cap - 1;
        memcpy(out, buf + lp + 1, pl);
        out[pl] = 0;
        return out[0] != 0;
      }
    }
    pos += el;
  }
  return 0;
}

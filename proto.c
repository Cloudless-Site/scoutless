#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "scoutless.h"
#include "probes.h"
#include "util.h"
#include "proto.h"
ServiceInfoType detect_iot_protocol(const unsigned char *buf, size_t len, int port) {
  if (len >= 2 && buf[0] == 0x20 && buf[1] == 0x02) return SERVICE_MQTT;
  if (len >= 4 && (buf[0] & 0xC0) == 0x40) return SERVICE_COAP;
  if (len >= 8 && buf[2] == 0x00 && buf[3] == 0x00) {
    uint8_t fc = buf[7];
    if (fc == 0x01 || fc == 0x02 || fc == 0x03 || fc == 0x04 || fc == 0x05 ||
        fc == 0x06 || fc == 0x0F || fc == 0x10 || fc == 0x81 || fc == 0x82 ||
        fc == 0x83 || fc == 0x84) {
      return SERVICE_MODBUS;
    }
  }
  if (len >= 1 && buf[0] == 0x81) return SERVICE_BACNET;
  if (len >= 2 && buf[0] == 0x06 && buf[1] == 0x10) return SERVICE_KNX;
  if (port == 1883 || port == 8883) return SERVICE_MQTT;
  if (port == 5683 || port == 5684) return SERVICE_COAP;
  if (port == 502) return SERVICE_MODBUS;
  if (port == 47808) return SERVICE_BACNET;
  if (port == 3671) return SERVICE_KNX;
  return SERVICE_UNKNOWN;
}
const char *service_names[] = {
    [SERVICE_UNKNOWN] = "unknown",
    [SERVICE_HTTP] = "http",
    [SERVICE_HTTPS] = "https",
    [SERVICE_SSH] = "ssh",
    [SERVICE_MQTT] = "mqtt",
    [SERVICE_COAP] = "coap",
    [SERVICE_MODBUS] = "modbus",[SERVICE_BACNET] = "bacnet",
    [SERVICE_KNX] = "knx",
    [SERVICE_TELNET] = "telnet",
    [SERVICE_FTP] = "ftp",
    [SERVICE_FTPS] = "ftps",
    [SERVICE_SMTP] = "smtp",
    [SERVICE_POP3] = "pop3",[SERVICE_IMAP] = "imap",
    [SERVICE_SMB] = "smb",[SERVICE_MYSQL] = "mysql",
    [SERVICE_POSTGRESQL] = "postgresql",[SERVICE_MONGODB] = "mongodb",
    [SERVICE_REDIS] = "redis",
    [SERVICE_DNS] = "dns",
    [SERVICE_LDAP] = "ldap",
    [SERVICE_RDP] = "rdp",
    [SERVICE_VNC] = "vnc",
    [SERVICE_ELASTICSEARCH] = "elasticsearch",[SERVICE_DOCKER] = "docker",
    [SERVICE_GIT] = "git",[SERVICE_RTSP] = "rtsp",
    [SERVICE_SIP] = "sip",
    [SERVICE_SNMP] = "snmp",
    [SERVICE_NTP] = "ntp",
    [SERVICE_PROMETHEUS] = "prometheus",
};
const char *service_to_string(ServiceInfoType t) {
  if ((int)t >= 0 && (int)t < (int)(sizeof(service_names) / sizeof(service_names[0])) && service_names[t]) return service_names[t];
  return "unknown";
}
static const ServiceSignature g_signatures[] = {
    {"Server: nginx", SERVICE_HTTP, "nginx", 0.90f},
    {"Server: Apache", SERVICE_HTTP, "Apache", 0.90f},
    {"Server: Microsoft-IIS", SERVICE_HTTP, "Microsoft-IIS", 0.95f},
    {"Server: lighttpd", SERVICE_HTTP, "lighttpd", 0.90f},
    {"Server: Caddy", SERVICE_HTTP, "Caddy", 0.85f},
    {"X-Powered-By: PHP", SERVICE_HTTP, "PHP", 0.70f},
    {"X-AspNet-Version:", SERVICE_HTTP, NULL, 0.80f},
    {"Server: Jetty", SERVICE_HTTP, "Jetty", 0.90f},
    {"Server: Tomcat", SERVICE_HTTP, "Tomcat", 0.90f},
    {"Server: Node.js", SERVICE_HTTP, NULL, 0.85f},
    {"SSH-2.0-OpenSSH", SERVICE_SSH, "OpenSSH_", 0.95f},
    {"SSH-2.0-dropbear", SERVICE_SSH, "dropbear_", 0.95f},
    {"SSH-1.99-Cisco", SERVICE_SSH, NULL, 0.90f},
    {"SSH-2.0-libssh", SERVICE_SSH, "libssh-", 0.90f},
    {"220 ProFTPD", SERVICE_FTP, "ProFTPD", 0.95f},
    {"220 FileZilla", SERVICE_FTP, "FileZilla", 0.95f},
    {"220 Microsoft FTP", SERVICE_FTP, NULL, 0.90f},
    {"220 vsftpd", SERVICE_FTP, "vsftpd", 0.95f},
    {"220", SERVICE_FTP, NULL, 0.70f},
    {"ESMTP Postfix", SERVICE_SMTP, "Postfix", 0.95f},
    {"ESMTP Sendmail", SERVICE_SMTP, "Sendmail", 0.95f},
    {"Microsoft ESMTP MAIL", SERVICE_SMTP, NULL, 0.95f},
    {"Exim", SERVICE_SMTP, "Exim", 0.95f},
    {"+OK Dovecot", SERVICE_POP3, "Dovecot", 0.95f},
    {"+OK", SERVICE_POP3, NULL, 0.80f},
    {"IMAP4rev1", SERVICE_IMAP, NULL, 0.85f},
    {"Microsoft Exchange", SERVICE_IMAP, NULL, 0.95f},
    {"mysql_native_password", SERVICE_MYSQL, NULL, 0.90f},
    {"PostgreSQL", SERVICE_POSTGRESQL, NULL, 0.90f},
    {"-PONG", SERVICE_REDIS, NULL, 0.95f},
    {"STAT pid", SERVICE_REDIS, NULL, 0.80f},
    {"RFB ", SERVICE_VNC, "RFB ", 0.95f},
    {"git-upload-pack", SERVICE_GIT, NULL, 0.95f},
    {"RTSP/1.0", SERVICE_RTSP, NULL, 0.95f},
    {"SIP/2.0", SERVICE_SIP, NULL, 0.95f},
    {"\"ApiVersion\":", SERVICE_DOCKER, NULL, 0.90f},
    {"\"cluster_name\":", SERVICE_ELASTICSEARCH, "\"version\"", 0.95f},
    {"\x20\x02", SERVICE_MQTT, NULL, 0.90f},
    {"MQIsdp", SERVICE_MQTT, NULL, 0.85f},
    {"\x00\x01\x00\x00", SERVICE_MODBUS, NULL, 0.75f},
    {NULL, SERVICE_UNKNOWN, NULL, 0.0f}};

static int extract_version_naive(const char *text, const char *token, char *out, size_t cap) {
  if (!text || !token || !out || cap == 0) return 0;
  const char *p = strstr(text, token);
  if (!p) return 0;
  p += strlen(token);
  if (*p == 0) return 0;
  if (*p == '/' || *p == '_' || *p == '-' || *p == ':') p++;
  size_t n = 0;
  while (*p && n + 1 < cap) {
    unsigned char c = (unsigned char)*p;
    if (!(isdigit(c) || c == '.' || c == 'p')) break;
    out[n++] = (char)c;
    p++;
  }
  out[n] = 0;
  return n > 0;
}
static void match_signatures_n(const char *banner, size_t len, ServiceInfo *out) {
  if (!banner || !out) return;
  float best = 0.0f;
  char best_ver[64] = {0};
  ServiceInfoType best_t = SERVICE_UNKNOWN;
  for (int i = 0; g_signatures[i].pattern; i++) {
    if (contains_ci_n(banner, len, g_signatures[i].pattern)) {
      if (g_signatures[i].weight > best) {
        best = g_signatures[i].weight;
        best_t = g_signatures[i].service;
        best_ver[0] = 0;
        if (g_signatures[i].version_token) extract_version_naive(banner, g_signatures[i].version_token, best_ver, sizeof(best_ver));
      }
    }
  }
  if (best_t != SERVICE_UNKNOWN) {
    out->type = best_t;
    snprintf(out->name, sizeof(out->name), "%s", service_to_string(best_t));
    if (best_ver[0]) snprintf(out->version, sizeof(out->version), "%s", best_ver);
    out->confidence = best;
  }
}
void match_signatures(const char *banner, ServiceInfo *out) {
  if (!banner || !out) return;
  match_signatures_n(banner, strlen(banner), out);
}
int udp_send_default_probe(int sock, const struct sockaddr_in *dst, int port) {
  const udp_probe_def_t *pd = udp_probe_find((uint16_t)port);
  if (pd) {
    if (pd->probe_kind == PROBE_STATIC_PAYLOAD && pd->payload) {
      size_t n = pd->payload_len ? (size_t)pd->payload_len : strlen((const char *)pd->payload);
      return (int)sendto(sock, (const char *)pd->payload, n, 0, (const struct sockaddr *)dst, sizeof(*dst));
    }
    if (pd->probe_kind == PROBE_BUILDER && pd->build_fn) {
      char tmp[640];
      int n = pd->build_fn(tmp, sizeof(tmp), dst, port);
      if (n > 0) return (int)sendto(sock, tmp, (size_t)n, 0, (const struct sockaddr *)dst, sizeof(*dst));
    }
  }
  unsigned char z = 0;
  return (int)sendto(sock, (const char *)&z, 1, 0, (const struct sockaddr *)dst, sizeof(*dst));
}
ServiceType map_service_to_tunnel(ServiceInfoType t, int proto, int port, const RemotePorts *rp) {
  tcp_web_policy_t web_policy;
  if (proto == IPPROTO_UDP) return SRV_UDP;
  if (t == SERVICE_HTTP) return SRV_HTTP;
  if (t == SERVICE_HTTPS) return SRV_HTTPS;
  if (t == SERVICE_MQTT || t == SERVICE_MODBUS) return SRV_TCP;
  web_policy = tcp_probe_web_policy_remote((uint16_t)port, rp);
  if (web_policy == TCP_WEB_POLICY_HTTP_ONLY || web_policy == TCP_WEB_POLICY_HTTP_TLS) return SRV_HTTP;
  if (web_policy == TCP_WEB_POLICY_TLS_ONLY) return SRV_HTTPS;
  return SRV_TCP;
}

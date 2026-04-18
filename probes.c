#include "probes.h"
#include "scoutless.h"
#include "vendor.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
static int build_sip_options_udp(char *out, size_t cap, const struct sockaddr_in *dst, int port) {
  (void)port;
  if (!out || cap < 16) return -1;
  const char *dstip = dst ? inet_ntoa(dst->sin_addr) : "0.0.0.0";
  int n = snprintf(out, cap, "OPTIONS sip:%s SIP/2.0\r\n" "Via: SIP/2.0/UDP scoutless\r\n" "From: <sip:scoutless@%s>\r\n" "To: <sip:%s>\r\n" "Call-ID: scoutless\r\n"
                   "CSeq: 1 OPTIONS\r\n" "Max-Forwards: 70\r\n" "Content-Length: 0\r\n\r\n", dstip, dstip, dstip);
  if (n <= 0 || (size_t)n >= cap) return -1;
  return n;
}
static int build_sip_options_tcp(char *out, size_t cap, const struct sockaddr_in *dst, int port) {
  (void)port;
  if (!out || cap < 16) return -1;
  const char *dstip = dst ? inet_ntoa(dst->sin_addr) : "0.0.0.0";
  int n = snprintf(out, cap, "OPTIONS sip:%s SIP/2.0\r\n" "Via: SIP/2.0/TCP scoutless\r\n" "From: <sip:scoutless@%s>\r\n" "To: <sip:%s>\r\n" "Call-ID: scoutless\r\n"
                   "CSeq: 1 OPTIONS\r\n" "Max-Forwards: 70\r\n" "Content-Length: 0\r\n\r\n", dstip, dstip, dstip);
  if (n <= 0 || (size_t)n >= cap) return -1;
  return n;
}
static int build_rdp_cr_cookie(char *out, size_t cap, const struct sockaddr_in *dst, int port) {
  (void)dst;
  (void)port;
  static const unsigned char x224[] = { 0x03,0x00,0x00,0x13, 0x0e, 0xe0, 0x00,0x00, 0x00,0x00, 0x00, 0x01, 0x00, 0x08,0x00, 0x03,0x00,0x00,0x00 };
  if (!out || cap < sizeof(x224)) return -1;
  memcpy(out, x224, sizeof(x224));
  return (int)sizeof(x224);
}
static const unsigned char dns_qry[] = { 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 't','e','s','t', 0x00, 0x00, 0x01, 0x00, 0x01 };
static const unsigned char ntp_query[] = { 0x23, 0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 };
static const unsigned char snmp_v2_get_sysdescr[] = { 0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 'p','u','b','l','i','c', 0xa0, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e,
  0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00 };
static const unsigned char natpmp_pubaddr_req[] = { 0x00, 0x00 };
static const unsigned char tftp_rrq[] = { 0x00,0x01, 't','e','s','t',0x00, 'o','c','t','e','t',0x00 };
static const unsigned char nbns_wpad_qry[] = { 0x13,0x37, 0x01,0x10, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x20, 'F','H','F','A','E','B','E','E', 'C','A','C','A','C','A','C','A',
  'C','A','C','A','C','A','C','A', 'C','A','C','A','C','A','C','A', 0x00, 0x00,0x20, 0x00,0x01 };
static const unsigned char rip_req[] = { 0x01, 0x01, 0x00, 0x00 };
static const unsigned char ipmi_rmcp_ping[] = { 0x06,0x00,0xff,0x07, 0x06,0x00,0x00,0x00 };
static const unsigned char coap_discovery[] = { 0x40, 0x01, 0x00, 0x01, 0xbb, '.', 'w','e','l','l','-','k','n','o','w','n', 0x04, 'c','o','r','e' };
static const unsigned char mqtt_connect[] = {0x10, 0x10, 0x00, 0x04, 'M','Q','T','T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x04, 's','c','a','n'};
static const unsigned char modbus_read_holding[] = { 0x00,0x01, 0x00,0x00, 0x00,0x06, 0x01,0x03, 0x00,0x00, 0x00,0x0a };
static const unsigned char bacnet_whois[] = { 0x81,0x0a,0x00,0x0c, 0x01,0x20,0xff,0xff, 0x00,0xff, 0x10,0x08 };
static const unsigned char stun_binding_req[] = { 0x00,0x01, 0x00,0x00, 0x21,0x12,0xA4,0x42, 0x12,0x34,0x56,0x78, 0x9a,0xbc,0xde,0xf0, 0x12,0x34,0x56,0x78 };
static const unsigned char radius_access_req[] = { 0x01, 0x01, 0x00, 0x14, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00 };
static const unsigned char mssql_ssrp_req[] = { 0x02 };
static const unsigned char http_get_root[] = "GET / HTTP/1.1\r\n\r\n";
static const unsigned char ftp_feat[] = "FEAT\r\n";
static const unsigned char smtp_ehlo[] = "EHLO scoutless\r\n";
static const unsigned char pop3_quit[] = "QUIT\r\n";
static const unsigned char imap_cap[] = "a001 CAPABILITY\r\n";
static const unsigned char redis_ping[] = "*1\r\n$4\r\nPING\r\n";
static const unsigned char rtsp_opt[] = "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n";
static const unsigned char memcached_stats[] = "stats\r\n";
static const unsigned char memcached_udp_stats[] = { 0x00,0x01, 0x00,0x00, 0x00,0x01, 0x00,0x00, 's','t','a','t','s','\r','\n' };
static const unsigned char pg_ssl_req[] = { 0x00,0x00,0x00,0x08, 0x04,0xd2,0x16,0x2f };
static const unsigned char smb2_negotiate[] = { 0x00,0x00,0x00,0x90, 0xfe, 'S','M','B', 0x40,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x24,0x00, 0x02,0x00, 0x01,0x00, 0x00,0x00, 0x7f,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00,
  0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00, 0x00,0x00 };
static const unsigned char mongo_ismaster[] = { 0x3a,0x00,0x00,0x00, 0x01,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0xd4,0x07,0x00,0x00, 0x00,0x00,0x00,0x00, 'a','d','m','i','n','.','$','c','m','d',0x00, 0x00,0x00,0x00,0x00,
  0x01,0x00,0x00,0x00, 0x13,0x00,0x00,0x00, 0x10, 'i','s','M','a','s','t','e','r',0x00, 0x01,0x00,0x00,0x00, 0x00 };

#define TCP_HTTP_PROBE(port) { port, "http", "http://", PROBE_STATIC_PAYLOAD, http_get_root, (uint16_t)sizeof(http_get_root)-1, NULL, MATCH_SUBSTR, "HTTP/", PROBE_F_WEB_GET }
#define TCP_NAMED_WEB_PROBE(port, name, scheme, flags) { port, name, scheme, PROBE_STATIC_PAYLOAD, http_get_root, (uint16_t)sizeof(http_get_root)-1, NULL, MATCH_SUBSTR, "HTTP/", flags }
#define TCP_TLS_HINT_PROBE(port, name, scheme) { port, name, scheme, PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, PROBE_F_TLS_HINT }
#define UDP_STATIC_UNICAST_PROBE(port, name, scheme, payload, flags) { port, name, scheme, PROBE_STATIC_PAYLOAD, payload, (uint16_t)sizeof(payload), NULL, MATCH_NONE, NULL, flags }
const tcp_probe_def_t tcp_probes[] = {
  TCP_HTTP_PROBE(80),
  TCP_TLS_HINT_PROBE(443, "https", "https://"),
  TCP_HTTP_PROBE(8080),
  TCP_NAMED_WEB_PROBE(8443, "https", "https://", PROBE_F_TLS_HINT | PROBE_F_WEB_GET),
  TCP_HTTP_PROBE(8000),
  TCP_HTTP_PROBE(5000),
  TCP_HTTP_PROBE(5001),
  TCP_NAMED_WEB_PROBE(7443, "https", "https://", PROBE_F_TLS_HINT | PROBE_F_WEB_GET),
  TCP_NAMED_WEB_PROBE(9443, "https", "https://", PROBE_F_TLS_HINT | PROBE_F_WEB_GET),
  TCP_HTTP_PROBE(8008),
  TCP_HTTP_PROBE(8081),
  TCP_HTTP_PROBE(8888),
  TCP_HTTP_PROBE(8181),
  TCP_HTTP_PROBE(9000),
  TCP_HTTP_PROBE(9001),
  TCP_NAMED_WEB_PROBE(2869, "upnp", "upnp://", PROBE_F_WEB_GET),
  { 554,"rtsp","rtsp://", PROBE_STATIC_PAYLOAD, rtsp_opt, (uint16_t)sizeof(rtsp_opt)-1, NULL, MATCH_SUBSTR, "RTSP/", 0 },
  { 631,"ipp", "ipp://",  PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  { 139, "netbios-ssn", "netbios-ssn://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  { 445,"smb",  "smb://",  PROBE_STATIC_PAYLOAD, smb2_negotiate, (uint16_t)sizeof(smb2_negotiate), NULL, MATCH_PREFIX, "þSMB", PROBE_F_EXPECT_BINARY },
  { 1883,"mqtt","mqtt://",PROBE_STATIC_PAYLOAD, mqtt_connect, (uint16_t)sizeof(mqtt_connect), NULL, MATCH_NONE, NULL, PROBE_F_EXPECT_BINARY },
  { 8883,"mqtt","mqtt://",PROBE_STATIC_PAYLOAD, mqtt_connect, (uint16_t)sizeof(mqtt_connect), NULL, MATCH_NONE, NULL, PROBE_F_TLS_HINT | PROBE_F_EXPECT_BINARY },
  { 5060, "sip", "sip://", PROBE_BUILDER, NULL, 0, build_sip_options_tcp, MATCH_SUBSTR, "SIP/2.0", 0 },
  { 5061, "sip-tls", "sip-tls://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, PROBE_F_TLS_HINT },
  { 53, "dns", "dns://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  TCP_TLS_HINT_PROBE(993, "imaps", "imaps://"),
  TCP_TLS_HINT_PROBE(995, "pop3s", "pop3s://"),
  { 587,"smtp", "smtp://", PROBE_STATIC_PAYLOAD, smtp_ehlo, (uint16_t)sizeof(smtp_ehlo)-1, NULL, MATCH_SUBSTR, "SMTP", PROBE_F_TLS_HINT },
  { 25, "smtp", "smtp://", PROBE_STATIC_PAYLOAD, smtp_ehlo, (uint16_t)sizeof(smtp_ehlo)-1, NULL, MATCH_SUBSTR, "SMTP", 0 },
  { 110,"pop3", "pop3://", PROBE_STATIC_PAYLOAD, pop3_quit, (uint16_t)sizeof(pop3_quit)-1, NULL, MATCH_PREFIX, "+OK", 0 },
  { 143,"imap", "imap://", PROBE_STATIC_PAYLOAD, imap_cap, (uint16_t)sizeof(imap_cap)-1, NULL, MATCH_SUBSTR, "IMAP", 0 },
  { 21, "ftp",  "ftp://",  PROBE_STATIC_PAYLOAD, ftp_feat, (uint16_t)sizeof(ftp_feat)-1, NULL, MATCH_NONE, NULL, 0 },
  { 20, "ftp-data",  "ftp-data://",  PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  { 23, "telnet","telnet://",PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, PROBE_F_BANNER_ONLY },
  { 3306,"mysql","mysql://",PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, PROBE_F_BANNER_ONLY | PROBE_F_EXPECT_BINARY },
  { 5432,"postgresql","postgresql://",PROBE_STATIC_PAYLOAD, pg_ssl_req, (uint16_t)sizeof(pg_ssl_req), NULL, MATCH_NONE, NULL, PROBE_F_EXPECT_BINARY },
  { 6379,"redis","redis://",PROBE_STATIC_PAYLOAD, redis_ping, (uint16_t)sizeof(redis_ping)-1, NULL, MATCH_SUBSTR, "PONG", 0 },
  TCP_NAMED_WEB_PROBE(5985, "winrm", "winrm://", PROBE_F_WEB_GET),
  TCP_NAMED_WEB_PROBE(5986, "winrm", "winrm://", PROBE_F_WEB_GET | PROBE_F_TLS_HINT),
  { 22, "ssh",  "ssh://",  PROBE_NONE, NULL, 0, NULL, MATCH_PREFIX, "SSH-", PROBE_F_BANNER_ONLY },
  { 3389,"rdp", "rdp://",  PROBE_BUILDER, NULL, 0, build_rdp_cr_cookie, MATCH_NONE, NULL, PROBE_F_EXPECT_BINARY },
  { 135, "msrpc", "msrpc://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  { 111, "rpcbind", "rpcbind://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  { 389,"ldap", "ldap://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  TCP_TLS_HINT_PROBE(636, "ldaps", "ldaps://"),
  TCP_HTTP_PROBE(3000),
  TCP_HTTP_PROBE(4848),
  TCP_HTTP_PROBE(5900),
  TCP_HTTP_PROBE(5901),
  TCP_HTTP_PROBE(7001),
  TCP_NAMED_WEB_PROBE(3128, "http-proxy", "http-proxy://", PROBE_F_WEB_GET),
  TCP_TLS_HINT_PROBE(6443, "https", "https://"),
  TCP_HTTP_PROBE(8001),
  TCP_HTTP_PROBE(8002),
  TCP_HTTP_PROBE(8003),
  TCP_HTTP_PROBE(8004),
  TCP_HTTP_PROBE(8005),
  TCP_HTTP_PROBE(8006),
  TCP_HTTP_PROBE(8007),
  TCP_HTTP_PROBE(8090),
  TCP_HTTP_PROBE(8161),
  TCP_HTTP_PROBE(9090),
  TCP_HTTP_PROBE(9200),
  TCP_HTTP_PROBE(15672),
  TCP_TLS_HINT_PROBE(465, "smtps", "smtps://"),
  { 427, "slp", "slp://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  { 502,"modbus","modbus://",PROBE_STATIC_PAYLOAD, modbus_read_holding, (uint16_t)sizeof(modbus_read_holding), NULL, MATCH_NONE, NULL, PROBE_F_EXPECT_BINARY },
  { 548, "afp", "afp://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  { 593, "rpc-http", "rpc-http://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  { 873, "rsync", "rsync://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  { 902, "vmware-auth", "vmware-auth://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  TCP_TLS_HINT_PROBE(989, "ftps", "ftps://"),
  TCP_TLS_HINT_PROBE(990, "ftps", "ftps://"),
  TCP_TLS_HINT_PROBE(10000, "https", "https://"),
  { 1025, "msrpc", "msrpc://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  { 1099, "rmi", "rmi://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  { 11211,"memcached","memcached://",PROBE_STATIC_PAYLOAD, memcached_stats, (uint16_t)sizeof(memcached_stats)-1, NULL, MATCH_SUBSTR, "STAT", 0 },
  { 1433, "mssql", "mssql://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  { 1521, "oracle", "oracle://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  { 1720, "h323", "h323://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  { 1723, "pptp", "pptp://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  { 179, "bgp", "bgp://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  { 2000, "sccp", "sccp://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  { 2049,"nfs", "nfs://",  PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  TCP_NAMED_WEB_PROBE(2375, "docker", "docker://", 0),
  TCP_TLS_HINT_PROBE(2376, "docker", "docker://"),
  { 27017,"mongodb","mongodb://",PROBE_STATIC_PAYLOAD, mongo_ismaster, (uint16_t)sizeof(mongo_ismaster), NULL, MATCH_NONE, NULL, PROBE_F_EXPECT_BINARY },
  { 3268, "ldap", "ldap://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  { 3269, "ldaps", "ldaps://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, PROBE_F_TLS_HINT },
  { 3690, "svn", "svn://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  { 4444, "shell", "shell://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  { 5672, "amqp", "amqp://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  { 9042,"cassandra","cassandra://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 },
  { 9300,"elastic","elastic://", PROBE_NONE, NULL, 0, NULL, MATCH_NONE, NULL, 0 }
};
const size_t tcp_probes_len = sizeof(tcp_probes) / sizeof(tcp_probes[0]);
const udp_probe_def_t udp_probes[] = {
  UDP_STATIC_UNICAST_PROBE(53, "dns", "dns://", dns_qry, 0),
  UDP_STATIC_UNICAST_PROBE(123, "ntp", "ntp://", ntp_query, 0),
  UDP_STATIC_UNICAST_PROBE(5351, "natpmp", "natpmp://", natpmp_pubaddr_req, 0),
  UDP_STATIC_UNICAST_PROBE(137, "nbns", "nbns://", nbns_wpad_qry, 0),
  UDP_STATIC_UNICAST_PROBE(161, "snmp", "snmp://", snmp_v2_get_sysdescr, 0),
  { 5060,"sip",    "sip://",    PROBE_BUILDER, NULL, 0, build_sip_options_udp, MATCH_SUBSTR, "SIP/2.0", 0 },
  UDP_STATIC_UNICAST_PROBE(5683, "coap", "coap://", coap_discovery, 0),
  UDP_STATIC_UNICAST_PROBE(3478, "stun", "stun://", stun_binding_req, 0),
  UDP_STATIC_UNICAST_PROBE(47808, "bacnet", "bacnet://", bacnet_whois, 0),
  UDP_STATIC_UNICAST_PROBE(69, "tftp", "tftp://", tftp_rrq, 0),
  UDP_STATIC_UNICAST_PROBE(623, "ipmi", "ipmi://", ipmi_rmcp_ping, 0),
  UDP_STATIC_UNICAST_PROBE(520, "rip", "rip://", rip_req, 0),
  UDP_STATIC_UNICAST_PROBE(1812, "radius", "radius://", radius_access_req, 0),
  UDP_STATIC_UNICAST_PROBE(1813, "radius", "radius://", radius_access_req, 0),
  UDP_STATIC_UNICAST_PROBE(1434, "mssql", "mssql://", mssql_ssrp_req, 0),
  { 11211,"memcached","memcached://",PROBE_STATIC_PAYLOAD, memcached_udp_stats, (uint16_t)sizeof(memcached_udp_stats), NULL, MATCH_SUBSTR, "STAT", 0 }
};
const size_t udp_probes_len = sizeof(udp_probes) / sizeof(udp_probes[0]);
const tcp_probe_def_t *tcp_probe_find(uint16_t port) {
  for (size_t i = 0; i < tcp_probes_len; i++)
    if (tcp_probes[i].port == port) return &tcp_probes[i];
  return NULL;
}
const udp_probe_def_t *udp_probe_find(uint16_t port) {
  for (size_t i = 0; i < udp_probes_len; i++)
    if (udp_probes[i].port == port) return &udp_probes[i];
  return NULL;
}

tcp_web_policy_t tcp_probe_web_policy(uint16_t port) {
  const tcp_probe_def_t *pd = tcp_probe_find(port);
  if (!pd) return TCP_WEB_POLICY_NONE;
  int has_web = (pd->flags & PROBE_F_WEB_GET) != 0;
  int has_tls = (pd->flags & PROBE_F_TLS_HINT) != 0;
  if (has_web && has_tls) return TCP_WEB_POLICY_HTTP_TLS;
  if (has_web) return TCP_WEB_POLICY_HTTP_ONLY;
  if (has_tls && pd->name && strcmp(pd->name, "https") == 0) return TCP_WEB_POLICY_TLS_ONLY;
  return TCP_WEB_POLICY_NONE;
}
tcp_web_policy_t tcp_probe_web_policy_remote(uint16_t port, const RemotePorts *rp) {
  tcp_web_policy_t policy = tcp_probe_web_policy(port);
  if (policy != TCP_WEB_POLICY_NONE) return policy;
  if (!rp) return TCP_WEB_POLICY_NONE;
  if (remote_ports_has(rp->tcp_http, rp->n_tcp_http, (int)port) && remote_ports_has(rp->tcp_https, rp->n_tcp_https, (int)port)) return TCP_WEB_POLICY_HTTP_TLS;
  if (remote_ports_has(rp->tcp_http, rp->n_tcp_http, (int)port)) return TCP_WEB_POLICY_HTTP_ONLY;
  if (remote_ports_has(rp->tcp_https, rp->n_tcp_https, (int)port)) return TCP_WEB_POLICY_TLS_ONLY;
  return TCP_WEB_POLICY_NONE;
}
static int tcp_probe_is_web_candidate(uint16_t port) {
  return tcp_probe_web_policy(port) != TCP_WEB_POLICY_NONE;
}
int tcp_probe_is_web_candidate_remote(uint16_t port, const RemotePorts *rp) {
  if (!rp) return tcp_probe_is_web_candidate(port);
  return tcp_probe_web_policy_remote(port, rp) != TCP_WEB_POLICY_NONE;
}
static int tcp_probe_stop_after_http(uint16_t port) {
  return tcp_probe_web_policy(port) == TCP_WEB_POLICY_HTTP_ONLY;
}
int tcp_probe_stop_after_http_remote(uint16_t port, const RemotePorts *rp) {
  if (!rp) return tcp_probe_stop_after_http(port);
  return tcp_probe_web_policy_remote(port, rp) == TCP_WEB_POLICY_HTTP_ONLY;
}

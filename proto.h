#pragma once
#include <stddef.h>
#include <netinet/in.h>
#include "scoutless.h"
#include "vendor.h"
typedef enum {
  SERVICE_UNKNOWN = 0,
  SERVICE_HTTP, SERVICE_HTTPS, SERVICE_SSH,
  SERVICE_MQTT, SERVICE_COAP, SERVICE_MODBUS,
  SERVICE_BACNET, SERVICE_KNX, SERVICE_TELNET,
  SERVICE_FTP, SERVICE_FTPS, SERVICE_SMTP,
  SERVICE_POP3, SERVICE_IMAP, SERVICE_SMB,
  SERVICE_MYSQL, SERVICE_POSTGRESQL, SERVICE_MONGODB,
  SERVICE_REDIS, SERVICE_DNS, SERVICE_LDAP,
  SERVICE_RDP, SERVICE_VNC, SERVICE_ELASTICSEARCH,
  SERVICE_DOCKER, SERVICE_GIT, SERVICE_RTSP,
  SERVICE_SIP, SERVICE_SNMP, SERVICE_NTP,
  SERVICE_PROMETHEUS
} ServiceInfoType;
typedef struct {
  ServiceInfoType type;
  char name[64];
  char version[64];
  float confidence;
  char banner[2048];
} ServiceInfo;
typedef struct{const char *pattern;ServiceInfoType service;const char *version_token;float weight;} ServiceSignature;
ServiceInfoType detect_iot_protocol(const unsigned char *buf, size_t len, int port);
ServiceType map_service_to_tunnel(ServiceInfoType t, int proto, int port, const RemotePorts *rp);
void match_signatures(const char *banner, ServiceInfo *out);
int udp_send_default_probe(int sock, const struct sockaddr_in *dst, int port);
const char *service_to_string(ServiceInfoType t);

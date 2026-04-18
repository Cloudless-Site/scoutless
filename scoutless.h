#pragma once
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include "discover.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef int cl_fd_t;
#define MAX_SERVICES DISCOVERY_MAX_SERVICES
typedef enum {
  SRV_TCP = 0,
  SRV_HTTP,
  SRV_HTTPS,
  SRV_UDP,
} ServiceType;
typedef struct {
  char ip[64];
  int  local_port;
  ServiceType type;
  char name[64];
  char svc_hint[192];
} Service;
#ifdef __cplusplus
}
#endif

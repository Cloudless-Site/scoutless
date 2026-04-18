#pragma once
#include "scoutless.h"
typedef struct {
  int http_ok;
  int https_ok;
  int http_status;
  char host_value[128];
  char sni_value[128];
  char redirect_host[128];
  char svc_hint[192];
  ServiceType final_type;
} WebProbeResult;

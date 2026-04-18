#pragma once
#include <stddef.h>
#include <stdint.h>
uint32_t get_default_gateway(void);
uint32_t get_default_gateway_iface(char *iface, size_t iface_sz);
uint32_t get_local_dns(void);
void util_set_gateway_override(const char *ip);
void util_set_local_ip_override(const char *ip);
void util_set_cidr_override(int cidr);
int util_get_local_ip_override(char *dst, size_t dst_sz);
int util_get_cidr_override(void);
int get_local_ip(char *dst, size_t dst_sz);
int iface_rank(const char *iface);

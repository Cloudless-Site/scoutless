#pragma once
#include <stdint.h>
#include <stddef.h>
#include "scoutless.h"
uint64_t now_us(void);
uint64_t now_ms(void);
void sleep_ms(int ms);
void sleep_us(int us);
uint32_t debug_elapsed_total_ms(void);
void dbg_service_found(const char *src, const char *ip, int port, int t, const char *name, const char *hint, uint32_t total_ms, uint32_t connect_ms, uint32_t match_ms);
int debug_service_filter_load(const char *path);
int debug_service_filter_match(const char *ip, int port, int proto);
int debug_service_filter_match_ip(const char *ip);
void dbg_service_trace(const char *phase, const char *ip, int port, int proto, const char *fmt, ...);
void dbg_host_trace(const char *phase, const char *src, const char *ip, const char *fmt, ...);
void safe_strncpy(char *dst, const char *src, size_t dst_sz);
int is_hard_unreach(int err);
int set_nonblock_fd(int fd);
int contains_ci_n(const char *hay, size_t hlen, const char *needle);
int add_service_unique(Service *list, int *io_n, const char *ip_str, int lport, int rport, ServiceType t, char *name);
void service_set_hint(Service *list, int n, const char *ip_str, int lport, ServiceType t, const char *hint);
void service_clear_hint(Service *list, int n, const char *ip_str, int lport, ServiceType t);
int epoll_add_or_mod_ptr(int ep, int fd, void *ptr, uint32_t events);
int epoll_mod_ptr(int ep, int fd, void *ptr, uint32_t events);
void scout_invariant_failed(const char *expr, const char *file, int line);
void set_nodelay(int fd);
void hard_close(int fd);
#ifdef SCOUT_ENABLE_INVARIANTS
#define SCOUT_ASSERT(expr) ((expr) ? (void)0 : scout_invariant_failed(#expr, __FILE__, __LINE__))
#else
#define SCOUT_ASSERT(expr) ((void)sizeof(expr))
#endif

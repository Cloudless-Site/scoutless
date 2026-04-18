#pragma once
#include <netinet/in.h>
#include <stdint.h>
typedef struct {
    uint8_t done;
    uint8_t in_use;
    uint8_t visible;
    uint16_t expected_src_port;
    int host_idx;
    int local_host_idx;
    int item_idx;
    uint64_t started_ms;
    uint64_t deadline_ms;
} udp_scan_pending_t;
typedef struct {
    struct sockaddr_in dst;
    uint16_t expected_src_port;
} udp_probe_target_t;
typedef struct {
    uint32_t ip;
    int host_idx;
} udp_scan_ip_index_t;
typedef struct {
    uint8_t seen_reply;
    uint32_t best_reply_ms;
} udp_scan_host_timing_t;

#define UDP_SCAN_DRAIN_BUDGET 128
#define UDP_SCAN_MAX_PENDING 4096

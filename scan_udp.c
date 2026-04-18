#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include "scoutless.h"
#include "proto.h"
#include "probes.h"
#include "util.h"
#include "vendor.h"
#include "scan.h"
#include "scan_internal.h"
#include "discover_policy.h"
#include "scan_udp_internal.h"

static void udp_scan_assert_pending_slot(const udp_scan_pending_t *slot) {
    if (!slot) return;
    SCOUT_ASSERT(slot->host_idx >= -1);
    SCOUT_ASSERT(slot->item_idx >= -1);
    if (slot->done) SCOUT_ASSERT(slot->deadline_ms == 0 || slot->deadline_ms >= slot->started_ms);
    if (!slot->done) SCOUT_ASSERT(slot->deadline_ms >= slot->started_ms);
    if (!slot->in_use) SCOUT_ASSERT(slot->visible == 0);
}
static int udp_scan_ip_index_cmp(const void *a, const void *b) {
    const udp_scan_ip_index_t *ia = (const udp_scan_ip_index_t *)a;
    const udp_scan_ip_index_t *ib = (const udp_scan_ip_index_t *)b;
    if (ia->ip < ib->ip) return -1;
    if (ia->ip > ib->ip) return 1;
    return 0;
}
static int udp_scan_host_timeout_ms(const udp_scan_host_timing_t *timing) {
    int timeout_ms = discovery_udp_timeout_ms();
    if (!timing || !timing->seen_reply || timing->best_reply_ms == 0) return timeout_ms;
    int base_ms = (int)(timing->best_reply_ms * 2U + 50U);
    if (base_ms < 150) base_ms = 150;
    if (base_ms > timeout_ms) base_ms = timeout_ms;
    return base_ms;
}
static int udp_scan_prepare_target(const ScanTarget *targets, int n_targets, const UdpPlanItem *udp_items, int udp_n, int host_idx, int item_idx, udp_probe_target_t *out) {
    if (!targets || !udp_items || !out) return -1;
    if (host_idx < 0 || host_idx >= n_targets) return -1;
    if (item_idx < 0 || item_idx >= udp_n) return -1;
    const UdpPlanItem *item = &udp_items[item_idx];
    memset(out, 0, sizeof(*out));
    out->dst.sin_family = AF_INET;
    out->dst.sin_port = htons((uint16_t)item->port);
    out->expected_src_port = (uint16_t)item->port;
    if (inet_pton(AF_INET, targets[host_idx].ip, &out->dst.sin_addr) != 1) return -1;
    const udp_probe_def_t *probe = udp_probe_find((uint16_t)item->port);
    (void)probe;
    return 0;
}
static int udp_scan_send_probe(int udp_fd, const UdpPlanItem *item, const udp_probe_target_t *target) {
    if (udp_fd < 0 || !item || !target) return -1;
    if (item->is_vendor_probe && item->vp) {
        const struct vendor_probe *vp = item->vp;
        if (vp->send_is_hex && vp->send_hex_len)
            return (int)sendto(udp_fd, (const char *)vp->send_hex, vp->send_hex_len, 0, (const struct sockaddr *)&target->dst, sizeof(target->dst));
        else if (vp->send_text[0])
            return (int)sendto(udp_fd, vp->send_text, strlen(vp->send_text), 0, (const struct sockaddr *)&target->dst, sizeof(target->dst));
        else
            return (int)sendto(udp_fd, "", 0, 0, (const struct sockaddr *)&target->dst, sizeof(target->dst));
    }
    return udp_send_default_probe(udp_fd, &target->dst, item->port);
}
static void udp_scan_drain_readable_fd(int udp_fd, udp_scan_pending_t *pending, int n_pending, const ScanTarget *targets, int n_targets, const UdpPlanItem *udp_items, int udp_n, const udp_scan_ip_index_t *ip_index, int host_base, int block_targets, udp_scan_host_timing_t *host_timing, Service *list, int *out_n, int max_services);
static int udp_scan_compute_timeout_ms(const udp_scan_pending_t *pending, int n_pending);
static void udp_scan_expire_pending(udp_scan_pending_t *pending, int n_pending, const ScanTarget *targets, const UdpPlanItem *udp_items);

static void udp_scan_wait_pacing_or_events(int ep, int udp_fd, udp_scan_pending_t *pending, int n_pending, const ScanTarget *targets, int n_targets, const UdpPlanItem *udp_items, int udp_n, const udp_scan_ip_index_t *ip_index, int host_base, int block_targets, udp_scan_host_timing_t *host_timing, Service *list, int *out_n, int max_services, int pacing_us) {
    if (ep < 0 || udp_fd < 0 || pacing_us <= 0) return;
    uint64_t now = now_ms();
    uint64_t deadline = now + (uint64_t)((pacing_us + 999) / 1000);
    for (;;) {
        now = now_ms();
        if (now >= deadline) return;
        int wait_ms = (int)(deadline - now);
        if (wait_ms <= 0) wait_ms = 1;
        struct epoll_event events[128];
        int nev = epoll_wait(ep, events, (int)(sizeof(events) / sizeof(events[0])), wait_ms);
        if (nev < 0) {
            if (errno == EINTR) continue;
            return;
        }
        if (nev > 0) udp_scan_drain_readable_fd(udp_fd, pending, n_pending, targets, n_targets, udp_items, udp_n, ip_index, host_base, block_targets, host_timing, list, out_n, max_services);
    }
}
static int udp_scan_slot_matches_reply(const udp_scan_pending_t *slot, const ScanTarget *targets, int n_targets, const UdpPlanItem *udp_items, int udp_n, const char *src_ip_str, int src_port, const unsigned char *buf, size_t len) {
    if (!slot || !targets || !udp_items || !src_ip_str) return 0;
    udp_scan_assert_pending_slot(slot);
    if (!slot->in_use || !slot->visible || slot->done) return 0;
    if (slot->host_idx < 0 || slot->host_idx >= n_targets) return 0;
    if (strcmp(targets[slot->host_idx].ip, src_ip_str) != 0) return 0;
    if (slot->item_idx < 0 || slot->item_idx >= udp_n) return 0;
    const UdpPlanItem *item = &udp_items[slot->item_idx];
    if (slot->expected_src_port != 0 && slot->expected_src_port != (uint16_t)src_port) return 0;
    if (item->is_vendor_probe && item->vp) {
        if (!(vendor_probe_expect_match(item->vp, (const char *)buf, len) || item->force_publish)) return 0;
    }
    return 1;
}
static void udp_scan_publish_reply(Service *list, int *out_n, const UdpPlanItem *item, const char *src_ip_str, int src_port, uint64_t started_ms) {
    if (!list || !out_n || !item || !src_ip_str) return;
    (void)src_port;
    char udp_name[64]; udp_name[0] = 0;
    const udp_probe_def_t *probe = udp_probe_find((uint16_t)item->port);
    if (probe && probe->name) safe_strncpy(udp_name, probe->name, sizeof(udp_name));
    else safe_strncpy(udp_name, "udp", sizeof(udp_name));
    add_service_unique(list, out_n, src_ip_str, item->port, item->port, item->forced, udp_name);
    dbg_service_trace("reply", src_ip_str, item->port, IPPROTO_UDP, "src_port=%d", src_port);
    uint64_t ended_ms = now_ms();
    uint32_t match_ms = started_ms != 0 && ended_ms > started_ms ? (uint32_t)(ended_ms - started_ms) : 0;
    dbg_service_found("udp", src_ip_str, item->port, item->forced, udp_name, NULL, match_ms, 0, match_ms);
}
static int udp_scan_receive_one(int udp_fd, unsigned char *buf, size_t cap, struct sockaddr_in *from, int *src_port, char *src_ip_str, size_t src_cap) {
    if (!buf || !from || !src_port || !src_ip_str || src_cap == 0) return -1;
    socklen_t fl = sizeof(*from);
    ssize_t r = recvfrom(udp_fd, (char *)buf, cap, 0, (struct sockaddr *)from, &fl);
    if (r < 0) {
        if (errno == EINTR) return -2;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return -3;
        return -1;
    }
    if (r == 0) return 0;
    *src_port = ntohs(from->sin_port);
    inet_ntop(AF_INET, &from->sin_addr, src_ip_str, (socklen_t)src_cap);
    return (int)r;
}
static int udp_scan_find_host_idx(const udp_scan_ip_index_t *ip_index, int n_targets, uint32_t src_ip) {
    if (!ip_index || n_targets <= 0) return -1;
    udp_scan_ip_index_t key;
    key.ip = src_ip;
    key.host_idx = 0;
    udp_scan_ip_index_t *found = bsearch(&key, ip_index, (size_t)n_targets, sizeof(*ip_index), udp_scan_ip_index_cmp);
    if (!found) return -1;
    return found->host_idx;
}
static int udp_scan_find_pending_start(const udp_scan_pending_t *pending, int n_pending, int block_targets, int local_host_idx) {
    if (!pending || n_pending <= 0 || block_targets <= 0 || local_host_idx < 0 || local_host_idx >= block_targets) return -1;
    for (int i = local_host_idx; i < n_pending; i += block_targets) {
        if (!pending[i].in_use) continue;
        if (!pending[i].visible) continue;
        if (pending[i].done) continue;
        if (pending[i].deadline_ms == 0) continue;
        return i;
    }
    return -1;
}
static void udp_scan_drain_readable_fd(int udp_fd, udp_scan_pending_t *pending, int n_pending, const ScanTarget *targets, int n_targets, const UdpPlanItem *udp_items, int udp_n, const udp_scan_ip_index_t *ip_index, int host_base, int block_targets, udp_scan_host_timing_t *host_timing, Service *list, int *out_n, int max_services) {
    for (int drain_budget = UDP_SCAN_DRAIN_BUDGET; drain_budget > 0; drain_budget--) {
        unsigned char buf[1024];
        struct sockaddr_in from;
        char src_ip_str[64];
        int src_port;
        int r = udp_scan_receive_one(udp_fd, buf, sizeof(buf), &from, &src_port, src_ip_str, sizeof(src_ip_str));
        if (r == -3) break;
        if (r <= 0) continue;
        int host_idx = udp_scan_find_host_idx(ip_index, n_targets, ntohl(from.sin_addr.s_addr));
        if (host_idx < 0) continue;
        if (host_idx < host_base || host_idx >= host_base + block_targets) continue;
        int local_host_idx = host_idx - host_base;
        int item_idx = udp_scan_find_pending_start(pending, n_pending, block_targets, local_host_idx);
        if (item_idx < 0) continue;
        for (; item_idx < n_pending; item_idx += block_targets) {
            if (*out_n >= max_services) return;
            if (!pending[item_idx].in_use) continue;
            if (!pending[item_idx].visible) continue;
            if (pending[item_idx].done) continue;
            if (pending[item_idx].deadline_ms == 0) continue;
            if (pending[item_idx].host_idx != host_idx) continue;
            if (pending[item_idx].local_host_idx != local_host_idx) continue;
            if (!udp_scan_slot_matches_reply(&pending[item_idx], targets, n_targets, udp_items, udp_n, src_ip_str, src_port, buf, (size_t)r)) continue;
            const UdpPlanItem *item = &udp_items[pending[item_idx].item_idx];
            if (host_timing && local_host_idx >= 0 && local_host_idx < block_targets) {
                uint64_t ended_ms = now_ms();
                uint32_t reply_ms = pending[item_idx].started_ms != 0 && ended_ms > pending[item_idx].started_ms ? (uint32_t)(ended_ms - pending[item_idx].started_ms) : 0;
                if (reply_ms > 0) {
                    if (!host_timing[local_host_idx].seen_reply || reply_ms < host_timing[local_host_idx].best_reply_ms) {
                        host_timing[local_host_idx].best_reply_ms = reply_ms;
                        host_timing[local_host_idx].seen_reply = 1;
                    }
                }
            }
            udp_scan_publish_reply(list, out_n, item, src_ip_str, src_port, pending[item_idx].started_ms);
            pending[item_idx].visible = pending[item_idx].in_use = 0;
            pending[item_idx].done = 1;
            break;
        }
    }
}
static int udp_scan_open_fd(void) {
    cl_fd_t udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if ((int)udp_fd < 0) return -1;
    (void)set_nonblock_fd(udp_fd);
    int rcv = 512 * 1024;
    (void)setsockopt(udp_fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
    return udp_fd;
}
static int udp_scan_open_epoll(int udp_fd, void *epoll_ptr) {
    int ep = epoll_create1(0);
    if (ep < 0) return -1;
    if (epoll_add_or_mod_ptr(ep, udp_fd, epoll_ptr, EPOLLIN | EPOLLERR | EPOLLHUP) != 0) {
        close(ep);
        return -1;
    }
    return ep;
}
static int udp_scan_build_ip_index(const ScanTarget *targets, int n_targets, udp_scan_ip_index_t *ip_index) {
    if (!targets || n_targets <= 0 || !ip_index) return -1;
    for (int i = 0; i < n_targets; i++) {
        struct in_addr ia;
        if (inet_pton(AF_INET, targets[i].ip, &ia) == 1) ip_index[i].ip = ntohl(ia.s_addr);
        ip_index[i].host_idx = i;
    }
    qsort(ip_index, (size_t)n_targets, sizeof(*ip_index), udp_scan_ip_index_cmp);
    return 0;
}
static int udp_scan_compute_host_block_size(int n_targets, int udp_n, int max_pending) {
    int pending_cap = max_pending > 0 ? max_pending : UDP_SCAN_MAX_PENDING;
    if (pending_cap > UDP_SCAN_MAX_PENDING) pending_cap = UDP_SCAN_MAX_PENDING;
    if (udp_n <= 0) return n_targets;
    int host_block = pending_cap / udp_n;
    if (host_block <= 0) host_block = 1;
    if (host_block > n_targets) host_block = n_targets;
    return host_block;
}
static void udp_scan_init_pending_slots(udp_scan_pending_t *pending, int n_pending) {
    if (!pending || n_pending <= 0) return;
    for (int i = 0; i < n_pending; i++) pending[i].done = 1;
}
static void udp_scan_reset_pending_slot(udp_scan_pending_t *slot) {
    if (!slot) return;
    memset(slot, 0, sizeof(*slot));
    slot->host_idx = slot->local_host_idx = slot->item_idx = -1;
    slot->done = 1;
}
static int udp_scan_send_block_item(int udp_fd, int ep, udp_scan_pending_t *pending, int n_pending, const ScanTarget *targets, int n_targets, const UdpPlanItem *udp_items, int udp_n, const udp_scan_ip_index_t *ip_index, int host_base, int block_targets, udp_scan_host_timing_t *host_timing, Service *list, int *out_n, int max_services, int pacing_us, int item_idx) {
    if (udp_fd < 0 || !pending || !targets || !udp_items || !ip_index || !host_timing || !list || !out_n) return -1;
    if (item_idx < 0 || item_idx >= udp_n) return -1;
    for (int local_host_idx = 0; local_host_idx < block_targets; local_host_idx++) {
        int host_idx = host_base + local_host_idx;
        int idx = item_idx * block_targets + local_host_idx;
        udp_scan_reset_pending_slot(&pending[idx]);
        udp_probe_target_t probe_target;
        if (udp_scan_prepare_target(targets, n_targets, udp_items, udp_n, host_idx, item_idx, &probe_target) != 0) continue;
        pending[idx].expected_src_port = probe_target.expected_src_port;
        pending[idx].host_idx = host_idx;
        pending[idx].local_host_idx = local_host_idx;
        pending[idx].item_idx = item_idx;
        pending[idx].started_ms = now_ms();
        pending[idx].deadline_ms = pending[idx].started_ms + (uint64_t)udp_scan_host_timeout_ms(&host_timing[local_host_idx]);
        pending[idx].in_use = 1;
        dbg_service_trace("send", targets[host_idx].ip, udp_items[item_idx].port, IPPROTO_UDP, "expected_src_port=%u", (unsigned)probe_target.expected_src_port);
        if (udp_scan_send_probe(udp_fd, &udp_items[item_idx], &probe_target) < 0) {
            dbg_service_trace("send-fail", targets[host_idx].ip, udp_items[item_idx].port, IPPROTO_UDP, "errno=%d", errno);
            pending[idx].in_use = pending[idx].visible = pending[idx].deadline_ms = 0;
            pending[idx].done = 1;
            continue;
        }
        pending[idx].done = 0;
        pending[idx].visible = 1;
        dbg_service_trace("wait", targets[host_idx].ip, udp_items[item_idx].port, IPPROTO_UDP, "deadline_ms=%u pacing_us=%d", (unsigned)(pending[idx].deadline_ms - pending[idx].started_ms), pacing_us);
        udp_scan_assert_pending_slot(&pending[idx]);
        udp_scan_drain_readable_fd(udp_fd, pending, n_pending, targets, n_targets, udp_items, udp_n, ip_index, host_base, block_targets, host_timing, list, out_n, max_services);
        if (pacing_us > 0) udp_scan_wait_pacing_or_events(ep, udp_fd, pending, n_pending, targets, n_targets, udp_items, udp_n, ip_index, host_base, block_targets, host_timing, list, out_n, max_services, pacing_us);
        if (*out_n >= max_services) return 1;
    }
    return 0;
}
static void udp_scan_wait_pending_block(int ep, int udp_fd, udp_scan_pending_t *pending, int n_pending, const ScanTarget *targets, int n_targets, const UdpPlanItem *udp_items, int udp_n, const udp_scan_ip_index_t *ip_index, int host_base, int block_targets, udp_scan_host_timing_t *host_timing, Service *list, int *out_n, int max_services) {
    for (;;) {
        if (*out_n >= max_services) break;
        udp_scan_expire_pending(pending, n_pending, targets, udp_items);
        for (int i = 0; i < n_pending; i++) udp_scan_assert_pending_slot(&pending[i]);
        int timeout_ms = udp_scan_compute_timeout_ms(pending, n_pending);
        if (timeout_ms < 0) break;
        struct epoll_event events[128];
        int nev = epoll_wait(ep, events, (int)(sizeof(events) / sizeof(events[0])), timeout_ms);
        if (nev < 0 && errno == EINTR) continue;
        if (nev > 0) udp_scan_drain_readable_fd(udp_fd, pending, n_pending, targets, n_targets, udp_items, udp_n, ip_index, host_base, block_targets, host_timing, list, out_n, max_services);
    }
}

static int udp_scan_compute_timeout_ms(const udp_scan_pending_t *pending, int n_pending) {
    int timeout_ms = -1;
    int any_pending = 0;
    uint64_t now = now_ms();
    for (int i = 0; i < n_pending; i++) {
        if (pending[i].done) continue;
        int left = (int)(pending[i].deadline_ms - now);
        if (left <= 0) continue;
        any_pending = 1;
        if (timeout_ms < 0 || left < timeout_ms) timeout_ms = left;
    }
    if (!any_pending) return -1;
    if (timeout_ms < 0) return 0;
    return timeout_ms;
}
static void udp_scan_expire_pending(udp_scan_pending_t *pending, int n_pending, const ScanTarget *targets, const UdpPlanItem *udp_items) {
    uint64_t now = now_ms();
    for (int i = 0; i < n_pending; i++) {
        if (!pending[i].in_use || !pending[i].visible || pending[i].done) continue;
        if (pending[i].deadline_ms <= now) {
            if (targets && udp_items && pending[i].host_idx >= 0 && pending[i].item_idx >= 0)
                dbg_service_trace("timeout", targets[pending[i].host_idx].ip, udp_items[pending[i].item_idx].port, IPPROTO_UDP, "deadline_ms=%u", (unsigned)(pending[i].deadline_ms - pending[i].started_ms));
            pending[i].visible = pending[i].in_use = pending[i].deadline_ms = 0;
            pending[i].done = 1;
        }
    }
}
void scan_udp_targets_paced_limited(const ScanTarget *targets, int n_targets, const UdpPlanItem *udp_items, int udp_n, const RemotePorts *rp, Service *list, int *out_n, int pacing_us, int max_pending, int max_services) {
    if (!targets || n_targets <= 0 || !udp_items || udp_n <= 0 || !list || !out_n) return;
    (void)rp;

    if (max_services <= 0) max_services = MAX_SERVICES;
    if (*out_n >= max_services) return;
    udp_scan_ip_index_t *ip_index = calloc((size_t)n_targets, sizeof(*ip_index));
    if (!ip_index) return;
    if (udp_scan_build_ip_index(targets, n_targets, ip_index) != 0) {
        free(ip_index);
        return;
    }
    int udp_fd = udp_scan_open_fd();
    if (udp_fd < 0) {
        free(ip_index);
        return;
    }
    int udp_epoll_token = 0;
    int ep = udp_scan_open_epoll(udp_fd, &udp_epoll_token);
    if (ep < 0) {
        close(udp_fd);
        free(ip_index);
        return;
    }
    int host_block = udp_scan_compute_host_block_size(n_targets, udp_n, max_pending);
    for (int host_base = 0; host_base < n_targets && *out_n < max_services; host_base += host_block) {
        int block_targets = n_targets - host_base;
        if (block_targets > host_block) block_targets = host_block;
        int n_pending = block_targets * udp_n;
        udp_scan_pending_t *pending = calloc((size_t)n_pending, sizeof(*pending));
        if (!pending) break;
        udp_scan_host_timing_t *host_timing = calloc((size_t)block_targets, sizeof(*host_timing));
        if (!host_timing) {
            free(pending);
            break;
        }
        udp_scan_init_pending_slots(pending, n_pending);
        for (int item_idx = 0; item_idx < udp_n && *out_n < max_services; item_idx++) {
            if (udp_scan_send_block_item(udp_fd, ep, pending, n_pending, targets, n_targets, udp_items, udp_n, ip_index, host_base, block_targets, host_timing, list, out_n, max_services, pacing_us, item_idx) != 0) break;
        }
        udp_scan_wait_pending_block(ep, udp_fd, pending, n_pending, targets, n_targets, udp_items, udp_n, ip_index, host_base, block_targets, host_timing, list, out_n, max_services);
        udp_scan_drain_readable_fd(udp_fd, pending, n_pending, targets, n_targets, udp_items, udp_n, ip_index, host_base, block_targets, host_timing, list, out_n, max_services);
        free(host_timing);
        free(pending);
    }
    (void)epoll_ctl(ep, EPOLL_CTL_DEL, udp_fd, NULL);
    close(udp_fd);
    close(ep);
    free(ip_index);
}

#define _POSIX_C_SOURCE 200809L
#include "vendor.h"
#include "util.h"
#include <string.h>
static int contains_bin_n(const unsigned char *hay, size_t hlen, const unsigned char *needle, size_t nlen) {
  size_t off;
  if (!hay || !needle || nlen == 0 || hlen < nlen) return 0;
  for (off = 0; off + nlen <= hlen; off++) {
    if (memcmp(hay + off, needle, nlen) == 0) return 1;
  }
  return 0;
}

#include "scoutless.h"
int remote_ports_has(const int *arr, int n, int port) {
  if (!arr || n <= 0) return 0;
  for (int i = 0; i < n; i++) {
    if (arr[i] == port) return 1;
  }
  return 0;
}

void remote_ports_add(int *arr, int *n, int port) {
  if (!arr || !n || *n < 0 || *n >= MAX_REMOTE_PORTS) return;
  if (remote_ports_has(arr, *n, port)) return;
  arr[*n] = port;
  (*n)++;
}


int vendor_probe_expect_match(const struct vendor_probe *vp, const char *buf, size_t len) {
  if (!vp || !buf) return 0;
  if (vp->expect_is_hex) {
    if (vp->expect_hex_len == 0) return 1;
    return contains_bin_n((const unsigned char *)buf, len, vp->expect_hex, vp->expect_hex_len);
  }
  if (!vp->expect_substr[0]) return 1;
  return contains_ci_n(buf, len, vp->expect_substr);
}

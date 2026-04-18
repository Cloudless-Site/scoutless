#pragma once
#include <stdint.h>
#include "discover_targets.h"
int discovery_build_targets(const DiscoveryContext *ctx, const uint32_t *seeds, int n_seeds, DiscoveryTarget *targets);
void discovery_run_host_discovery_loop(const DiscoveryContext *ctx, DiscoveryTarget *targets, int *n_targets);

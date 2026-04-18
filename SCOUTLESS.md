
## 🔍 Overview

Scoutless is a high-performance network discovery tool written in C, designed to operate with minimal overhead and maximum control over network interactions.

## ⚙️  Design Principles

- Event-driven architecture based on epoll
- Global pacing to avoid network stress
- No unnecessary abstractions or external dependencies
- Direct socket control for TCP, UDP, and ICMP

## 🚀 Key Characteristics

- Fast host discovery using multicast + ICMP
- Incremental expansion strategy for network exploration
- TCP and UDP service discovery with non-blocking I/O
- Single-socket UDP design for efficiency

## 🧠 Performance Strategy

- Global pacing applied to all probes
- Windowed scanning using epoll entries
- Minimal memory overhead and predictable behavior


# Scoutless

## 🎯 Scope

Scoutless is a local-network host and service discovery tool written in C.

In this source tree it is focused on:
- IPv4 local network discovery
- bounded host discovery
- bounded TCP service discovery
- bounded UDP service discovery
- lightweight HTTP/HTTPS classification on selected TCP ports

It is not documented here as a generic internet scanner, OS fingerprinting engine, or scripting platform, because those capabilities are not present in these sources.

## ⚙️  Execution model

Scoutless is single-process and event-driven.

The code uses:
- non-blocking sockets
- `epoll`
- explicit per-target and per-slot state
- global pacing overrides shared across discovery and service scans

There is no thread scheduler in this code path.

## 🗂️ Source layout

Main files in this tree:
- `src/scoutless.c` — CLI parsing, runtime overrides, optional plan loading, final output
- `src/discover.c` — top-level orchestration
- `src/discover_targets.c` — network context, seed generation, target set management
- `src/discover_hosts.c` — host discovery loop and expansion
- `src/discover_passive.c` — passive/multicast discovery and initial ICMP step
- `src/scan_liveness.c` — TCP liveness sweep
- `src/scan_tcp.c`, `src/scan_tcp_slot.c`, `src/scan_tcp_probe.c` — TCP service scan and probe handling
- `src/scan_udp.c` — UDP service scan
- `src/web_probe.c`, `src/web_probe_policy.c`, `src/web_probe_proto.c` — HTTP/HTTPS detection and hint generation
- `src/probes.c` — built-in TCP and UDP probe lists
- `src/plan.c` — external plan file parser

## 📏 Runtime limits and defaults

Important constants from the current sources:
- maximum discovered hosts: `2048`
- maximum reported services: `2048`
- small-network threshold: less than `1024` hosts
- initial window radius on large networks: `128`
- expansion radius around each newly alive host: `4`
- default global pacing: `10000` microseconds
- default global burst max: `128`
- default global epoll max: `64` 
- default service budget constant: `120000` ms

The host and service caps are hard limits in the current implementation.

## 📶 Network context and scan modes

At startup Scoutless builds a `DiscoveryContext` from the local interface, local IPv4 address, netmask, default gateway, and local DNS.

Two scan modes exist:
- `full`
- `window`

Selection rules in current code:
- if the network has fewer than `1024` hosts, Scoutless uses `full`
- otherwise it uses `window`
- `--force-large-net` forces `window` even on smaller networks

For `/31` networks, seed generation uses the two valid addresses in that network model.

## 👥 Initial target population

Initial targets are built from seed host indexes.

Behavior depends on scan mode.

### 🔥 Full mode

In `full` mode, Scoutless seeds the whole local subnet except the local host.

### 🪟 Window mode

In `window` mode, Scoutless seeds:
- a window of `±128` around the local host index
- a window of `±128` around the gateway index when the gateway is inside the local subnet

Bounds are clamped so addresses outside the subnet are not added.

Duplicate targets are rejected.

## 🔍 Host discovery flow

The host discovery loop implemented by `discovery_run_host_discovery_loop()` is:

1. initial multicast + ICMP step
2. TCP liveness step on unresolved targets, unless disabled
3. repeated expansion loop:
   - expand target windows by `±4` around newly alive hosts not yet expanded
   - ICMP-only step on new unresolved targets
   - TCP liveness step again, unless disabled
4. stop when no new targets are added or when the host cap is reached

If the host cap is reached, pending unresolved targets are marked done and scanning stops.

## 📡 Initial multicast + ICMP phase

The initial host-discovery sweep combines passive discovery traffic and ICMP handling in one epoll-driven phase.

Passive probes sent by the current code are:
- SSDP M-SEARCH to `239.255.255.250:1900`
- mDNS query to `224.0.0.251:5353`
- WS-Discovery probe to `239.255.255.250:3702`
- LLMNR query to `224.0.0.252:5355`
- NBNS broadcast query to `255.255.255.255:137`

ICMP behavior in current code:
- first try raw ICMP socket
- if that fails, fall back to datagram ICMP socket
- if both fail, the passive part can still run
- any received ICMP reply is treated as a positive signal for that source IP

When a passive or ICMP reply is received, the source IP is marked alive if it belongs to the current subnet and the host cap has not been reached.

## 🔌 TCP liveness phase

TCP liveness is used after the initial sweep and after later expansion sweeps unless disabled with `--disable-tcp-liveness`.

The liveness sweep is paced and epoll-based.

The window size is:
- `global_epoll_max` when explicitly set
- otherwise the configured/default internal value, bounded by the implementation

Targets already known alive are skipped.

## 🧭 Service discovery flow

After host discovery finishes, Scoutless builds a scan plan and runs:
- TCP service discovery first
- UDP service discovery second

Only hosts marked alive are considered scan candidates.

The local host is excluded from service scanning.

Per-host timeout for service scans is derived from host discovery timing through `discovery_host_scan_timeout_ms()`.

## 📋 Default built-in plan

If no external plan is provided, Scoutless builds its service plan from the built-in probe arrays in `src/probes.c`.

That default plan includes many common TCP and UDP service ports already encoded in the source.

Examples present in the current TCP list include ports for:
- HTTP and HTTPS variants
- RTSP
- IPP
- SMB
- MQTT
- SIP
- DNS over TCP
- mail protocols
- FTP
- Telnet
- MySQL
- PostgreSQL
- Redis
- WinRM
- SSH
- RDP
- LDAP and LDAPS
- Docker
- MongoDB
- Cassandra
- Elastic

Examples present in the current UDP list include ports for:
- DNS
- NTP
- NAT-PMP
- NBNS
- SNMP
- SIP
- CoAP
- STUN
- BACnet
- TFTP
- IPMI
- RIP
- RADIUS
- SQL Server SSRP
- Memcached

The exact order is defined by `tcp_probes[]` and `udp_probes[]`.

## 🔗 External plan files

`--plan <path>` loads a text plan file.

The parser supports port declarations beginning with:
- `tcp`
- `udp`

Per-port data can also include:
- `send_text`
- `send_hex`
- `expect_substr`
- optional `force_publish`

A loaded external plan replaces the default built-in plan for the protocols it provides through the generated plan structures used at runtime.

If a plan file is loaded but contains no ports, Scoutless reports `plan: missing ports` and falls back to no external plan.

## 🌐 Web probing and classification

Selected TCP ports can trigger additional HTTP/HTTPS probing.

Web classification is driven by:
- built-in probe metadata in `src/probes.c`
- remote port hints when present
- web probe state and result selection logic in `src/web_probe_policy.c`

The current implementation can:
- attempt HTTP-oriented probing on web candidates
- attempt TLS probing on TLS-capable candidates
- build service hints that may include `?host=` and/or `?sni=`

The public-domain value used by TLS/public-host probing defaults to:
- `g-12345.cloudless.site`

It can be overridden with:
- `--public-domain <name>`

## 💻 CLI options currently implemented

The current `scoutless.c` parses these options:
- `--debug`
- `--plan <path>`
- `--public-domain <name>`
- `--gateway <ipv4>`
- `--ip <ipv4>`
- `--cidr <bits>`
- `--debug-services-file <path>`
- `--disable-tcp-liveness`
- `--disable-icmp-liveness`
- `--debug-services-all`
- `--deeper`
- `--aggressive`
- `--burst <n>`
- `--epoll <n>`
- `--pacing <microseconds>`
- `--force-large-net`

Current behavior of notable options:
- `--gateway`, `--ip`, and `--cidr` override detected local network values
- `--deeper` sets burst `32`, epoll `32`, pacing `20000`
- `--aggressive` sets burst `1024`, epoll `1024`, pacing `2`
- explicit `--burst`, `--epoll`, and `--pacing` override the runtime defaults directly
- `--debug-services-file` loads a service filter and also enables debug mode

## 📤 Output format

Final output is produced after service sorting.

Services are sorted by:
- IP address
- service type rank
- local port
- service name

Each service is printed as a pseudo-URL.

Examples of formats produced by the current code:
- `http://192.168.1.10:80/svc/http`
- `https://192.168.1.20:443?sni=example.local`
- `tcp://192.168.1.30:22/svc/ssh`
- `udp://192.168.1.40:161/svc/snmp`

When web probing produces a service hint, that hint is printed instead of the default `/svc/<name>` suffix.

## 📱 Android note

This source tree contains no Android-specific API layer inside Scoutless itself.

The implementation here is still plain C using sockets and `epoll`.

That does not imply identical behavior across all Android devices. It only means the scanner core in this tree does not contain a separate Android-only execution path in the documented files above.

## 🚫 Non-goals for this document

This document intentionally does not claim:
- OS fingerprinting
- NSE-like scripting
- SYN scan support
- internet-wide scan features
- packet crafting beyond the probes visible in these sources
- Windows backend support in this tree

Those claims would not be aligned with the current source base.


## ⚠️  Real Behavior

Scoutless does not rely on passive assumptions or protocol purity.

- Any ICMP response is treated as valid (no strict filtering)
- Discovery is driven by observed responses, not predefined topology
- Host expansion is dynamic (new hosts generate new scan windows)
- No blocking operations: everything is non-blocking and epoll-driven

## 🧩 Discovery Pipeline

1. Initial multicast + ICMP phase
2. Host expansion via response-driven windows
3. TCP liveness validation
4. TCP service discovery (connect + probe)
5. UDP discovery using single socket + recvfrom drain

Each phase is constrained only by global pacing and epoll capacity.

## 🔬 Critical Design Constraints

- Global pacing is enforced across ALL protocols (ICMP, TCP, UDP)
- No per-module rate control divergence allowed
- Epoll loop must never be blocked by synchronous operations
- UDP receive path must always be drained to avoid packet loss

## ⚠️  Known Fragilities (Design Awareness)

- Incorrect pacing propagation can stall entire discovery
- Blocking probe paths can break epoll fairness
- UDP matching inefficiencies can become O(n²) under load
- Mis-accounted inflight targets can lead to infinite loops

These are not abstract risks but concrete failure modes observed during development.


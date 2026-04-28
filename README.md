# 🔍 Scoutless

Scoutless is a LAN host and service discovery tool written in C.

It is designed for fast, bounded, real-world local-network discovery with:
- single-process execution
- event-driven I/O (`epoll`)
- strict non-blocking sockets
- global pacing across ICMP, TCP and UDP

This README is used as the public landing page for the dedicated Scoutless GitHub export.

## ⚙️  What it does

Scoutless focuses on:
- IPv4 local network host discovery
- bounded TCP service discovery
- bounded UDP service discovery
- lightweight HTTP/HTTPS classification on selected TCP ports

It does not implement:
- internet-wide scanning
- OS fingerprinting
- scripting engines
- SYN scan techniques

All behavior described here is directly aligned with the current source code.

## 🏗️ Core design

- no threads
- no blocking operations in the scan path
- explicit per-target state
- event-driven execution with `epoll`
- global pacing shared across all protocols
- dynamic host expansion from observed live targets
- single-socket UDP scanning with recvfrom drain
- minimal memory footprint and predictable behavior

## 🔄 Discovery pipeline

Scoutless runs a multi-phase pipeline:

1. multicast + ICMP sweep
2. TCP liveness
3. incremental host expansion
4. TCP service scan (connect + probe)
5. UDP scan

The order is intentional:

- early phases maximize signal collection (ICMP, passive)
- TCP liveness fills gaps where ICMP is unreliable
- expansion is driven by real responses, not assumptions
- UDP is last to avoid interference with TCP probing

In practice, probe ordering has measurable impact.

On some Android devices, running UDP before TCP significantly improves results on unstable Wi-Fi networks.

## 📊 Runtime characteristics

The implementation is strictly bounded:

- maximum hosts: 2048
- maximum services: 2048
- global pacing applied to all probes
- epoll window limits concurrent activity

Typical performance:

- ~30 seconds for a /24 network under normal conditions
- ~2 minutes worst case

Actual timing depends on network behavior and device responsiveness.

## 📤 Output format

Scoutless prints services as pseudo-URLs:

```text
http://192.168.1.10:80/svc/http
https://192.168.1.20:443?sni=device.local
tcp://192.168.1.30:22/svc/ssh
udp://192.168.1.40:161/svc/snmp
```

When web probing detects additional context, hints such as `?host=` or `?sni=` are included.

## ⚠️  Non-obvious behavior

Any ICMP reply is treated as valid.

There is no strict filtering of ICMP types or sequence.

This is a deliberate trade-off:
- increases robustness on inconsistent consumer networks
- tolerates non-standard or partial implementations

## 🛠️ Build

In the dedicated Scoutless GitHub export, build with:

```bash
make
```

## 📚 Documentation

Full technical documentation:

👉 https://github.com/Cloudless-Site/scoutless/blob/main/SCOUTLESS.md

## 🌐 Context

Scoutless is used as the discovery layer in Cloudless.

Its role is to determine, with minimal assumptions, which hosts and services are actually present on a local network, enabling zero-effort exposure workflows.

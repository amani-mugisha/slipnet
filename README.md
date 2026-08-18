# SlipNet

### Network Intelligence Engine

SlipNet is a modern **C++20 network intelligence CLI** designed to discover, analyze, monitor, and understand network environments from the command line.

It combines network discovery, host analysis, port scanning, service detection, packet inspection, topology mapping, security analysis, and AI-assisted intelligence into a modular network analysis engine.

> **Status:** Active development — SlipNet is currently evolving toward a complete network intelligence and security analysis platform.

---

## Overview

Modern networks generate large amounts of information: hosts, interfaces, ports, services, packets, connections, and security events.

SlipNet is being built to turn that raw network information into structured intelligence.

The project follows a modular architecture where individual engines collect and analyze different layers of network information.

```text
                    ┌─────────────────────┐
                    │     SlipNet CLI      │
                    └──────────┬──────────┘
                               │
             ┌─────────────────┼─────────────────┐
             │                 │                 │
             ▼                 ▼                 ▼
       Network Engine     Security Engine    AI Engine
             │                 │                 │
      ┌──────┼──────┐          │                 │
      │      │      │          │                 │
      ▼      ▼      ▼          ▼                 ▼
   Hosts   Ports  Services   Alerts          Analysis
      │      │      │          │                 │
      └──────┴──────┴──────────┴─────────────────┘
                         │
                         ▼
                  Network Intelligence
```

The long-term goal is to make SlipNet a powerful, extensible platform for **network visibility, security analysis, and intelligent network monitoring**.

---

## Features

### Network Discovery

SlipNet provides the foundation for discovering and understanding the local network environment.

* Network interface discovery
* IP address handling
* Network mask detection
* Subnet calculation
* Host discovery
* Network state management

### Host Intelligence

SlipNet maintains structured information about discovered hosts, including:

* IP addresses
* Hostnames
* Online/offline state
* Network latency
* Host status

### Port Analysis

The port analysis engine is designed to identify exposed network services and build an understanding of a host's reachable attack surface.

Current architecture supports:

* Port discovery
* Open/closed state
* Protocol information
* Service association
* Per-host port state

### Service Detection

SlipNet includes a service detection layer for identifying services associated with discovered ports.

The service model supports:

* Service name
* Protocol
* Port
* Version
* Banner information
* Detection status

This information also provides the foundation for future vulnerability and security intelligence.

### Security Analysis

SlipNet includes a defensive, rule-based security analysis engine.

Current checks include:

* Legacy protocol exposure
* FTP exposure
* Telnet exposure
* Database exposure
* MySQL/MariaDB exposure
* PostgreSQL exposure
* MongoDB exposure
* SSH exposure
* RDP exposure
* SMB exposure
* Large attack-surface detection

Security findings are represented as structured alerts with:

```text
Type
Description
Severity
```

Severity levels currently range from:

```text
0 → Informational
1 → Low
2 → Medium
3 → High
```

### Packet Analysis

SlipNet contains a packet analysis layer intended for:

* Packet capture
* Packet inspection
* Protocol analysis
* Traffic intelligence

This subsystem is currently being expanded.

### Network Monitoring

The monitoring subsystem provides the foundation for continuously observing network activity and generating network statistics.

Future development will expand this into:

* Traffic monitoring
* Connection statistics
* Bandwidth analysis
* Network activity trends
* Anomaly detection

### Network Topology

SlipNet includes a topology mapping subsystem for representing discovered network nodes and relationships.

The long-term objective is to transform discovered network information into an understandable topology such as:

```text
                         ┌──────────────┐
                         │   Gateway    │
                         │ 192.168.1.1  │
                         └───────┬──────┘
                                 │
                 ┌───────────────┼───────────────┐
                 │               │               │
                 ▼               ▼               ▼
          ┌────────────┐  ┌────────────┐  ┌────────────┐
          │   Host A   │  │   Host B   │  │   Host C   │
          │ 192.168.1.5│  │192.168.1.10│  │192.168.1.20│
          └────────────┘  └────────────┘  └────────────┘
```

### AI-Assisted Analysis

SlipNet contains an AI analysis subsystem designed to eventually transform raw network measurements into higher-level intelligence.

The planned pipeline is:

```text
Network Data
     │
     ▼
Feature Extraction
     │
     ▼
AI Analysis
     │
     ▼
Risk / Anomaly Assessment
     │
     ▼
Human-readable Intelligence
```

The AI layer is currently under development.

---

# Architecture

SlipNet follows a modular C++ architecture designed to keep network components independent and extensible.

```text
slipnet/
│
├── include/
│   ├── ai/
│   ├── cli/
│   ├── core/
│   ├── host/
│   ├── monitoring/
│   ├── network/
│   ├── packet/
│   ├── port/
│   ├── security/
│   ├── service/
│   └── topology/
│
├── src/
│   ├── ai/
│   ├── cli/
│   ├── core/
│   ├── host/
│   ├── monitoring/
│   ├── network/
│   ├── packet/
│   ├── port/
│   ├── security/
│   ├── service/
│   ├── topology/
│   └── main.cpp
│
├── CMakeLists.txt
└── README.md
```

### Core Components

| Component    | Responsibility                                         |
| ------------ | ------------------------------------------------------ |
| `cli`        | Command parsing, terminal interaction, signal handling |
| `core`       | Shared network state and engine context                |
| `network`    | IP, subnet, interface and network discovery            |
| `host`       | Host discovery and host intelligence                   |
| `port`       | Port analysis and scanning                             |
| `service`    | Service identification                                 |
| `packet`     | Packet capture and inspection                          |
| `monitoring` | Network monitoring and statistics                      |
| `security`   | Defensive security analysis and alerts                 |
| `topology`   | Network topology representation                        |
| `ai`         | Feature extraction and intelligent analysis            |

---

# CLI

SlipNet is designed around an interactive command-line interface.

The command system follows a category/action structure:

```text
category|:action
```

Examples of the current command architecture include:

```text
ip|:seek
host|:find
port|:scan
svc|:detect
topo|:map
pkt|:capture
pkt|:inspect
net|:monitor
net|:show
net|:clear
sec|:detect
ai|:analyze
session|:info
help
fire
```

The command interface will continue to evolve as the underlying engines become more capable.

---

# Building SlipNet

## Requirements

SlipNet currently requires:

* Linux
* C++20-compatible compiler
* CMake 3.20+
* POSIX threading support

The current development environment has been tested with:

```text
GCC 11.4
CMake 3.22+
C++20
```

## Clone

```bash
git clone <YOUR_REPOSITORY_URL>
cd slipnet
```

## Configure

```bash
mkdir build
cd build
cmake ..
```

## Build

```bash
cmake --build . -j$(nproc)
```

The executable will be generated as:

```text
build/slipnet
```

## Run

From the `build` directory:

```bash
./slipnet
```

---

# Development

SlipNet is being developed incrementally.

The development philosophy is to build reliable network primitives first and then combine them into higher-level intelligence.

```text
                    SlipNet
                       │
                       ▼
              Network Discovery
                       │
                       ▼
                 Host Discovery
                       │
                       ▼
                  Port Analysis
                       │
                       ▼
                Service Detection
                       │
                       ▼
                Security Analysis
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
       Packet Analysis      Topology Mapping
             │                   │
             └─────────┬─────────┘
                       ▼
                  AI Analysis
                       │
                       ▼
              Network Intelligence
```

This approach allows each subsystem to become useful independently while also contributing data to higher-level analysis.

---

# Roadmap

## Phase 1 — Core Engine

* [x] C++20 project architecture
* [x] CMake build system
* [x] Interactive CLI foundation
* [x] Network state management
* [x] Network interface architecture
* [x] Host discovery architecture
* [x] Security detection foundation
* [x] AI analysis foundation

## Phase 2 — Network Intelligence

* [ ] Improve network discovery
* [ ] Improve host discovery
* [ ] Expand subnet analysis
* [ ] Improve TCP port scanning
* [ ] Improve service detection
* [ ] Structured scan results
* [ ] Better CLI output

## Phase 3 — Security Intelligence

* [ ] Expand security rules
* [ ] Structured security reports
* [ ] Risk scoring
* [ ] Security finding prioritization
* [ ] Service-version intelligence
* [ ] Configuration exposure analysis
* [ ] Security event history

## Phase 4 — Packet Intelligence

* [ ] Packet capture improvements
* [ ] Packet decoding
* [ ] Protocol identification
* [ ] Traffic statistics
* [ ] Connection tracking
* [ ] Suspicious traffic detection

## Phase 5 — Network Topology

* [ ] Automatic topology generation
* [ ] Host relationship mapping
* [ ] Gateway identification
* [ ] Network graph export
* [ ] Interactive topology visualization

## Phase 6 — AI Intelligence

* [ ] Network feature extraction
* [ ] Anomaly detection
* [ ] Risk prediction
* [ ] Security event classification
* [ ] AI-generated network summaries
* [ ] Intelligent recommendations

## Phase 7 — Stable Release

The long-term objective is a stable SlipNet release capable of providing:

```text
Discovery
    +
Monitoring
    +
Security Analysis
    +
Topology Intelligence
    +
AI Analysis
    =
Network Intelligence Platform
```

---

# Security Philosophy

SlipNet is being developed primarily as a **defensive network intelligence and security analysis tool**.

Its security engine is designed to analyze information already collected by SlipNet's network discovery and analysis components.

The project aims to help users:

* Understand their network
* Identify exposed services
* Analyze network attack surface
* Detect suspicious conditions
* Understand network relationships
* Make informed defensive decisions

Only scan and analyze systems and networks that you own or have explicit authorization to assess.

---

# Project Status

SlipNet is currently in **early active development**.

The architecture and core subsystems are being implemented incrementally. Some components currently provide foundational functionality and are expected to become significantly more capable in future releases.

Expect breaking changes while the project is under active development.

---

# Contributing

Contributions, ideas, bug reports, and technical discussions are welcome.

Before submitting a contribution:

1. Create a branch for your change.
2. Keep changes focused.
3. Follow the existing C++ project structure.
4. Make sure the project builds successfully with CMake.
5. Test the affected functionality.
6. Submit a clear pull request describing the change.

---

# License

License information will be added before the first stable release.

---

# Author

**Amani Mugisha**

SlipNet is an independent project focused on building practical network intelligence and security technology with modern C++.

---

> **SlipNet — Discover. Analyze. Understand.**

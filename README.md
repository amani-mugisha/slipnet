# SlipNet

**Network Intelligence Engine**

SlipNet is a modern C++20 network intelligence CLI for discovering, analyzing, monitoring, and understanding network environments from the command line.

It unifies network discovery, host analysis, port scanning, service detection, packet inspection, topology mapping, security analysis, and AI-assisted intelligence into a single modular engine.

> SlipNet v0.1.0 is the first completed version of the project and establishes the core network intelligence and security analysis foundation.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [CLI](#cli)
- [Architecture](#architecture)
- [Building SlipNet](#building-slipnet)
- [Development Philosophy](#development-philosophy)
- [Roadmap](#roadmap)
- [Security Philosophy](#security-philosophy)
- [Project Status](#project-status)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)

---

## Overview

Modern networks generate large volumes of information — hosts, interfaces, ports, services, packets, connections, and security events. SlipNet turns that raw information into structured intelligence.

The project follows a modular architecture in which independent engines collect and analyze different layers of network data:

```
                    ┌─────────────────────┐
                    │      SlipNet CLI     │
                    └──────────┬──────────┘
                               │
                 ┌─────────────┼─────────────┐
                 │             │             │
                 ▼             ▼             ▼
          Network Engine  Security Engine  AI Engine
                 │             │             │
          ┌──────┼──────┐      │             │
          │      │      │      │             │
          ▼      ▼      ▼      ▼             ▼
        Hosts  Ports Services Alerts      Analysis
          │      │      │      │             │
          └──────┴──────┴──────┴─────────────┘
                               │
                               ▼
                     Network Intelligence
```

---

## Features

### Network Discovery
- Network interface discovery
- IP address handling and network mask detection
- Subnet calculation
- Host discovery and network state management

### Host Intelligence
Structured information about discovered hosts, including IP addresses, hostnames, online/offline state, latency, and status.

### Port Analysis
Identifies exposed network services and builds an understanding of a host's reachable attack surface.
- Port discovery and open/closed state
- Protocol and service association
- Per-host port state
- Common and custom TCP port range scanning

### Service Detection
- Service name, protocol, port, and version
- Banner information and detection status
- Foundation for vulnerability and security analysis

### Subnet Analysis
Analysis engine for IPv4 CIDR networks, including network/broadcast/netmask/wildcard calculation, prefix identification, total and usable host counts, and private/public address classification.

### Network Intelligence
Combines information from all engines into a shared network state — hosts, ports, services, network info, security findings, monitoring data, and topology — so information can be reused across commands rather than treated in isolation.

### Security Analysis
A defensive, rule-based security engine covering:
- Legacy protocol exposure (FTP, Telnet)
- Database exposure (MySQL/MariaDB, PostgreSQL, MongoDB)
- Remote access exposure (SSH, RDP, SMB)
- Large attack-surface detection
- Vulnerability and credential exposure heuristics
- Firewall analysis and TLS security analysis

Findings are represented as structured alerts with an ID, title, description, severity, evidence, confidence, and remediation guidance.

**Severity levels:**

| Level | Meaning |
|---|---|
| 0 | Informational |
| 1 | Low |
| 2 | Medium |
| 3 | High |
| 4 | Critical |

### Vulnerability Assessment
Identifies potential security exposures from discovered services using conservative heuristics rather than confirmed CVE claims — covering exposed FTP, Telnet, SMB, RDP, and database services, as well as potentially outdated or legacy service versions. Findings include evidence, confidence levels, and remediation.

### Credential Exposure Analysis
Identifies potential credential exposure risks associated with discovered services. **No credentials are collected, tested, or brute-forced.** Provides exposure indicators, severity classification, evidence, and recommendations.

### Firewall Analysis
Evaluates observed TCP port behavior and classifies ports as `OPEN`, `CLOSED`, `FILTERED`, or `UNKNOWN`. The scanner is conservative and does not claim a closed port proves firewall filtering; results are backed by evidence and a stated conclusion.

### TLS Security Analysis
Evaluates detected secure services and surfaces potential security configuration concerns, with findings that can be validated against actual service configuration and current recommendations.

### Packet Analysis
Foundation layer for packet capture, inspection, protocol analysis, and traffic intelligence — to be expanded in future releases.

### Network Monitoring
Foundation for continuous observation of network activity and statistics generation. Planned expansion includes traffic monitoring, connection statistics, bandwidth analysis, activity trends, and anomaly detection.

### Network Topology
Subsystem for representing discovered network nodes and relationships, with the long-term goal of producing a full network topology map:

```
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

### DNS Intelligence
Hostname resolution, IP resolution, reverse DNS lookup, and DNS-based network information.

### MAC Address Intelligence
MAC address discovery, interface association, and hardware vendor identification (where supported by the OS).

### Operating System Fingerprinting
Heuristic layer that estimates the likely OS family of a target host. Results are treated as heuristic intelligence rather than guaranteed identification.

### Banner Analysis
Retrieves available service/application banner information from reachable TCP services, supporting service identification, version detection, and security analysis.

### AI-Assisted Analysis
Transforms raw network measurements into higher-level intelligence:

```
Network Data → Feature Extraction → AI Analysis → Risk/Anomaly Assessment → Human-readable Intelligence
```

This layer will become more advanced in future releases.

---

## CLI

SlipNet uses an interactive command-line interface built around a `category|:action` structure:

| Command | Description |
|---|---|
| `ip\|:seek` | IP discovery |
| `host\|:find` | Host discovery |
| `port\|:scan` | Port scanning |
| `svc\|:detect` | Service detection |
| `topo\|:map` | Topology mapping |
| `mac\|:resolve` | MAC address resolution |
| `dns\|:resolve` | DNS resolution |
| `os\|:fingerprint` | OS fingerprinting |
| `banner\|:grab` | Banner grabbing |
| `subnet\|:calc` | Subnet calculation |
| `pkt\|:capture` | Packet capture |
| `pkt\|:inspect` | Packet inspection |
| `net\|:monitor` | Network monitoring |
| `net\|:show` | Show network state |
| `net\|:clear` | Clear network state |
| `sec\|:detect` | Security detection |
| `vuln\|:scan` | Vulnerability scanning |
| `cred\|:check` | Credential exposure check |
| `ssl\|:audit` | TLS/SSL audit |
| `firewall\|:probe` | Firewall probing |
| `ai\|:analyze` | AI-assisted analysis |
| `session\|:info` | Session information |
| `system\|:info` | System information |
| `help` | Command help |
| `fire` | — |

The command interface will continue to evolve as the underlying engines become more capable.

---

## Architecture

SlipNet follows a modular C++ architecture that keeps network components independent and extensible.

```
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
│   ├── topology/
│   └── platform/
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
│   ├── platform/
│   │   ├── linux/
│   │   └── windows/
│   └── main.cpp
│
├── CMakeLists.txt
└── README.md
```

### Core Components

| Component | Responsibility |
|---|---|
| `cli` | Command parsing, terminal interaction, signal handling |
| `core` | Shared network state and engine context |
| `network` | IP, subnet, interface, and network discovery |
| `host` | Host discovery and host intelligence |
| `port` | Port analysis and scanning |
| `service` | Service identification |
| `packet` | Packet capture and inspection |
| `monitoring` | Network monitoring and statistics |
| `security` | Defensive security analysis and alerts |
| `topology` | Network topology representation |
| `ai` | Feature extraction and intelligent analysis |
| `platform` | Operating-system-specific network implementations |

### Platform Architecture

SlipNet uses a cross-platform architecture with separate implementations for Windows and Linux. The command interface and common engines are shared, while OS-specific functionality lives in the corresponding platform layer. Each executable targets the operating system on which it is built and executed.

```
                    SlipNet
                       │
              ┌────────┴────────┐
              │                 │
           Common             Platform
           Engine              Layer
              │                 │
       ┌──────┴──────┐      ┌───┴────┐
       │             │      │        │
       ▼             ▼      ▼        ▼
     Linux         Windows Linux   Windows
    Build          Build  Impl.     Impl.
```

---

## Building SlipNet

### Requirements

**Linux**
- C++20-compatible compiler
- CMake 3.20+
- POSIX threading support
- OpenSSL

Tested with GCC 11.4, CMake 3.22+, and C++20.

**Windows**
- C++20-compatible compiler
- CMake 3.20+
- OpenSSL
- Windows networking libraries

### Clone

```bash
git clone <YOUR_REPOSITORY_URL>
cd slipnet
```

### Linux Build

```bash
mkdir build && cd build
cmake ..
cmake --build . -j$(nproc)
```

The executable is generated at `build/slipnet`.

```bash
./slipnet
```

### Windows Build

```bash
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

The executable is generated in the corresponding Windows build configuration directory.

---

## Development Philosophy

SlipNet is developed incrementally: reliable network primitives first, then combined into higher-level intelligence.

```
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

This approach allows each subsystem to be useful independently while also feeding data into higher-level analysis.

---

## Roadmap

### Phase 1 — Core Engine ✅
- [x] C++20 project architecture
- [x] CMake build system
- [x] Interactive CLI foundation
- [x] Network state management
- [x] Network interface architecture
- [x] Host discovery architecture
- [x] Security detection foundation
- [x] AI analysis foundation
- [x] Cross-platform architecture
- [x] Linux platform implementation
- [x] Windows platform implementation

### Phase 2 — Network Intelligence
- [ ] Improve network discovery
- [ ] Improve host discovery
- [ ] Expand subnet analysis
- [ ] Improve TCP port scanning
- [ ] Improve service detection
- [ ] Structured scan results
- [ ] Better CLI output

### Phase 3 — Security Intelligence
- [ ] Expand security rules
- [ ] Structured security reports
- [ ] Risk scoring
- [ ] Security finding prioritization
- [ ] Service-version intelligence
- [ ] Configuration exposure analysis
- [ ] Security event history

### Phase 4 — Packet Intelligence
- [ ] Packet capture improvements
- [ ] Packet decoding
- [ ] Protocol identification
- [ ] Traffic statistics
- [ ] Connection tracking
- [ ] Suspicious traffic detection

### Phase 5 — Network Topology
- [ ] Automatic topology generation
- [ ] Host relationship mapping
- [ ] Gateway identification
- [ ] Network graph export
- [ ] Interactive topology visualization

### Phase 6 — AI Intelligence
- [ ] Network feature extraction
- [ ] Anomaly detection
- [ ] Risk prediction
- [ ] Security event classification
- [ ] AI-generated network summaries
- [ ] Intelligent recommendations

### Phase 7 — Stable Release

The long-term objective is a stable SlipNet release combining Discovery, Monitoring, Security Analysis, Topology Intelligence, and AI Analysis into a complete **Network Intelligence Platform**.

---

## Security Philosophy

SlipNet is developed primarily as a **defensive** network intelligence and security analysis tool. Its security engine analyzes information collected by SlipNet's own discovery and analysis components to help users:

- Understand their network
- Identify exposed services
- Analyze network attack surface
- Detect suspicious conditions
- Understand network relationships
- Make informed defensive decisions

> **Only scan and analyze systems and networks that you own or have explicit authorization to assess.**

---

## Project Status

**SlipNet v0.1.0 — Completed**

Version 0.1.0 establishes the first complete foundation of SlipNet, including network discovery, host discovery, port scanning, service detection, subnet calculation, topology and packet analysis foundations, network monitoring foundation, security analysis, vulnerability assessment, credential exposure analysis, TLS auditing, firewall analysis, AI analysis foundation, Linux and Windows platform support, and an interactive CLI.

Future versions will focus on expanding intelligence, visualization, security, monitoring, and AI capabilities. Breaking changes may occur as SlipNet continues to evolve.

---

## Contributing

Contributions, ideas, bug reports, and technical discussions are welcome.

Before submitting a contribution:

1. Create a branch for your change.
2. Keep changes focused.
3. Follow the existing C++ project structure.
4. Make sure the project builds successfully with CMake.
5. Test the affected functionality.
6. Submit a clear pull request describing the change.

---

## License

License information will be added before the first stable release.

---

## Author

**Amani Mugisha**

SlipNet is an independent project focused on building practical network intelligence and security technology with modern C++.
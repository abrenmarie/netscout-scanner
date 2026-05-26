# NetScout Scanner 

NetScout is a high-performance, multithreaded network and subnet scanner written in native C++11. Designed for fast network reconnaissance, it implements a highly efficient **Thread Pool** architecture and **Asynchronous (Non-blocking) Sockets** to scan thousands of ports and IP addresses in seconds without breaking.

## Key Features

* **High-Performance Thread Pool:** Dynamic task distribution via a thread-safe queue prevents worker starvation.
* **Subnet Scanning (CIDR Parser):** Parses range formats like `192.168.1.0/24` down to individual target IPs.
* **Async Network I/O:** Uses non-blocking sockets with `select()` system calls for precise, adjustable timeouts.
* **Deep Reconnaissance (Banner Grabbing):** Discovers hidden services by forcing quiet servers (like HTTP) to reply with signature banners.
* **OS Fingerprinting:** Inspects the connection's TTL (Time-To-Live) values to predict the target's Operating System.
* **Real-time UI & Reporting:** Features a smooth thread-safe CLI progress bar and automated exports to structured JSON (`report.json`).

## Architecture Overview

Instead of splitting tasks statically, NetScout queues all IP/Port combinations dynamically. Thread workers continuously pull jobs until the shared thread-safe queue is depleted. Mutexes isolate critical sections, and atomic counters drive the accurate visual progress display.

## Getting Started

### Prerequisites

* A C++11 compliant compiler (`g++` or `clang++`)
* `make` build utility

### Compilation

Compile the project natively using the provided automated `Makefile`:

```bash
make clean && make
```

## Usage Examples

- Scan a single target for specific ports:

```bash
./netscout 127.0.0.1 8000 8100 1
```

- Scan an entire local subnet range:

```bash
./netscout 192.168.1.0/24 22 443 1
```

## Sample Output Format [report.json](report.json)

```JSON
{
  "target_input": "127.0.0.1",
  "open_ports": [
    {
      "ip": "127.0.0.1",
      "port": 5000,
      "status": "open",
      "os_guess": "Linux / macOS",
      "banner": "Server: AirTunes/925.5.1"
    }
  ]
}
```

## Project Roadmap

Here is my strategic vision for building a high-performance network analysis ecosystem.

### ✅ Completed Milestones

- [x] **Highload Thread Pool engine**: Optimized parallel execution core.
- [x] **Subnet CIDR parsing logic**: Advanced network targeting capabilities.
- [x] **TTL OS Fingerprinting**: Intelligent analysis of network responses.
- [x] **Low-level UDP scanning implementation**: Full transport layer support.
- [x] **Distributed REST API**: Scalable Go-based backend integration.

### ⏳ In Progress & Future Vision

- [ ] **Advanced Network Analysis (Fingerprinting)**
    - Implement banner grabbing for service identification (SSH, HTTP, FTP, etc.).
- [ ] **Asynchronous Task Management**
    - Refactor Go API for background task processing.
    - Implement status polling for long-running scan operations.
- [ ] **Modern Web Dashboard**
    - Build a responsive interface with dynamic data visualization.
    - Add real-time progress tracking and port status indicators.
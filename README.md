# NetScout Scanner

NetScout is an IPv4 TCP/UDP port-scanning CLI written in C++11. The current implementation uses a bounded worker pool and non-blocking TCP connect attempts. It is intended for systems and networks that you own or are explicitly authorized to assess.

> **Implementation status:** this repository is being recovered from an earlier prototype. This README describes the code in the current branch, not the original aspirational roadmap.

## Current capabilities

- IPv4 host and CIDR parsing (up to 65,536 addresses per invocation).
- TCP connect scanning with non-blocking sockets, `select()` and `SO_ERROR` validation.
- UDP probing with conservative `open|filtered` reporting when no response is received.
- Bounded thread count and a mutex-protected task queue.
- Basic service banner collection: reads unsolicited greetings and sends a non-destructive HTTP `HEAD` probe to common HTTP ports.
- JSON report output with escaped strings.
- Explicitly reports OS identification as `unknown`.

## Important limitations

### Banner grabbing

Banner collection is currently intentionally small in scope. It reads service greetings and sends an HTTP `HEAD /` request to common HTTP ports. It is not a general-purpose protocol fingerprinting engine and does not yet identify SSH/FTP/SMTP versions through active protocol-specific probes.

### Asynchronous task management

The C++ scanner has concurrent worker threads and non-blocking socket operations. The Go HTTP API is still a synchronous prototype: it runs the scanner process and waits for it to finish. There are no background task IDs, status polling, cancellation, or per-task result isolation yet. Do not describe the API as an asynchronous task system.

### Performance

No throughput claim is made yet. Performance must be measured with reproducible benchmarks on a documented host and network before publishing numerical claims.

### OS fingerprinting

The scanner does **not** currently collect the remote host's IP TTL. Reading the local socket's TTL would not identify the remote operating system. Therefore, `os_guess` is `unknown`; TTL-based OS estimation is deferred until remote TTL measurement is implemented and tested.

### UDP semantics

A UDP service may remain silent even when its port is open. A timeout is therefore reported as `open|filtered`, not as a confirmed open port. This implementation does not perform protocol-specific UDP probes.

## Requirements

- Linux or another POSIX-compatible environment.
- C++11 compiler (`g++` or `clang++`).
- GNU Make.
- Python 3 for integration tests.

## Build

```bash
make clean
make
```

## Usage

```bash
./netscout <IPv4|CIDR> <start_port> <end_port> [timeout_seconds] [tcp|udp] [output.json]
```

Examples:

```bash
# scan selected TCP ports on loopback
./netscout 127.0.0.1 22 443 1 tcp

# scan a small private subnet range
./netscout 192.168.1.0/28 1 1024 1 tcp

# UDP scan; silent ports are reported as open|filtered
./netscout 127.0.0.1 53 53 2 udp udp-report.json
```

Timeout is specified in seconds and must be between 1 and 30. CIDR ranges larger than 65,536 addresses and scans larger than 2,000,000 IP/port tasks are rejected to prevent accidental oversized scans.

## JSON report

The report contains `target_input`, `open_ports`, and an `os_fingerprinting` status object. Despite the historical key name `open_ports`, UDP entries may have status `open|filtered`; consumers should inspect each entry's `status` field.

Example:

```json
{
  "target_input": "127.0.0.1",
  "open_ports": [
    {
      "ip": "127.0.0.1",
      "port": 8080,
      "protocol": "tcp",
      "status": "open",
      "os_guess": "unknown",
      "banner": "HTTP/1.0 200 OK"
    }
  ],
  "os_fingerprinting": {
    "status": "not_available",
    "reason": "Remote TTL is not collected; no OS claim is made."
  }
}
```

## Tests

```bash
make test
```

The integration tests start a local HTTP test server, verify banner collection, and check invalid/oversized target handling. They do not scan external hosts.

## Roadmap

- [x] Restore CIDR parsing and core TCP scanning.
- [x] Restore worker-pool task execution.
- [x] Implement conservative UDP state reporting.
- [x] Connect basic HTTP banner collection to the TCP scan pipeline.
- [x] Remove unsupported OS fingerprinting claims.
- [ ] Add protocol-specific service probes (SSH, FTP, SMTP, TLS).
- [ ] Implement remote TTL collection and validated OS heuristics, or keep OS identification explicitly unsupported.
- [ ] Replace the synchronous Go handler with background task management, per-task results, status polling, and cancellation.
- [ ] Add reproducible performance benchmarks.
- [ ] Add end-to-end API and Docker Compose tests.
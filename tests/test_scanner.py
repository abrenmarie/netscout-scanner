#!/usr/bin/env python3

import json
import pathlib
import random
import re
import socket
import subprocess
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCANNER = ROOT / "netscout"

SUMMARY_KEYS = {
    "open": "open",
    "closed": "closed",
    "filtered": "filtered",
    "open|filtered": "open_filtered",
    "error": "errors",
}


def free_port(protocol):
    with socket.socket(socket.AF_INET, protocol) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run_scan(protocol, start, end, directory, timeout=1):
    report_path = directory / f"{protocol}-{start}-{end}.json"

    command = [
        str(SCANNER),
        "127.0.0.1",
        str(start),
        str(end),
        str(timeout),
        protocol,
        str(report_path),
    ]

    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=15,
    )

    if completed.returncode != 0:
        raise AssertionError(
            f"Scanner exited with {completed.returncode}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )

    with report_path.open(encoding="utf-8") as file:
        report = json.load(file)

    return report, completed.stdout


def validate_summary(report):
    summary = report["summary"]
    results = report["results"]

    assert summary["total"] == len(results), summary

    calculated = {
        key: 0 for key in SUMMARY_KEYS.values()
    }

    for result in results:
        status = result["status"]
        assert status in SUMMARY_KEYS, status
        calculated[SUMMARY_KEYS[status]] += 1

    for key, expected in calculated.items():
        assert summary[key] == expected, (
            f"Summary mismatch for {key}: "
            f"expected {expected}, got {summary[key]}"
        )

    assert sum(calculated.values()) == summary["total"]


def get_result(report, port):
    matches = [
        item for item in report["results"]
        if item["port"] == port
    ]

    assert len(matches) == 1, matches
    return matches[0]


def test_tcp_open(directory):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(5)

    port = server.getsockname()[1]
    errors = []

    payload = (
        b'NETSCOUT "quoted" path\\segment\r\nNEXT\tFIELD'
    )

    def serve():
        try:
            connection, _ = server.accept()
            with connection:
                connection.sendall(payload)
        except Exception as exc:
            errors.append(exc)
        finally:
            server.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    try:
        report, _ = run_scan("tcp", port, port, directory)
    finally:
        thread.join(timeout=6)

    assert not thread.is_alive(), "TCP server thread did not finish"
    assert not errors, errors

    result = get_result(report, port)

    expected_banner = (
        'NETSCOUT "quoted" path\\segment  NEXT FIELD'
    )

    assert result["status"] == "open", result
    assert result["banner"] == expected_banner, repr(result["banner"])

    validate_summary(report)
    print("PASS: TCP open and Banner Grabbing")
    print("PASS: JSON escaping end-to-end")


def test_tcp_closed(directory):
    port = free_port(socket.SOCK_STREAM)

    report, _ = run_scan("tcp", port, port, directory)
    result = get_result(report, port)

    assert result["status"] == "closed", result

    validate_summary(report)
    print("PASS: TCP closed")


def test_udp_open(directory):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    server.settimeout(5)

    port = server.getsockname()[1]
    errors = []

    def serve():
        try:
            _, address = server.recvfrom(512)
            server.sendto(b"NETSCOUT-UDP-TEST", address)
        except Exception as exc:
            errors.append(exc)
        finally:
            server.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    try:
        report, _ = run_scan("udp", port, port, directory)
    finally:
        thread.join(timeout=6)

    assert not thread.is_alive(), "UDP server thread did not finish"
    assert not errors, errors

    result = get_result(report, port)

    assert result["status"] == "open", result
    assert result["banner"] == "NETSCOUT-UDP-TEST", result

    validate_summary(report)
    print("PASS: UDP open and response capture")


def test_udp_closed(directory):
    port = free_port(socket.SOCK_DGRAM)

    report, _ = run_scan("udp", port, port, directory)
    result = get_result(report, port)

    assert result["status"] == "closed", result

    validate_summary(report)
    print("PASS: UDP closed")


def test_udp_silent(directory):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))

    port = server.getsockname()[1]

    try:
        report, _ = run_scan("udp", port, port, directory)
    finally:
        server.close()

    result = get_result(report, port)

    assert result["status"] == "open|filtered", result

    validate_summary(report)
    print("PASS: UDP open|filtered")


def reserve_udp_range(count):
    for _ in range(100):
        start = random.randint(20000, 50000)
        sockets = []

        try:
            for port in range(start, start + count):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(("127.0.0.1", port))
                sockets.append(sock)

            return start, sockets

        except OSError:
            for sock in sockets:
                sock.close()

    raise RuntimeError("Could not reserve a consecutive UDP port range")


def test_thread_pool(directory):
    count = 4
    timeout_seconds = 1

    start, servers = reserve_udp_range(count)

    try:
        begin = time.monotonic()

        report, output = run_scan(
            "udp",
            start,
            start + count - 1,
            directory,
            timeout=timeout_seconds,
        )

        elapsed = time.monotonic() - begin

    finally:
        for sock in servers:
            sock.close()

    assert len(report["results"]) == count

    assert all(
        item["status"] == "open|filtered"
        for item in report["results"]
    )

    worker_match = re.search(r"workers:\s*(\d+)", output)
    assert worker_match is not None, output

    workers = int(worker_match.group(1))
    assert 1 <= workers <= count, workers

    if workers >= 2:
        sequential_time = count * timeout_seconds
        assert elapsed < sequential_time - 0.5, (
            f"Possible sequential execution: workers={workers}, "
            f"elapsed={elapsed:.2f}s"
        )
        print(f"PASS: Parallel execution with {workers} workers")
    else:
        print("SKIP: Parallel timing assertion; only one worker is available")

    # Four one-second waits should overlap rather than run sequentially.
    assert elapsed < 3.5, (
        f"Possible sequential execution: {elapsed:.2f}s"
    )

    validate_summary(report)

    print("PASS: Four concurrent UDP tasks")
    print(f"PASS: Thread Pool elapsed time: {elapsed:.2f}s")


def main():
    if not SCANNER.is_file():
        raise SystemExit(
            "NetScout binary not found. Run 'make' first."
        )

    with tempfile.TemporaryDirectory(
        prefix="netscout-tests-"
    ) as temp:
        directory = pathlib.Path(temp)

        tests = [
            test_tcp_open,
            test_tcp_closed,
            test_udp_open,
            test_udp_closed,
            test_udp_silent,
            test_thread_pool,
        ]

        for test in tests:
            test(directory)

    print("\nAll integration tests passed.")


if __name__ == "__main__":
    main()
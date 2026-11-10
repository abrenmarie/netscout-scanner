#ifndef NETSCOUT_SCANNER_H
#define NETSCOUT_SCANNER_H

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

enum class PortState : std::uint8_t
{
    Open,
    Closed,
    Filtered,
    OpenFiltered,
    Error
};

// compact per-task storage; IP, port and protocol are derived from task index
struct ScanOutcome
{
    PortState state;
    std::string banner;

    ScanOutcome() : state(PortState::Error) {}
};

// full transient result used by an individual socket scan
struct PortResult
{
    std::string ip;
    int port;
    std::string protocol;
    std::string state; // open, closed, filtered, open|filtered, error
    std::string banner;
    std::string os_guess; // unknown until remote TTL is measured
};

std::vector<std::string> parse_cidr(const std::string &target,
                                    std::string *error = nullptr);
PortResult scan_port_tcp(const std::string &ip, int port, int timeout_ms);
PortResult scan_port_udp(const std::string &ip, int port, int timeout_ms);

void pool_worker_thread(
    const std::vector<std::string> &ips,
    int start_port,
    std::uint32_t port_count,
    const std::string &protocol,
    std::uint64_t total_tasks,
    std::atomic<std::uint64_t> &next_task_index,
    int timeout_ms,
    std::vector<ScanOutcome> &outcomes,
    std::atomic<std::uint64_t> &progress_counter);

#endif

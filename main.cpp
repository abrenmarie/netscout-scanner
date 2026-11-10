#include "scanner.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <new>
#include <sstream>
#include <thread>
#include <system_error>
#include <vector>

namespace
{
    void print_usage(const char *name)
    {
        std::cout << "Usage: " << name
                  << " <IPv4|CIDR> <start_port> <end_port> [timeout_seconds] [tcp|udp] [output.json]\n"
                  << "Example: " << name << " 127.0.0.1 1 1024 1 tcp report.json\n";
    }

    std::string json_escape(const std::string &value)
    {
        std::ostringstream out;
        for (unsigned char c : value)
        {
            switch (c)
            {
            case '"':
                out << "\\\"";
                break;
            case '\\':
                out << "\\\\";
                break;
            case '\b':
                out << "\\b";
                break;
            case '\f':
                out << "\\f";
                break;
            case '\n':
                out << "\\n";
                break;
            case '\r':
                out << "\\r";
                break;
            case '\t':
                out << "\\t";
                break;
            default:
                if (c < 0x20)
                {
                    const char *hex = "0123456789abcdef";
                    out << "\\u00" << hex[(c >> 4) & 0xf] << hex[c & 0xf];
                }
                else
                    out << static_cast<char>(c);
            }
        }
        return out.str();
    }

    const char *port_state_name(PortState state)
    {
        switch (state)
        {
        case PortState::Open:
            return "open";
        case PortState::Closed:
            return "closed";
        case PortState::Filtered:
            return "filtered";
        case PortState::OpenFiltered:
            return "open|filtered";
        case PortState::Error:
            return "error";
        }
        return "error";
    }

    bool save_json_report(const std::string &filename,
                          const std::string &target,
                          const std::vector<std::string> &ips,
                          int start_port,
                          std::uint32_t port_count,
                          const std::string &protocol,
                          const std::vector<ScanOutcome> &results)
    {
        if (port_count == 0 ||
            static_cast<std::uint64_t>(ips.size()) * port_count != results.size())
            return false;

        size_t open_count = 0;
        size_t closed_count = 0;
        size_t filtered_count = 0;
        size_t open_filtered_count = 0;
        size_t error_count = 0;

        for (const auto &r : results)
        {
            switch (r.state)
            {
            case PortState::Open:
                ++open_count;
                break;
            case PortState::Closed:
                ++closed_count;
                break;
            case PortState::Filtered:
                ++filtered_count;
                break;
            case PortState::OpenFiltered:
                ++open_filtered_count;
                break;
            case PortState::Error:
                ++error_count;
                break;
            }
        }

        std::ofstream file(filename.c_str());
        if (!file)
            return false;

        file << "{\n"
             << "  \"target_input\": \"" << json_escape(target) << "\",\n"
             << "  \"summary\": {\n"
             << "    \"total\": " << results.size() << ",\n"
             << "    \"open\": " << open_count << ",\n"
             << "    \"closed\": " << closed_count << ",\n"
             << "    \"filtered\": " << filtered_count << ",\n"
             << "    \"open_filtered\": " << open_filtered_count << ",\n"
             << "    \"errors\": " << error_count << "\n"
             << "  },\n"
             << "  \"results\": [\n";

        for (size_t i = 0; i < results.size(); ++i)
        {
            const ScanOutcome &r = results[i];
            const size_t ip_index = i / port_count;
            const int port = start_port + static_cast<int>(i % port_count);

            file << "    {"
                 << "\"ip\": \"" << json_escape(ips[ip_index]) << "\", "
                 << "\"port\": " << port << ", "
                 << "\"protocol\": \"" << json_escape(protocol) << "\", "
                 << "\"status\": \"" << port_state_name(r.state) << "\", "
                 << "\"os_guess\": \"unknown\", "
                 << "\"banner\": \"" << json_escape(r.banner) << "\""
                 << "}";

            file << (i + 1 == results.size() ? "\n" : ",\n");
        }

        file << "  ],\n"
             << "  \"os_fingerprinting\": {"
             << "\"status\": \"not_available\", "
             << "\"reason\": \"Remote TTL is not collected; no OS claim is made.\""
             << "}\n"
             << "}\n";

        return static_cast<bool>(file);
    }
}

int main(int argc, char *argv[])
{
    if (argc == 2 && (std::string(argv[1]) == "-h" ||
                      std::string(argv[1]) == "--help"))
    {
        print_usage(argv[0]);
        return 0;
    }
    if (argc < 4 || argc > 7)
    {
        print_usage(argv[0]);
        return 2;
    }

    const std::string target = argv[1];
    char *end = nullptr;
    long start = std::strtol(argv[2], &end, 10);
    if (!end || *end != '\0')
    {
        std::cerr << "Invalid start port.\n";
        return 2;
    }
    long finish = std::strtol(argv[3], &end, 10);
    if (!end || *end != '\0' || start < 1 || finish > 65535 ||
        start > finish || finish < 1)
    {
        std::cerr << "Port range must satisfy 1 <= start <= end <= 65535.\n";
        return 2;
    }

    long timeout_seconds = argc >= 5 ? std::strtol(argv[4], &end, 10) : 1;
    if ((argc >= 5 && (!end || *end != '\0')) ||
        timeout_seconds < 1 || timeout_seconds > 30)
    {
        std::cerr << "Timeout must be between 1 and 30 seconds.\n";
        return 2;
    }

    std::string protocol = "tcp";
    if (argc >= 6)
    {
        protocol = argv[5];
        std::transform(protocol.begin(), protocol.end(), protocol.begin(),
                       [](unsigned char c)
                       { return static_cast<char>(std::tolower(c)); });
    }
    if (protocol != "tcp" && protocol != "udp")
    {
        std::cerr << "Protocol must be tcp or udp.\n";
        return 2;
    }
    const std::string output = argc >= 7 ? argv[6] : "report.json";

    std::string parse_error;
    std::vector<std::string> ips = parse_cidr(target, &parse_error);
    if (ips.empty())
    {
        std::cerr << "Invalid target: " << parse_error << "\n";
        return 2;
    }

    const uint64_t total64 = static_cast<uint64_t>(ips.size()) *
                             static_cast<uint64_t>(finish - start + 1);
    if (total64 > 2000000ULL)
    {
        std::cerr << "Scan contains more than 2,000,000 tasks; narrow the target or port range.\n";
        return 2;
    }
    const std::uint64_t total = total64;
    const std::uint32_t port_count =
        static_cast<std::uint32_t>(finish - start + 1);

    unsigned int workers = std::thread::hardware_concurrency();
    if (workers == 0)
        workers = 4;
    workers = std::max(1U, std::min(workers, 128U));
    workers = std::min(workers, static_cast<unsigned int>(total));

    std::vector<ScanOutcome> results;
    try
    {
        results.resize(static_cast<std::size_t>(total));
    }
    catch (const std::bad_alloc &)
    {
        std::cerr << "Insufficient memory for " << total
                  << " scan results; narrow the target or port range.\n";
        return 2;
    }

    std::atomic<std::uint64_t> next_task_index(0);
    std::atomic<std::uint64_t> progress(0);
    std::vector<std::thread> pool;
    pool.reserve(workers);
    const int timeout_ms = static_cast<int>(timeout_seconds * 1000);

    // if thread creation partially fails, already-started workers can still
    // drain the entire atomic task index; fail only if none could start
    for (unsigned int i = 0; i < workers; ++i)
    {
        try
        {
            pool.emplace_back(
                pool_worker_thread,
                std::cref(ips),
                static_cast<int>(start),
                port_count,
                std::cref(protocol),
                total,
                std::ref(next_task_index),
                timeout_ms,
                std::ref(results),
                std::ref(progress));
        }
        catch (const std::system_error &e)
        {
            std::cerr << "[!] Could not start another worker: "
                      << e.what() << "\n";
            break;
        }
    }

    if (pool.empty())
    {
        std::cerr << "[!] Could not start any scanner workers.\n";
        return 2;
    }

    std::cout << "[*] NetScout Scanner\n"
              << "[*] Target: " << target << " (" << ips.size() << " IPv4 addresses)\n"
              << "[*] Protocol: " << protocol << ", ports: " << start << "-" << finish << "\n"
              << "[*] Tasks: " << total << ", workers: " << pool.size() << "\n";

    // progress is printed by the main thread; workers never write to stdout

    while (progress.load() < total)
    {
        const int done = progress.load();
        std::cout << "\r[+] Progress: " << done << "/" << total
                  << " (" << (100LL * done / total) << "%)" << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    for (auto &worker : pool)
        if (worker.joinable())
            worker.join();
    std::cout << "\r[+] Progress: " << total << "/" << total << " (100%)\n";

    size_t confirmed_open = 0;
    size_t closed_count = 0;
    size_t filtered_count = 0;
    size_t ambiguous_udp = 0;
    size_t error_count = 0;

    for (size_t i = 0; i < results.size(); ++i)
    {
        const ScanOutcome &r = results[i];
        switch (r.state)
        {
        case PortState::Open:
            ++confirmed_open;
            break;
        case PortState::Closed:
            ++closed_count;
            break;
        case PortState::Filtered:
            ++filtered_count;
            break;
        case PortState::OpenFiltered:
            ++ambiguous_udp;
            break;
        case PortState::Error:
            ++error_count;
            break;
        }

        if (r.state == PortState::Closed)
            continue;

        const size_t ip_index = i / port_count;
        const int port = static_cast<int>(start) +
                         static_cast<int>(i % port_count);

        std::cout << "  " << ips[ip_index] << ":" << port
                  << "/" << protocol << " " << port_state_name(r.state);
        if (!r.banner.empty())
            std::cout << " | " << r.banner;
        std::cout << "\n";
    }

    std::cout << "[+] Results: total=" << results.size()
              << ", open=" << confirmed_open
              << ", closed=" << closed_count
              << ", filtered=" << filtered_count
              << ", open|filtered=" << ambiguous_udp
              << ", errors=" << error_count << "\n";

    if (!save_json_report(output, target, ips, static_cast<int>(start),
                          port_count, protocol, results))
    {
        std::cerr << "[!] Could not write report: " << output << "\n";
        return 1;
    }
    std::cout << "[+] Report written to " << output << "\n";
    return 0;
}
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <algorithm>
#include <string>
#include <cstdlib> 
#include <fstream>  
#include <atomic>   
#include <chrono>   
#include <queue> 
#include "scanner.h"

void print_usage(const char* prog_name) {
    std::cout << "Usage: " << prog_name << " <IP_or_CIDR> <Start_Port> <End_Port> [Timeout_Sec] [tcp/udp]\n";
    std::cout << "Example: " << prog_name << " 127.0.0.1 53 80 1 udp\n";
}

void print_progress_bar(std::atomic<int>& progress, int total) {
    int bar_width = 40;
    while (progress < total) {
        float percentage = (float)progress / total;
        int progress_chars = percentage * bar_width;

        std::cout << "\r[";
        for (int i = 0; i < bar_width; ++i) {
            if (i < progress_chars) std::cout << "=";
            else if (i == progress_chars) std::cout << ">";
            else std::cout << " ";
        }
        std::cout << "] " << int(percentage * 100.0) << "% (" << progress << "/" << total << ")" << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    std::cout << "\r[";
    for (int i = 0; i < bar_width; ++i) std::cout << "=";
    std::cout << "] 100% (" << total << "/" << total << ")\n" << std::flush;
}

void save_json_report(const std::string& filename, const std::string& target, const std::vector<PortResult>& results) {
    std::ofstream file(filename);
    if (!file.is_open()) return;
    file << "{\n  \"target_input\": \"" << target << "\",\n  \"open_ports\": [\n";
    for (size_t i = 0; i < results.size(); ++i) {
        file << "    {\n";
        file << "      \"ip\": \"" << results[i].ip << "\",\n";
        file << "      \"port\": " << results[i].port << ",\n";
        file << "      \"protocol\": \"" << results[i].protocol << "\",\n";
        file << "      \"status\": \"open\",\n";
        file << "      \"os_guess\": \"" << results[i].os_guess << "\",\n";
        
        std::string clean_banner = results[i].banner;
        size_t pos = 0;
        while ((pos = clean_banner.find("\"", pos)) != std::string::npos) {
            clean_banner.replace(pos, 1, "\\\"");
            pos += 2;
        }
        file << "      \"banner\": \"" << clean_banner << "\"\n";
        file << "    }";
        if (i < results.size() - 1) file << ",";
        file << "\n";
    }
    file << "  ]\n}\n";
    file.close();
}

int main(int argc, char* argv[]) {
    std::string target_input = "127.0.0.1";
    int start_port = 8080;
    int end_port = 8085; 
    int timeout_sec = 1;
    std::string mode = "tcp";

    

    if (argc > 1) {
        std::string first_arg = argv[1];
        if (first_arg == "-h" || first_arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
        if (argc < 4) {
            std::clog << "[!] Error: Missing required arguments.\n";
            print_usage(argv[0]);
            return 1;
        }
        target_input = argv[1];
        start_port = std::atoi(argv[2]);
        end_port = std::atoi(argv[3]);
        
        if (argc >= 5) timeout_sec = std::atoi(argv[4]);
        if (argc >= 6) {
            std::string proto_arg = argv[5];
            std::transform(proto_arg.begin(), proto_arg.end(), proto_arg.begin(), ::tolower);
            if (proto_arg == "udp") mode = "udp";
        }
    }

    if (start_port < 1 || end_port > 65535 || start_port > end_port) {
        std::clog << "[!] Error: Invalid port range.\n";
        return 1;
    }

    std::vector<std::string> target_ips = parse_cidr(target_input);
    if (target_ips.empty()) return 1;

    std::queue<ScanTask> task_queue;
    for (const auto& ip : target_ips) {
        for (int port = start_port; port <= end_port; ++port) {
            task_queue.push({ip, port, mode});
        }
    }
    int total_tasks = task_queue.size();

    unsigned int num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0) num_threads = 4;

    std::cout << "[*] Starting NetScout Scanner..." << std::endl;
    std::cout << "[*] Target: " << target_input << " (" << target_ips.size() << " IPs)" << std::endl;
    std::cout << "[*] Mode: " << (mode == "udp" ? "UDP (Connectionless)" : "TCP (Stateful)") << std::endl;
    std::cout << "[*] Ports: " << start_port << " - " << end_port << std::endl;
    std::cout << "[*] Pool Size: " << num_threads << " threads" << std::endl;
    std::cout << "==================================================" << std::endl;

    std::vector<PortResult> open_ports;
    std::mutex result_mutex;
    std::mutex queue_mutex;
    std::atomic<int> progress_counter(0);

    std::vector<std::thread> thread_pool;
    for (size_t i = 0; i < num_threads; ++i) {
        thread_pool.push_back(std::thread(pool_worker_thread, 
                                          std::ref(task_queue), std::ref(queue_mutex),
                                          timeout_sec, std::ref(open_ports), 
                                          std::ref(result_mutex), std::ref(progress_counter)));
    }

    print_progress_bar(progress_counter, total_tasks);

    for (auto& t : thread_pool) {
        if (t.joinable()) t.join();
    }

    std::sort(open_ports.begin(), open_ports.end(), [](const PortResult& a, const PortResult& b) {
        if (a.ip != b.ip) return a.ip < b.ip;
        return a.port < b.port;
    });

    std::cout << "==================================================" << std::endl;
    std::cout << "[+] Scan complete!" << std::endl;
    
    if (open_ports.empty()) {
        std::cout << "[-] No open ports found." << std::endl;
    } else {
        std::cout << "[+] Found " << open_ports.size() << " open ports:" << std::endl;
        for (const auto& res : open_ports) {
            std::cout << "  -> [" << res.ip << "] Port " << res.port << "/" << res.protocol << " is OPEN";
            if (!res.banner.empty()) std::cout << " | " << res.banner;
            std::cout << std::endl;
        }
    }

    std::cout << "==================================================" << std::endl;
    save_json_report("report.json", target_input, open_ports);
    std::cout << "[+] Report saved to report.json" << std::endl;

    return 0;
}
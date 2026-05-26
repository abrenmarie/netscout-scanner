#ifndef SCANNER_H
#define SCANNER_H

#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <queue>

struct PortResult {
    std::string ip;
    int port;
    bool is_open;
    std::string banner;
};

struct ScanTask {
    std::string ip;
    int port;
};

std::vector<std::string> parse_cidr(const std::string& cidr);
PortResult scan_port(const std::string& ip, int port, int timeout_sec);

void pool_worker_thread(std::queue<ScanTask>& task_queue, std::mutex& queue_mutex,
                        int timeout_sec, std::vector<PortResult>& shared_results, 
                        std::mutex& result_mutex, std::atomic<int>& progress_counter);

#endif // SCANNER_H
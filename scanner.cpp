#include "scanner.h"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sstream>
#include <cmath>

std::vector<std::string> parse_cidr(const std::string& cidr) {
    std::vector<std::string> ips;
    size_t slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos) {
        ips.push_back(cidr);
        return ips;
    }
    std::string ip_part = cidr.substr(0, slash_pos);
    std::string mask_part = cidr.substr(slash_pos + 1);
    int mask = std::atoi(mask_part.c_str());
    if (mask < 0 || mask > 32) return ips;
    
    struct in_addr in;
    if (inet_pton(AF_INET, ip_part.c_str(), &in) != 1) return ips;
    
    uint32_t ip_bytes = ntohl(in.s_addr);
    uint32_t subnet_mask = (mask == 0) ? 0 : (~0 << (32 - mask));
    uint32_t network_addr = ip_bytes & subnet_mask;
    uint32_t broadcast_addr = network_addr | ~subnet_mask;
    
    for (uint32_t current_ip = network_addr; current_ip <= broadcast_addr; ++current_ip) {
        struct in_addr out_addr;
        out_addr.s_addr = htonl(current_ip);
        char ip_str[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &out_addr, ip_str, INET_ADDRSTRLEN) != NULL) {
            ips.push_back(std::string(ip_str));
        }
    }
    return ips;
}

PortResult scan_port_tcp(const std::string& ip, int port, int timeout_sec) {
    PortResult result;
    result.ip = ip;
    result.port = port;
    result.protocol = "TCP";
    result.is_open = false;
    result.banner = "";
    result.os_guess = "Unknown";

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return result;

    int ttl = 0;
    socklen_t ttl_len = sizeof(ttl);
    if (getsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, &ttl_len) == 0) {
        if (ttl <= 64) result.os_guess = "Linux / macOS";
        else if (ttl <= 128) result.os_guess = "Windows";
        else result.os_guess = "Network Device";
    }

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    int connect_res = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    if (connect_res < 0 && errno == EINPROGRESS) {
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(sock, &write_fds);
        struct timeval tv = {timeout_sec, 0};
        int select_res = select(sock + 1, NULL, &write_fds, NULL, &tv);
        if (select_res > 0 && FD_ISSET(sock, &write_fds)) {
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
            if (so_error == 0) result.is_open = true;
        }
    } else if (connect_res == 0) result.is_open = true;

    if (result.is_open) {
    
    }
    close(sock);
    return result;
}

PortResult scan_port_udp(const std::string& ip, int port, int timeout_sec) {
    PortResult result;
    result.ip = ip;
    result.port = port;
    result.protocol = "UDP";
    result.is_open = false;
    result.banner = "No response";
    result.os_guess = "Unknown";

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return result;

    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    struct timeval tv = {timeout_sec, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sendto(sock, "NetScout UDP", 12, 0, (struct sockaddr*)&addr, sizeof(addr));
    
    char buffer[1024];
    int bytes = recv(sock, buffer, sizeof(buffer), 0);
    if (bytes >= 0 || errno != ECONNREFUSED) {
        result.is_open = true;
    }
    close(sock);
    return result;
}

void pool_worker_thread(std::queue<ScanTask>& task_queue, std::mutex& queue_mutex,
                        int timeout_sec, std::vector<PortResult>& shared_results, 
                        std::mutex& result_mutex, std::atomic<int>& progress_counter) {
    while (true) {
        ScanTask task;
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            if (task_queue.empty()) break;
            task = task_queue.front();
            task_queue.pop();
        }

        PortResult res = (task.protocol == "UDP") ? 
                         scan_port_udp(task.ip, task.port, timeout_sec) : 
                         scan_port_tcp(task.ip, task.port, timeout_sec);
        
        if (res.is_open) {
            std::lock_guard<std::mutex> lock(result_mutex);
            shared_results.push_back(res);
        }
        progress_counter++;
    }
}
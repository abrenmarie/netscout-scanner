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
    if (mask < 0 || mask > 32) {
        std::clog << "[!] Error: Invalid CIDR mask.\n";
        return ips;
    }
    
    struct in_addr in;
    if (inet_pton(AF_INET, ip_part.c_str(), &in) != 1) {
        std::clog << "[!] Error: Invalid base IP in CIDR.\n";
        return ips;
    }
    
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

PortResult scan_port(const std::string& ip, int port, int timeout_sec) {
    PortResult result;
    result.port = port;
    result.is_open = false;
    result.banner = "";

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return result;

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

        struct timeval tv;
        tv.tv_sec = timeout_sec;
        tv.tv_usec = 0;

        int select_res = select(sock + 1, NULL, &write_fds, NULL, &tv);
        if (select_res > 0 && FD_ISSET(sock, &write_fds)) {
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
            if (so_error == 0) result.is_open = true;
        }
    } else if (connect_res == 0) {
        result.is_open = true;
    }

    if (result.is_open) {
        fcntl(sock, F_SETFL, flags); 

        struct timeval timeout_tv;
        timeout_tv.tv_sec = 1; 
        timeout_tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout_tv, sizeof(timeout_tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout_tv, sizeof(timeout_tv));

        std::string http_payload = "HEAD / HTTP/1.1\r\nHost: " + ip + "\r\nConnection: close\r\n\r\n";
        send(sock, http_payload.c_str(), http_payload.length(), 0);

        char buffer[1024];
        std::memset(buffer, 0, sizeof(buffer));
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        
        if (bytes > 0) {
            std::string raw_banner(buffer, bytes);
            std::string clean_banner = "";
            
            size_t server_pos = raw_banner.find("Server:");
            if (server_pos != std::string::npos) {
                size_t end_pos = raw_banner.find("\r\n", server_pos);
                if (end_pos != std::string::npos) {
                    clean_banner = raw_banner.substr(server_pos, end_pos - server_pos);
                }
            }
            
            if (clean_banner.empty()) {
                size_t first_line = raw_banner.find("\r\n");
                if (first_line != std::string::npos) {
                    clean_banner = raw_banner.substr(0, first_line);
                } else {
                    clean_banner = raw_banner.substr(0, 50);
                }
            }

            std::string final_banner = "";
            for (char c : clean_banner) {
                if (c >= 32 && c < 127) final_banner += c;
            }
            result.banner = final_banner;
        }
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
            if (task_queue.empty()) {
                break;
            }
            task = task_queue.front();
            task_queue.pop();
        }

        PortResult res = scan_port(task.ip, task.port, timeout_sec);
        
        if (res.is_open) {
            std::lock_guard<std::mutex> lock(result_mutex);
            shared_results.push_back(res);
        }
        
        progress_counter++;
    }
}
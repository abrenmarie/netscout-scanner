#include <iostream>
#include <vector>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <fstream>
#include "scanner.h"

std::string grabBanner(int sock) {
    char buffer[1024] = {0};
    struct timeval tv = {1, 0};
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    
    if (select(sock + 1, &fds, NULL, NULL, &tv) > 0) {
        recv(sock, buffer, sizeof(buffer) - 1, 0);
        return std::string(buffer);
    }
    return "No banner";
}

void perform_scan(std::string ip, int start, int end) {
    std::ofstream report("report.json");
    report << "{\"target_input\": \"" << ip << "\", \"open_ports\": [";

    bool first = true;
    for (int port = start; port <= end; ++port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

        fcntl(sock, F_SETFL, O_NONBLOCK);
        connect(sock, (struct sockaddr*)&addr, sizeof(addr));

        struct timeval tv = {1, 0};
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
            if (!first) report << ", ";
            report << port;
            first = false;
        }
        close(sock);
    }
    report << "]}" << std::endl;
    report.close();
}

std::vector<std::string> parse_cidr(const std::string& cidr) { 
    (void)cidr; 
    return {}; 
}

void pool_worker_thread(std::queue<ScanTask>&, std::mutex&, int, std::vector<PortResult>&, std::mutex&, std::atomic<int>&) {
    
}

PortResult scan_port_tcp(const std::string&, int, int) { return {}; }
PortResult scan_port_udp(const std::string&, int, int) { return {}; }
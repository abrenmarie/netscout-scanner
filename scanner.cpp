#include "scanner.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <chrono>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <sstream>
#include <utility>

namespace
{
    PortResult make_result(const std::string &ip, int port, const std::string &proto,
                           const std::string &state, const std::string &banner = "")
    {
        PortResult r;
        r.ip = ip;
        r.port = port;
        r.protocol = proto;
        r.state = state;
        r.banner = banner;
        r.os_guess = "unknown";
        return r;
    }

    enum class WaitStatus
    {
        Ready,
        Timeout,
        Error
    };

    WaitStatus wait_fd(int fd, bool write_ready, int timeout_ms)
    {
        if (fd < 0 || timeout_ms < 0)
        {
            errno = EINVAL;
            return WaitStatus::Error;
        }

        struct pollfd pfd{};
        pfd.fd = fd;
        pfd.events = write_ready ? POLLOUT : POLLIN;

        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeout_ms);
        int remaining_ms = timeout_ms;

        for (;;)
        {
            pfd.revents = 0;
            const int rc = poll(&pfd, 1, remaining_ms);

            if (rc > 0)
            {
                if (pfd.revents & POLLNVAL)
                {
                    errno = EBADF;
                    return WaitStatus::Error;
                }

                if (pfd.revents & (pfd.events | POLLERR | POLLHUP))
                    return WaitStatus::Ready;

                errno = EIO;
                return WaitStatus::Error;
            }

            if (rc == 0)
                return WaitStatus::Timeout;

            if (errno != EINTR)
                return WaitStatus::Error;

            const auto remaining_us =
                std::chrono::duration_cast<std::chrono::microseconds>(
                    deadline - std::chrono::steady_clock::now())
                    .count();

            if (remaining_us <= 0)
                return WaitStatus::Timeout;

            remaining_ms = static_cast<int>((remaining_us + 999) / 1000);
        }
    }

    std::string clean_banner(const char *data, size_t size)
    {
        std::string out;
        for (size_t i = 0; i < size && out.size() < 512; ++i)
        {
            unsigned char c = static_cast<unsigned char>(data[i]);
            if (c == '\r' || c == '\n' || c == '\t')
                out.push_back(' ');
            else if (c >= 32 && c < 127)
                out.push_back(static_cast<char>(c));
        }
        while (!out.empty() && out.back() == ' ')
            out.pop_back();
        return out;
    }

    bool send_all_with_timeout(int fd, const std::string &payload, int timeout_ms)
    {
        if (fd < 0 || timeout_ms < 0)
        {
            errno = EINVAL;
            return false;
        }

#if defined(SO_NOSIGPIPE)
        // macOS/BSD: prevent a peer closing during send() from terminating the process
        const int no_sigpipe = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE,
                       &no_sigpipe, sizeof(no_sigpipe)) < 0)
            return false;
#endif

        size_t offset = 0;
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeout_ms);

        while (offset < payload.size())
        {
            const auto remaining_us =
                std::chrono::duration_cast<std::chrono::microseconds>(
                    deadline - std::chrono::steady_clock::now())
                    .count();
            if (remaining_us <= 0)
            {
                errno = ETIMEDOUT;
                return false;
            }

            const int remaining_ms =
                static_cast<int>((remaining_us + 999) / 1000);
            const WaitStatus wait_status = wait_fd(fd, true, remaining_ms);

            if (wait_status == WaitStatus::Timeout)
            {
                errno = ETIMEDOUT;
                return false;
            }
            if (wait_status == WaitStatus::Error)
                return false;

            int send_flags = 0;
#if defined(MSG_NOSIGNAL)
            // linux: suppress SIGPIPE for this send operation
            send_flags |= MSG_NOSIGNAL;
#endif
            const ssize_t sent = send(fd, payload.data() + offset,
                                      payload.size() - offset, send_flags);
            if (sent > 0)
            {
                offset += static_cast<size_t>(sent);
                continue;
            }
            if (sent == 0)
            {
                errno = EPIPE;
                return false;
            }
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            return false;
        }

        return true;
    }

    std::string grab_banner(int fd, const std::string &ip, int port, int timeout_ms)
    {
        char buffer[1024] = {};

        const WaitStatus initial_status =
            wait_fd(fd, false, std::min(timeout_ms, 700));
        if (initial_status == WaitStatus::Ready)
        {
            const ssize_t n = recv(fd, buffer, sizeof(buffer) - 1, 0);
            if (n > 0)
                return clean_banner(buffer, static_cast<size_t>(n));
            if (n == 0)
                return ""; // peer closed the connection; do not probe a dead socket
            if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
                return "";
        }
        else if (initial_status == WaitStatus::Error)
        {
            return "";
        }

        // send a conservative HTTP HEAD probe only to common HTTP ports
        if (port == 80 || port == 8000 || port == 8080 ||
            port == 8081 || port == 8888)
        {
            std::ostringstream request;
            request << "HEAD / HTTP/1.0\r\n"
                    << "Host: " << ip << "\r\n"
                    << "User-Agent: NetScout/1.0\r\n"
                    << "Connection: close\r\n\r\n";
            const std::string payload = request.str();

            if (!send_all_with_timeout(fd, payload, timeout_ms))
                return "";

            const WaitStatus response_status = wait_fd(fd, false, timeout_ms);
            if (response_status == WaitStatus::Ready)
            {
                const ssize_t n = recv(fd, buffer, sizeof(buffer) - 1, 0);
                if (n > 0)
                    return clean_banner(buffer, static_cast<size_t>(n));
            }
        }

        return "";
    }
}

std::vector<std::string> parse_cidr(const std::string &target, std::string *error)
{
    std::vector<std::string> addresses;
    auto fail = [&](const std::string &message)
    {
        if (error)
            *error = message;
        return addresses;
    };

    const size_t slash = target.find('/');
    const std::string ip_text = target.substr(0, slash);
    in_addr addr;
    if (inet_pton(AF_INET, ip_text.c_str(), &addr) != 1)
        return fail("Target must be a valid IPv4 address or IPv4 CIDR.");

    uint32_t network = ntohl(addr.s_addr);
    int prefix = 32;
    if (slash != std::string::npos)
    {
        const std::string prefix_text = target.substr(slash + 1);
        if (prefix_text.empty())
            return fail("CIDR prefix is missing.");
        char *end = nullptr;
        long parsed = std::strtol(prefix_text.c_str(), &end, 10);
        if (!end || *end != '\0' || parsed < 0 || parsed > 32)
            return fail("CIDR prefix must be between 0 and 32.");
        prefix = static_cast<int>(parsed);
    }

    const uint32_t mask = prefix == 0 ? 0U : (0xFFFFFFFFU << (32 - prefix));
    const uint32_t first = network & mask;
    const uint64_t count = prefix == 32 ? 1ULL : (1ULL << (32 - prefix));
    // guard accidental scans of huge address ranges /16 is the largest accepted range
    if (count > 65536ULL)
        return fail("CIDR contains more than 65,536 addresses; use a narrower range.");

    for (uint64_t i = 0; i < count; ++i)
    {
        in_addr current;
        current.s_addr = htonl(first + static_cast<uint32_t>(i));
        char text[INET_ADDRSTRLEN] = {};
        if (!inet_ntop(AF_INET, &current, text, sizeof(text)))
            return fail("Failed to format IPv4 address.");
        addresses.push_back(text);
    }
    return addresses;
}

PortResult scan_port_tcp(const std::string &ip, int port, int timeout_ms)
{
    PortResult result = make_result(ip, port, "tcp", "closed");
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        result.state = "error";
        return result;
    }

    const int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        close(fd);
        result.state = "error";
        return result;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1)
    {
        close(fd);
        result.state = "error";
        return result;
    }

    const int rc = connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS)
    {
        result.state = (errno == ECONNREFUSED) ? "closed" : "error";
        close(fd);
        return result;
    }

    if (rc < 0)
    {
        const WaitStatus wait_status = wait_fd(fd, true, timeout_ms);
        if (wait_status == WaitStatus::Timeout)
        {
            result.state = "filtered";
            close(fd);
            return result;
        }
        if (wait_status == WaitStatus::Error)
        {
            result.state = "error";
            close(fd);
            return result;
        }

        int socket_error = 0;
        socklen_t len = sizeof(socket_error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &len) < 0)
        {
            result.state = "error";
            close(fd);
            return result;
        }
        if (socket_error != 0)
        {
            if (socket_error == ECONNREFUSED)
                result.state = "closed";
            else if (socket_error == ETIMEDOUT)
                result.state = "filtered";
            else
                result.state = "error";
            close(fd);
            return result;
        }
    }

    result.state = "open";
    result.banner = grab_banner(fd, ip, port, timeout_ms);
    close(fd);
    return result;
}
PortResult scan_port_udp(const std::string &ip, int port, int timeout_ms)
{
    PortResult result = make_result(ip, port, "udp", "open|filtered");
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        result.state = "error";
        return result;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1)
    {
        result.state = "error";
        close(fd);
        return result;
    }

    if (connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
    {
        result.state = (errno == ECONNREFUSED) ? "closed" : "error";
        close(fd);
        return result;
    }

    // a zero-length UDP datagram is a minimal reachability probe
    const ssize_t sent = send(fd, "", 0, 0);
    if (sent < 0)
    {
        result.state = (errno == ECONNREFUSED) ? "closed" : "error";
        close(fd);
        return result;
    }

    const WaitStatus wait_status = wait_fd(fd, false, timeout_ms);
    if (wait_status == WaitStatus::Timeout)
    {
        result.state = "open|filtered";
        close(fd);
        return result;
    }
    if (wait_status == WaitStatus::Error)
    {
        result.state = "error";
        close(fd);
        return result;
    }

    char buffer[512] = {};
    const ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
    if (received >= 0)
    {
        result.state = "open";
        result.banner = clean_banner(buffer, static_cast<size_t>(received));
    }
    else if (errno == ECONNREFUSED)
    {
        result.state = "closed";
    }
    else
    {
        result.state = "error";
    }

    close(fd);
    return result;
}

void pool_worker_thread(
    const std::vector<std::string> &ips,
    int start_port,
    std::uint32_t port_count,
    const std::string &protocol,
    std::uint64_t total_tasks,
    std::atomic<std::uint64_t> &next_task_index,
    int timeout_ms,
    std::vector<ScanOutcome> &outcomes,
    std::atomic<std::uint64_t> &progress_counter)
{
    for (;;)
    {
        const std::uint64_t index =
            next_task_index.fetch_add(1, std::memory_order_relaxed);
        if (index >= total_tasks)
        {
            break;
        }

        const std::size_t ip_index =
            static_cast<std::size_t>(index / port_count);
        const int port = start_port +
                         static_cast<int>(index % port_count);

        PortResult result = protocol == "udp"
                                ? scan_port_udp(ips[ip_index], port, timeout_ms)
                                : scan_port_tcp(ips[ip_index], port, timeout_ms);

        ScanOutcome outcome;
        if (result.state == "open")
        {
            outcome.state = PortState::Open;
        }
        else if (result.state == "closed")
        {
            outcome.state = PortState::Closed;
        }
        else if (result.state == "filtered")
        {
            outcome.state = PortState::Filtered;
        }
        else if (result.state == "open|filtered")
        {
            outcome.state = PortState::OpenFiltered;
        }
        else
        {
            outcome.state = PortState::Error;
        }
        outcome.banner = std::move(result.banner);

        // each task index is claimed exactly once, so each worker writes
        // to a distinct preallocated vector element without a result mutex
        outcomes[static_cast<std::size_t>(index)] = std::move(outcome);
        progress_counter.fetch_add(1, std::memory_order_release);
    }
}
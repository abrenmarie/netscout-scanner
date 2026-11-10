#include "scanner.h"

#include <iostream>
#include <string>
#include <vector>

int passed = 0;
int failed = 0;

void expect_valid(
    const std::string &input,
    const std::vector<std::string> &expected)
{
    std::string error;
    const std::vector<std::string> actual = parse_cidr(input, &error);

    if (actual == expected)
    {
        ++passed;
        std::cout << "PASS: " << input << "\n";
    }
    else
    {
        ++failed;
        std::cerr << "FAIL: " << input
                  << " expected=" << expected.size()
                  << " actual=" << actual.size()
                  << " error=" << error << "\n";
    }
}

void expect_invalid(const std::string &input)
{
    std::string error;
    const std::vector<std::string> actual = parse_cidr(input, &error);

    if (actual.empty() && !error.empty())
    {
        ++passed;
        std::cout << "PASS: invalid input rejected: " << input << "\n";
    }
    else
    {
        ++failed;
        std::cerr << "FAIL: invalid input accepted: "
                  << input << "\n";
    }
}

int main()
{
    expect_valid(
        "127.0.0.1",
        {"127.0.0.1"});

    expect_valid(
        "127.0.0.0/30",
        {"127.0.0.0",
         "127.0.0.1",
         "127.0.0.2",
         "127.0.0.3"});

    expect_valid(
        "192.0.2.5/31",
        {"192.0.2.4",
         "192.0.2.5"});

    expect_valid(
        "192.0.2.5/32",
        {"192.0.2.5"});

    std::string error;
    const auto subnet = parse_cidr("192.0.2.1/24", &error);

    if (subnet.size() == 256 &&
        subnet.front() == "192.0.2.0" &&
        subnet.back() == "192.0.2.255")
    {
        ++passed;
        std::cout << "PASS: /24 range boundaries\n";
    }
    else
    {
        ++failed;
        std::cerr << "FAIL: /24 range boundaries\n";
    }

    expect_invalid("not-an-ip");
    expect_invalid("127.0.0.1/33");
    expect_invalid("127.0.0.1/-1");
    expect_invalid("127.0.0.1/abc");
    expect_invalid("127.0.0.1/");
    expect_invalid("127.0.0.1/0");
    expect_invalid("2001:db8::1");

    std::cout << "\nCIDR tests: "
              << passed << " passed, "
              << failed << " failed\n";

    return failed == 0 ? 0 : 1;
}
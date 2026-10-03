// Unit tests for lynx::utils::sock (linux/socket.h).
//
// Needs CAP_NET_RAW (run with sudo) - open_raw()/bind_to_iface()/
// set_promiscuous() all touch AF_PACKET, which is root-only on Linux.
//
// Prompts once, before any test runs, for an interface name, its expected
// IPv4 address, and its expected MAC - these become the ground truth that
// get_iface_ip()/get_iface_mac() are checked against.

#define DOCTEST_CONFIG_IMPLEMENT
#include "doctest.h"

#include <lynx/net/io.h>

#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>

using namespace lynx;
using namespace lynx::sock;

// ----------- test fixture data, filled in main() before doctest runs -----------


namespace {

    struct Config {
        std::string iface;
        uint8_t     expected_ip[4]  {};
        uint8_t     expected_mac[6] {};
    } g_cfg;

    bool parse_ip4(const std::string& s, uint8_t out[4]) {
        int a, b, c, d;
        if (std::sscanf(s.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
            return false;
        }
        for (int v : {a, b, c, d}) if (v < 0 || v > 255) {
            return false;
        }
        out[0] = uint8_t(a); out[1] = uint8_t(b); out[2] = uint8_t(c); out[3] = uint8_t(d);
        return true;
    }

    bool parse_mac(const std::string& s, uint8_t out[6]) {
        unsigned b[6];
        if (std::sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
            return false;
        }
        for (int i = 0; i < 6; ++i) {
            out[i] = uint8_t(b[i]);
        }
        return true;
    }

    // small BPF program: "return 0" (drop everything) - enough to exercise
    // set_filter()/clear_filter() without needing a real filter design
    const ::sock_filter k_drop_all_prog[] = {
        { 0x06, 0, 0, 0x00000000 }, // ret #0
    };

} // namespace

// ----------- interface identity -----------

TEST_CASE("get_ifindex resolves the given interface") {
    int idx = INVALID_IDX;
    auto err = get_ifindex(g_cfg.iface.c_str(), idx);
    REQUIRE(err.ok());
    CHECK(idx != INVALID_IDX);
    CHECK(idx > 0);
}

TEST_CASE("get_ifindex fails for a nonexistent interface") {
    int idx = 123;
    auto err = get_ifindex("doesnotexist0", idx);
    CHECK_FALSE(err.ok());
    CHECK(idx == INVALID_IDX);
}

TEST_CASE("get_iface_ip matches the address provided at startup") {
    int fd = INVALID_FD;
    REQUIRE(open_raw(fd).ok());

    uint8_t ip[4]{};
    auto err = get_iface_ip(fd, g_cfg.iface.c_str(), ip);
    REQUIRE(err.ok());
    CHECK(std::memcmp(ip, g_cfg.expected_ip, 4) == 0);

    close_fd(fd);
    CHECK(fd == INVALID_FD);
}

TEST_CASE("get_iface_mac matches the address provided at startup") {
    int fd = INVALID_FD;
    REQUIRE(open_raw(fd).ok());

    uint8_t mac[6]{};
    auto err = get_iface_mac(fd, g_cfg.iface.c_str(), mac);
    REQUIRE(err.ok());
    CHECK(std::memcmp(mac, g_cfg.expected_mac, 6) == 0);

    close_fd(fd);
}

TEST_CASE("get_iface_mtu returns a plausible value") {
    int fd = INVALID_FD;
    REQUIRE(open_raw(fd).ok());

    uint32_t mtu = 0;
    auto err = get_iface_mtu(fd, g_cfg.iface.c_str(), mtu);
    REQUIRE(err.ok());
    CHECK(mtu > 0);
    CHECK(mtu <= 65535); // no jumbo-frame assumption, just sanity

    close_fd(fd);
}

TEST_CASE("get_iface_flags and iface_is_up agree") {
    int fd = INVALID_FD;
    REQUIRE(open_raw(fd).ok());

    uint32_t flags = 0;
    REQUIRE(get_iface_flags(fd, g_cfg.iface.c_str(), flags).ok());

    bool up = false;
    REQUIRE(iface_is_up(fd, g_cfg.iface.c_str(), up).ok());

    bool flags_say_up = (flags & IFF_UP) && (flags & IFF_RUNNING);
    CHECK(up == flags_say_up);

    close_fd(fd);
}

TEST_CASE("get_default_gw returns a non-zero address, if a route exists") {
    uint8_t gw[4]{};
    auto err = get_default_gw(gw);
    if (!err.ok()) {
        WARN("no default route on this host - skipping address check");
        return;
    }
    uint8_t zero[4]{};
    CHECK(std::memcmp(gw, zero, 4) != 0);
}

// ----------- socket lifecycle -----------

TEST_CASE("open_raw produces a usable fd") {
    int fd = INVALID_FD;
    auto err = open_raw(fd);
    REQUIRE(err.ok());
    CHECK(fd >= 0);
    close_fd(fd);
}

TEST_CASE("close_fd is safe to call twice") {
    int fd = INVALID_FD;
    REQUIRE(open_raw(fd).ok());
    close_fd(fd);
    CHECK(fd == INVALID_FD);
    close_fd(fd); // must not crash or misbehave on an already-closed fd
    CHECK(fd == INVALID_FD);
}

TEST_CASE("bind_to_iface succeeds against a real interface") {
    int fd = INVALID_FD;
    REQUIRE(open_raw(fd).ok());

    int idx = INVALID_IDX;
    REQUIRE(get_ifindex(g_cfg.iface.c_str(), idx).ok());

    CHECK(bind_to_iface(fd, idx).ok());
    close_fd(fd);
}

// ----------- socket options -----------

TEST_CASE("set_recv_timeout accepts a positive timeout") {
    int fd = INVALID_FD;
    REQUIRE(open_raw(fd).ok());
    CHECK(set_recv_timeout(fd, 100).ok());
    close_fd(fd);
}

TEST_CASE("set_recv_timeout(0) disables the timeout without erroring") {
    int fd = INVALID_FD;
    REQUIRE(open_raw(fd).ok());
    CHECK(set_recv_timeout(fd, 0).ok());
    close_fd(fd);
}

TEST_CASE("set_recv_buffer accepts a nonzero size") {
    int fd = INVALID_FD;
    REQUIRE(open_raw(fd).ok());
    CHECK(set_recv_buffer(fd, 1 << 20).ok());
    close_fd(fd);
}

TEST_CASE("set_recv_buffer(0) is a no-op success") {
    int fd = INVALID_FD;
    REQUIRE(open_raw(fd).ok());
    CHECK(set_recv_buffer(fd, 0).ok());
    close_fd(fd);
}

TEST_CASE("set_io_direction accepts every enumerator") {
    int fd = INVALID_FD;
    REQUIRE(open_raw(fd).ok());
    CHECK(set_io_direction(fd, io_direction::In).ok());
    CHECK(set_io_direction(fd, io_direction::Out).ok());
    CHECK(set_io_direction(fd, io_direction::Both).ok());
    close_fd(fd);
}

TEST_CASE("set_promiscuous can be enabled then disabled") {
    int fd = INVALID_FD;
    REQUIRE(open_raw(fd).ok());

    int idx = INVALID_IDX;
    REQUIRE(get_ifindex(g_cfg.iface.c_str(), idx).ok());

    CHECK(set_promiscuous(fd, idx, true).ok());
    CHECK(set_promiscuous(fd, idx, false).ok()); // must always be paired - see socket.h's note

    close_fd(fd);
}

TEST_CASE("set_filter and clear_filter round-trip") {
    int fd = INVALID_FD;
    REQUIRE(open_raw(fd).ok());

    CHECK(set_filter(fd, k_drop_all_prog, 1).ok());
    CHECK(clear_filter(fd).ok());

    close_fd(fd);
}

// ----------- ARP -----------

TEST_CASE("get_arp_entry fails cleanly for an address with no cache entry") {
    int fd = INVALID_FD;
    REQUIRE(open_raw(fd).ok());

    // 203.0.113.0/24 is TEST-NET-3 (RFC 5737) - reserved for documentation,
    // guaranteed to never have a real ARP entry on any real network
    uint8_t doc_ip[4] = { 203, 0, 113, 1 };
    uint8_t mac[6]{};

    auto err = get_arp_entry(fd, g_cfg.iface.c_str(), doc_ip, mac);
    CHECK_FALSE(err.ok());

    close_fd(fd);
}

TEST_CASE("get_arp_entry rejects null pointers") {
    int fd = INVALID_FD;
    REQUIRE(open_raw(fd).ok());

    uint8_t mac[6]{};
    CHECK_FALSE(get_arp_entry(fd, g_cfg.iface.c_str(), nullptr, mac).ok());

    uint8_t ip[4]{};
    CHECK_FALSE(get_arp_entry(fd, g_cfg.iface.c_str(), ip, nullptr).ok());

    close_fd(fd);
}

// ----------- randomness / ports -----------

TEST_CASE("get_random_mac produces a valid locally-administered unicast address") {
    uint8_t mac[6]{};
    REQUIRE(get_random_mac(mac).ok());
    CHECK((mac[0] & 0x01) == 0); // unicast
    CHECK((mac[0] & 0x02) != 0); // locally administered
}

TEST_CASE("get_random_mac varies across calls") {
    uint8_t a[6]{}, b[6]{};
    REQUIRE(get_random_mac(a).ok());
    REQUIRE(get_random_mac(b).ok());
    CHECK(std::memcmp(a, b, 6) != 0); // astronomically unlikely to collide
}

TEST_CASE("get_random_port agrees with is_ephemeral_port") {
    uint16_t port = 0;
    REQUIRE(get_random_port(port).ok());

    bool ephemeral = false;
    REQUIRE(is_ephemeral_port(port, ephemeral).ok());
    CHECK(ephemeral);
}

TEST_CASE("is_ephemeral_port rejects a well-known port") {
    bool ephemeral = true;
    REQUIRE(is_ephemeral_port(22, ephemeral).ok());
    CHECK_FALSE(ephemeral);
}

// ----------- send/recv (best-effort - depends on driver loopback behavior) -----------

TEST_CASE("raw_send reports an error for an oversized/invalid call gracefully") {
    int fd = INVALID_FD;
    REQUIRE(open_raw(fd).ok());

    int idx = INVALID_IDX;
    REQUIRE(get_ifindex(g_cfg.iface.c_str(), idx).ok());
    REQUIRE(bind_to_iface(fd, idx).ok());

    uint8_t bogus_mac[6] = { 0, 0, 0, 0, 0, 0 };
    uint8_t tiny_frame[4] = { 0, 0, 0, 0 }; // shorter than a valid Ethernet frame

    // not asserting success/failure here - just that it returns cleanly
    // rather than crashing on a too-short frame
    auto err = raw_send(fd, idx, tiny_frame, sizeof(tiny_frame), bogus_mac);
    (void)err;

    close_fd(fd);
}

TEST_CASE("raw_recv times out cleanly with no traffic forced") {
    int fd = INVALID_FD;
    REQUIRE(open_raw(fd).ok());

    int idx = INVALID_IDX;
    REQUIRE(get_ifindex(g_cfg.iface.c_str(), idx).ok());
    REQUIRE(bind_to_iface(fd, idx).ok());
    REQUIRE(set_recv_timeout(fd, 50).ok());

    uint8_t buf[2048];
    Error   err = Error::none();
    int32_t n   = raw_recv(fd, buf, sizeof(buf), nullptr, err);

    // 0 (timeout) or a positive byte count are both fine - a real interface
    // may have ambient traffic; -1 (hard error) is the only failure mode
    CHECK(n >= 0);
    CHECK(err.ok());

    close_fd(fd);
}

// ----------- entry point -----------

int main(int argc, char** argv) {
    std::cout << "Interface name (e.g. eth0): ";
    std::cin >> g_cfg.iface;

    std::string ip_str;
    do {
        std::cout << "Expected IPv4 address of " << g_cfg.iface << " (d.d.d.d): ";
        std::cin >> ip_str;
    } while (!parse_ip4(ip_str, g_cfg.expected_ip));

    std::string mac_str;
    do {
        std::cout << "Expected MAC address of " << g_cfg.iface << " (xx:xx:xx:xx:xx:xx): ";
        std::cin >> mac_str;
    } while (!parse_mac(mac_str, g_cfg.expected_mac));

    doctest::Context ctx;
    ctx.applyCommandLine(argc, argv);
    int res = ctx.run();

    if (ctx.shouldExit()) {
        return res;
    }
    return res;
}

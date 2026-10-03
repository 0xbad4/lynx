#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include <lynx/core/utils.h>

using namespace lynx;
using namespace lynx::utils;

TEST_CASE("mac_str formats bytes as xx:xx:xx:xx:xx:xx") {
    uint8_t mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    CHECK(std::string(codec::mac_str(mac).c_str()) == "aa:bb:cc:dd:ee:ff");
}
 
TEST_CASE("parse_mac round-trips a valid string") {
    uint8_t mac[6] = {0x01, 0x02, 0x03, 0xaa, 0xbb, 0xcc};
    CHECK(codec::parse_mac("01:02:03:aa:bb:cc") == mn_mac(mac));
    CHECK(codec::parse_mac("01-02-03-aa-bb-cc") == mn_mac(mac)); // hyphens ok
}

TEST_CASE("parse_mac rejects garbage") {
    uint8_t zero[6] = {};
    CHECK(codec::parse_mac("not a mac") == mn_mac(zero));
    CHECK(codec::parse_mac("aa:bb:cc:dd:ee") == mn_mac(zero));   // too short
    CHECK(codec::parse_mac(nullptr) == mn_mac(zero));
}

TEST_CASE("ip_str formats bytes as dotted-decimal") {
    uint8_t ip[4] = {192, 168, 1, 1};
    CHECK(std::string(codec::ip_str(ip).c_str()) == "192.168.1.1");
}

TEST_CASE("parse_ip round-trips a valid string") {
    uint8_t ip[4] = {10, 0, 0, 1};
    CHECK(codec::parse_ip("10.0.0.1") == mn_ipv4(ip));
}

TEST_CASE("parse_ip rejects garbage") {
    uint8_t zero[4] = {};
    CHECK(codec::parse_ip("256.1.1.1") == mn_ipv4(zero)); // out of range
    CHECK(codec::parse_ip("1.2.3") == mn_ipv4(zero));      // too few octets
    CHECK(codec::parse_ip(nullptr) == mn_ipv4(zero));
}

TEST_CASE("ip6_str / parse_ip6 round-trip") {
    uint8_t ip6[16] = {0xfe, 0x80, 0,0,0,0,0,0,0,0,0,0,0,0,0,0x01};
    auto s = codec::ip6_str(ip6);
    CHECK(codec::parse_ip6(s.c_str()) == mn_ipv6(ip6));
}

TEST_CASE("mac_eui64 sets bytes 8-15, leaves 0-7 zero") {
    uint8_t mac[6] = {0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e};
    auto id = codec::mac_eui64(mac);
    CHECK(id[0] == 0x00); // prefix half must be untouched
    CHECK(id[8] == 0x02); // 0x00 ^ 0x02 (universal/local bit flipped)
    CHECK(id[11] == 0xFF);
    CHECK(id[12] == 0xFE);
    CHECK(id[15] == 0x5e);
}

TEST_CASE("checksum matches a known RFC 1071 example") {
    // classic example: 0x0001 0xf203 0xf4f5 0xf6f7 -> checksum 0x220d
    uint8_t data[] = {0x00,0x01, 0xf2,0x03, 0xf4,0xf5, 0xf6,0xf7};
    CHECK(checksum::inet(data, sizeof(data)) == 0x220d);
}

TEST_CASE("checksum is order-sensitive (sanity, not a real property)") {
    uint8_t a[] = {0x12, 0x34};
    uint8_t b[] = {0x34, 0x12};
    CHECK(checksum::inet(a, 2) != checksum::inet(b, 2));
}

TEST_CASE("crc32c matches a known vector") {
    // CRC-32C("123456789") is a standard test vector
    const uint8_t* data = reinterpret_cast<const uint8_t*>("123456789");
    CHECK(checksum::crc32c(data, 9) == 0xE3069283);
}

TEST_CASE("bswap reverses byte order") {
    CHECK(mem::bswap<uint16_t>(0x1234) == 0x3412);
    CHECK(mem::bswap<uint32_t>(0x11223344) == 0x44332211);
}

TEST_CASE("memory_copy / memory_zero do what they say") {
    uint8_t src[4] = {1, 2, 3, 4};
    uint8_t dst[4] = {};
    mem::copy(dst, src, 4);
    CHECK(memcmp(dst, src, 4) == 0);

    mem::zero(dst, 4);
    uint8_t zero[4] = {};
    CHECK(memcmp(dst, zero, 4) == 0);
}

TEST_CASE("mac_randomize sets unicast + locally-administered bits") {
    uint8_t mac[6];
    codec::randomize_mac(mac);
    CHECK((mac[0] & 0x01) == 0); // unicast
    CHECK((mac[0] & 0x02) != 0); // locally administered
}

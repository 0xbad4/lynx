#pragma once

#include "lynx/core/common.h"
#include "lynx/core/view.h"
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <bit>
#include <concepts>

/**
 * @brief Utility helpers used throughout the library.
 *
 * This namespace groups small conversion, checksum, memory, and arithmetic
 * helpers used by protocol implementations and network utilities.
 */
namespace lynx::utils {
    /**
     * @brief Status-to-string conversion helpers.
     */
    namespace err {
        /**
         * @brief Returns a static string representation of a status code.
         *
         * @param s status value to convert to a string.
         *
         * @return Null-terminated static string describing @p s.
         *
         * @code
         * printf("Error: %s\n", lynx::utils::err::status_str(status::IfaceNotOpen));
         * @endcode
         * 
         * @note Performs no dynamic allocation or system calls and is safe to use
         *       from signal handlers.
         */
        [[nodiscard]] inline const char* status_str(status s) noexcept {
            switch (s) {
                case status::Ok:                return "ok";
                case status::SocketCreateFail:  return "socket create failed";
                case status::SocketBindFail:    return "socket bind failed";
                case status::SocketOptionFail:  return "socket option failed";
                case status::IfaceNotFound:     return "interface not found";
                case status::IfaceNotOpen:      return "interface not open";
                case status::IfaceAlreadyOpen:  return "interface already open";
                case status::MacResolveFail:    return "MAC resolve failed";
                case status::ArpResolveFail:    return "ARP lookup failed";
                case status::SendFail:          return "send failed";
                case status::SendTruncated:     return "send truncated";
                case status::RecvFail:          return "recv failed";
                case status::RecvTimeout:       return "recv timeout";
                case status::BufferTooSmall:    return "buffer too small";
                case status::BufferAllocFail:   return "buffer alloc failed";
                case status::MalformedPacket:   return "malformed packet";
                case status::TruncatedPayload:  return "truncated payload";
                case status::MissingLayer:      return "missing required layer";
                case status::InvalidState:      return "invalid state";
                case status::InvalidView:       return "invalid view";
                case status::InvalidArgument:   return "invalid argument";
                case status::NotImplemented:    return "not implemented";
                case status::Unknown:           return "unknown";
                default:                        return "unknown error";
            }
        }
    } // namespace err
    
    /**
     * @brief Conversion helpers for MAC, IPv4, and IPv6 addresses.
     *
     * @details The codec namespace contains small, stateless routines used to format and
     * parse protocol addresses and numeric payloads.
     */
    namespace codec
    {
        /**
         * @brief Hex digit alphabet used to format byte values as printable text.
         */
        static constexpr uint8_t kHex[] = "0123456789abcdef";

        /**
         * @brief Converts one ASCII hex character to its 4-bit numeric value.
         * @param c ASCII character in range '0'-'9', 'a'-'f', or 'A'-'F'.
         * @return Numeric value 0-15, or 0xFF on invalid input.
         */
        static constexpr uint8_t hex_val(uint8_t c) noexcept {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
            return 0xFF;
        }

        /**
         * @brief Formats a 6-byte MAC address as "xx:xx:xx:xx:xx:xx".
         * @param mac Pointer to 6 raw MAC bytes.
         * @return Formatted address, convertible to const char*.
         * 
         * @code
         * uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
         * auto txt = lynx::utils::codec::mac_str(mac);
         * @endcode
        */
        [[nodiscard]] inline hr_mac mac_str(const uint8_t mac[6]) noexcept {
            char buf[18];
            for (int i = 0; i < 6; ++i) {
                const uint8_t b = mac[i];
                buf[i * 3]     = kHex[b >> 4];
                buf[i * 3 + 1] = kHex[b & 0x0F];
                buf[i * 3 + 2] = (i != 5) ? ':' : '\0';
            }
            return hr_mac(buf);
        }

        /**
         * @brief Parses a MAC address string into 6 raw bytes.
         * @details Accepts colon-separated ("xx:xx:xx:xx:xx:xx") and
         *          hyphen-separated ("xx-xx-xx-xx-xx-xx") formats.
         *@@param s Null-terminated MAC string.
         *@@return Parsed address, or all-zero on malformed input.
         */
        [[nodiscard]] inline mn_mac parse_mac(const char* s) noexcept {
            if (!s) return mn_mac{};
            uint8_t tmp[6];
            const char* p = s;
            for (int i = 0; i < 6; ++i) {
                const uint8_t hi = hex_val(static_cast<uint8_t>(p[0]));
                const uint8_t lo = hex_val(static_cast<uint8_t>(p[1]));
                if (hi == 0xFF || lo == 0xFF) return mn_mac{};
                tmp[i] = static_cast<uint8_t>((hi << 4) | lo);
                p += 2;
                if (i != 5) {
                    if (*p != ':' && *p != '-') return mn_mac{};
                    ++p;
                }
            }
            return (*p == '\0') ? mn_mac(tmp) : mn_mac{};
        }

        /**
         * @brief Generates a random locally-administered unicast MAC address.
         * @details Uses rand(). Not cryptographically secure.
         *          Bit 0 of byte 0 is cleared (unicast).
         *          Bit 1 of byte 0 is set (locally administered).
         * @param mac Output buffer of at least 6 bytes.
         */
        inline void randomize_mac(uint8_t mac[6]) noexcept {
            for (int i = 0; i < 6; ++i) {
                mac[i] = static_cast<uint8_t>(rand() % 256);
            }
            mac[0] = (mac[0] & 0xFE) | 0x02;
        }

        /**
         * @brief Formats a 4-byte IPv4 address in dotted-decimal notation.
         * @param ip Pointer to 4 raw IPv4 bytes in network byte order.
         * @return Formatted address, convertible to const char*.
         */
        [[nodiscard]] inline hr_ipv4 ip_str(const uint8_t ip[4]) noexcept {
            char buf[16];
            int pos = 0;
            for (int i = 0; i < 4; ++i) {
                const uint8_t b = ip[i];
                if      (b >= 100) { buf[pos++] = '0' + b / 100;
                                    buf[pos++] = '0' + (b / 10) % 10;
                                    buf[pos++] = '0' + b % 10; }
                else if (b >= 10)  { buf[pos++] = '0' + b / 10;
                                    buf[pos++] = '0' + b % 10; }
                else               { buf[pos++] = '0' + b; }
                buf[pos++] = (i != 3) ? '.' : '\0';
            }
            return hr_ipv4(buf);
        }

        /**
         * @brief Parses a dotted-decimal IPv4 string into 4 raw bytes.
         * @details Each octet must be in the range 0-255.
         * @param s Null-terminated string in "d.d.d.d" format.
         * @return Parsed address, or all-zero on malformed input.
         */
        [[nodiscard]] inline mn_ipv4 parse_ip(const char* s) noexcept {
            if (!s) return mn_ipv4{};
            uint8_t tmp[4];
            const char* p = s;
            for (int i = 0; i < 4; ++i) {
                if (*p < '0' || *p > '9') return mn_ipv4{};
                uint32_t val = 0;
                int      dig = 0;
                while (*p >= '0' && *p <= '9') {
                    val = val * 10 + static_cast<uint32_t>(*p++ - '0');
                    if (++dig > 3 || val > 255) return mn_ipv4{};
                }
                tmp[i] = static_cast<uint8_t>(val);
                if (i != 3) {
                    if (*p != '.') return mn_ipv4{};
                    ++p;
                }
            }
            return (*p == '\0') ? mn_ipv4(tmp) : mn_ipv4{};
        }

        /**
         * @brief Formats a 16-byte IPv6 address in full uncompressed hex-colon notation.
         * @details Output has no :: compression.
         * @param ip Pointer to 16 raw IPv6 bytes in network byte order.
         * @return Formatted address, convertible to const char*.
         */
        [[nodiscard]] inline hr_ipv6 ip6_str(const uint8_t ip[16]) noexcept {
            char buf[40];
            for (int i = 0; i < 8; ++i) {
                const uint16_t w = (static_cast<uint16_t>(ip[i * 2]) << 8) | ip[i * 2 + 1];
                buf[i * 5]     = kHex[(w >> 12) & 0x0F];
                buf[i * 5 + 1] = kHex[(w >>  8) & 0x0F];
                buf[i * 5 + 2] = kHex[(w >>  4) & 0x0F];
                buf[i * 5 + 3] = kHex[ w        & 0x0F];
                buf[i * 5 + 4] = (i != 7) ? ':' : '\0';
            }
            return hr_ipv6(buf);
        }

        /**
         * @brief Parses a full uncompressed IPv6 hex-colon string into 16 raw bytes.
         * @details Does not handle :: compression. Each group must be 1-4 hex digits.
         * @param s Null-terminated string in "xxxx:xxxx:..." format.
         * @return Parsed address, or all-zero on malformed input.
         */
        [[nodiscard]] inline mn_ipv6 parse_ip6(const char* s) noexcept {
            if (!s) return mn_ipv6{};
            uint8_t tmp[16];
            const char* p = s;
            for (int i = 0; i < 8; ++i) {
                uint16_t val = 0;
                int      dig = 0;
                while ((*p >= '0' && *p <= '9') ||
                    (*p >= 'a' && *p <= 'f') ||
                    (*p >= 'A' && *p <= 'F')) {
                    const uint8_t n = hex_val(static_cast<uint8_t>(*p++));
                    if (n == 0xFF) return mn_ipv6{};
                    val = static_cast<uint16_t>((val << 4) | n);
                    if (++dig > 4) return mn_ipv6{};
                }
                tmp[i * 2]     = static_cast<uint8_t>(val >> 8);
                tmp[i * 2 + 1] = static_cast<uint8_t>(val & 0xFF);
                if (i != 7) {
                    if (*p != ':') return mn_ipv6{};
                    ++p;
                }
            }
            return (*p == '\0') ? mn_ipv6(tmp) : mn_ipv6{};
        }

        /**
         * @brief Derives an EUI-64 interface identifier from a MAC address per RFC 4291 §2.5.1.
         * @details Writes only bytes 8-15 of the result. Bytes 0-7 are zero -
         *          the caller sets the desired prefix (e.g. fe80::/64) before use.
         * @param mac Pointer to 6 raw MAC bytes.
         * @return Address with the EUI-64 IID in bytes [8..15], zeros in bytes [0..7].
         */
        [[nodiscard]] inline mn_ipv6 mac_eui64(const uint8_t mac[6]) noexcept {
            uint8_t tmp[16] = {};
            tmp[8]  = mac[0] ^ 0x02;
            tmp[9]  = mac[1];
            tmp[10] = mac[2];
            tmp[11] = 0xFF;
            tmp[12] = 0xFE;
            tmp[13] = mac[3];
            tmp[14] = mac[4];
            tmp[15] = mac[5];
            return mn_ipv6(tmp);
        }
    } // namespace codec

    /**
     * @brief Memory operations for buffer setup and copying.
     */
    namespace mem
    {
        /**
         * @brief Byte-swaps an unsigned integer of any width.
         *
         * @tparam T Must be an unsigned integer type.
         * @param value Value to swap.
         * @return Byte-swapped value.
         *
         * @code
         * uint16_t swapped = lynx::utils::mem::bswap<uint16_t>(0x1234);
         * @endcode
         */
        template<typename T>
        requires std::unsigned_integral<T>
        [[nodiscard]] static constexpr T bswap(T value) noexcept {
            return std::byteswap(value);
        }

        /**
         * @brief Copies @p size bytes from @p src to @p dst.
         *
         * @param dst Destination buffer.
         * @param src Source buffer.
         * @param size Number of bytes to copy.
         */
        static inline void copy(void* dst, const void* src, size_t size) noexcept {
            memcpy(dst, src, size);
        }

        /**
         * @brief Zeroes @p size bytes starting at @p dst.
         *
         * @param dst Destination buffer.
         * @param size Number of bytes to zero.
         */
        static inline void zero(void* dst, size_t size) noexcept {
            memset(dst, 0, size);
        }

        /**
         * @brief Fills a buffer with pseudo-random bytes.
         *
         * @param buf Output buffer.
         * @param len Number of bytes to fill.
         * @return view over the filled region.
         */
        inline view randomize(uint8_t* buf, size_t len) noexcept {
            for (size_t i = 0; i < len; ++i) {
                buf[i] = static_cast<uint8_t>(rand() % 256);
            }
            return view(buf, len);
        }
    } // namespace mem
    
    /**
     * @brief Checksum helpers for IPv4 and transport-layer validation.
     */
    namespace checksum
    {
        /**
         * @brief RFC 1071 one's-complement checksum.
         *
         * @param data Pointer to the byte sequence.
         * @param len  Length in bytes.
         * @return 16-bit checksum in host byte order.
         */
        [[nodiscard]] inline uint16_t inet(const uint8_t* data, size_t len) noexcept {
            uint32_t sum = 0;
            while (len > 1) {
                sum += static_cast<uint16_t>((data[0] << 8) | data[1]);
                data += 2;
                len  -= 2;
            }
            if (len)
                sum += static_cast<uint16_t>(data[0] << 8);
            while (sum >> 16)
                sum = (sum & 0xffff) + (sum >> 16);
            return static_cast<uint16_t>(~sum);
        }

        /**
         * @brief View overload of checksum().
         *
         * @param data Byte view.
         * @return 16-bit checksum in host byte order.
         */
        [[nodiscard]] inline uint16_t inet(view data) noexcept {
            return inet(data.data(), data.size());
        }

        /**
         * @brief Builds the CRC-32C lookup table.
         *
         * @return Table used by @ref crc32c.
         */
        inline constexpr auto make_crc32c_table() noexcept {
            struct T { uint32_t v[256]; } t{};

            for (uint32_t i = 0; i < 256; ++i) {
                uint32_t c = i;
                for (int j = 0; j < 8; ++j)
                    c = (c & 1) ? (0x82F63B78u ^ (c >> 1)) : (c >> 1);
                t.v[i] = c;
            }
            return t;
        }

        /**
         * @brief CRC-32C lookup table used by @ref crc32c.
         */
        inline constexpr auto kCRC32C = make_crc32c_table();

        /**
         * @brief CRC-32c (Castagnoli) checksum.
         *
         * @param data Pointer to the byte sequence.
         * @param len Length in bytes.
         * @return 32-bit CRC-32c value.
         */
        [[nodiscard]] inline uint32_t crc32c(const uint8_t* data, uint32_t len) noexcept {
            uint32_t crc = CRC32C_INIT;
            for (uint32_t i = 0; i < len; ++i) {
                crc = kCRC32C.v[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
            }
            return ~crc;
        }
    } // namespace checksum

    /**
     * @brief Common arithmetic helpers.
     */
    namespace math {
        /**
         * @brief Returns the smaller of two values.
         *
         * @tparam T Value type.
         * @param a First value.
         * @param b Second value.
         * @return The smaller value.
         */
        template<typename T>
        constexpr T min(T a, T b) {
            return a < b ? a : b;
        }

        /**
         * @brief Returns the larger of two values.
         *
         * @tparam T Value type.
         * @param a First value.
         * @param b Second value.
         * @return The larger value.
         */
        template<typename T>
        constexpr T max(T a, T b) {
            return a > b ? a : b;
        }
    }
    

} // namespace lynx::utils

#pragma once


#include <memory>
#include <cerrno>
#include <cstring>
#include <cstdint>

/**
 * @brief Common attributes and custom library types.
 *
 * Defines shared attributes and custom types used throughout the library.
 */

namespace lynx
{
    /**
     * @brief Marks a structure as packed with no padding between members.
     *
     * This macro is used for protocol headers whose on-wire layout must match the
     * binary format exactly.
     */
    #define LYNX_PACKED struct __attribute__((packed))
    
    /**
     * @brief CRC-32C polynomial used for checksum calculation.
     */
    inline constexpr uint32_t CRC32C_POLY = 0x1EDC6F41;

    /**
     * @brief Initial value used by the CRC-32C checksum algorithm.
     */
    inline constexpr uint32_t CRC32C_INIT = 0xFFFFFFFF;

    /**
     * @brief Shorthand for a shared pointer to a dynamically allocated byte array.
     */
    #define ushared8_ptr std::shared_ptr<uint8_t[]>

    /**
     * @brief Compile-time validation macro for protocol-derived types.
     *
     * @tparam T Type to validate.
     */
    #define ASSERT_PROTOCOL static_assert(std::is_base_of_v<ProtocolBaseObject, T>, "T must inherit from ProtocolBaseObject");
    
    /**
     * @brief Declares an inline constexpr function returning a 32-bit unsigned value.
     */
    #define icu32 inline constexpr uint32_t

    /**
     * @brief Declares an inline constexpr function returning a 16-bit unsigned value.
     */
    #define icu16 inline constexpr uint16_t

    /**
     * @brief Declares an inline constexpr function returning an 8-bit unsigned value.
     */
    #define icu8 inline constexpr uint8_t

    /**
     * @brief Specifies the io_direction of captured network traffic.
     *
     * @enum io_direction
     * @var io_direction::In
     *      Captures incoming frames only.
     * @var io_direction::Out
     *      Captures outgoing frames only. Outgoing frames are filtered by the
     *      receive loop.
     * @var io_direction::Both
     *      Captures both incoming and outgoing frames. This is the default.
     */
    enum class io_direction : uint8_t {
        In   = 0,   /// incoming frames only
        Out  = 1,   /// outgoing frames only (filtered in recv loop)
        Both = 2,   /// default, all frames
    };

    /**
     * @enum status
     * @brief Operation result codes.
     */
    enum class status : uint8_t {
        // ok
        Ok                ,    /// no error

        // socket errors
        SocketCreateFail  ,    /// socket(AF_PACKET) returned -1
        SocketBindFail    ,    /// bind() to interface failed
        SocketOptionFail  ,    /// setsockopt() failed (promisc, timeout, etc.)

        // interface errors
        IfaceNotFound     ,   /// could not resolve interface name to an index
        IfaceNotOpen      ,   /// send/recv called before open()
        IfaceAlreadyOpen  ,   /// open() called twice without close()

        // MAC / ARP resolution errors
        MacResolveFail   ,   /// MAC address retrieve failed
        ArpResolveFail   ,   /// ARP lookup failed, host not in cache

        // send errors
        SendFail         ,   /// sendto() returned -1
        SendTruncated    ,   /// sendto() sent fewer bytes than requested

        // recv errors
        RecvFail         ,   /// recvfrom() returned -1
        RecvTimeout,

        // buffer errors
        BufferTooSmall   ,   /// write would exceed Buffer::cap
        BufferAllocFail  ,   /// new uint8_t[] returned null

        // packet / dissection errors
        MalformedPacket  ,   /// raw bytes too short for declared header
        TruncatedPayload ,   /// payload length field exceeds buffer bounds

        // serialization errors
        MissingLayer     ,   /// required lower layer absent (e.g. no IPv4 when computing TCP pseudo-header)
        InvalidState     ,   /// layer state does not allow requested operation

        // generic
        InvalidView,
        InvalidArgument  ,   // null pointer, zero length, bad enum value
        NotImplemented   ,   // stub - feature not built in this version
        Unknown          ,   // catch-all, should never appear in practice
    };

    
    /**
     * @brief Human-readable MAC address string ("xx:xx:xx:xx:xx:xx").
     * @code
     *   auto s = utils::mac_str(raw_mac);
     *   printf("mac: %s@n", s.c_str());
     * @endcode
     */
    struct hr_mac {
        /**
         * @brief Constructs from an existing null-terminated string.
         * @param s Null-terminated source string, truncated if longer than 17 characters.
         */
        explicit hr_mac(const char* s) noexcept {
            size_t i = 0;
            for (; i < sizeof(buf_) - 1 && s[i]; ++i) buf_[i] = s[i];
            buf_[i] = '\0';
        }

        operator const char*() const noexcept { return buf_; }

        /** @brief Returns the formatted, null-terminated string. */
        [[nodiscard]] const char* c_str() const noexcept { return buf_; }

        private:
            char buf_[18];
    };

    /**
     * @brief Raw 6-byte MAC address.
     * @details Supports index access and equality comparison without a named field.
     * @code
     *   mn_mac m = utils::parse_mac("aa:bb:cc:dd:ee:ff");
     *   if (m == other) { }
     *   uint8_t first = m[0];
     * @endcode
     */
    struct mn_mac {
        /** @brief Constructs a zero-initialized address. */
        mn_mac() noexcept : bytes_{} {}

        /**
         * @brief Constructs from 6 raw bytes.
         * @param b Pointer to 6 source bytes.
         */
        explicit mn_mac(const uint8_t b[6]) noexcept {
            for (int i = 0; i < 6; ++i) bytes_[i] = b[i];
        }

        uint8_t  operator[](int i) const noexcept { return bytes_[i]; }
        uint8_t& operator[](int i)       noexcept { return bytes_[i]; }
        bool operator==(const mn_mac& o) const noexcept { return memcmp(bytes_, o.bytes_, 6) == 0; }
        bool operator!=(const mn_mac& o) const noexcept { return !(*this == o); }

        /** @brief Returns a pointer to the 6 underlying bytes, for APIs expecting uint8_t[6]. */
        [[nodiscard]] const uint8_t* data() const noexcept { return bytes_; }

        static mn_mac broadcast() noexcept {
            mn_mac mac;
            for (int i = 0; i < 6; ++i)
                mac.bytes_[i] = 0xFF;
            return mac;
        }

        static mn_mac zero() noexcept {
            return mn_mac();
        }
        
        static mn_mac solicit6(const uint8_t ip6[16]) noexcept {
            uint8_t mac[6] = { 0x33, 0x33, 0xFF, ip6[13], ip6[14], ip6[15] };
            return mn_mac(mac);
        }

        private:
            uint8_t bytes_[6];
    };

    /**
     * @brief Human-readable IPv4 address string ("ddd.ddd.ddd.ddd").
     * @details Implicitly converts to const char*.
     */
    struct hr_ipv4 {
        /**
         * @brief Constructs from an existing null-terminated string.
         * @param s Null-terminated source string, truncated if longer than 15 characters.
         */
        explicit hr_ipv4(const char* s) noexcept {
            size_t i = 0;
            for (; i < sizeof(buf_) - 1 && s[i]; ++i) buf_[i] = s[i];
            buf_[i] = '\0';
        }

        operator const char*() const noexcept { return buf_; }

        /** @brief Returns the formatted, null-terminated string. */
        [[nodiscard]] const char* c_str() const noexcept { return buf_; }

        private:
            char buf_[16];
    };

    /**
     * @brief Raw 4-byte IPv4 address.
     * @details Supports index access and equality comparison.
     * @code
     *   mn_ipv4 ip = utils::parse_ip("192.168.1.1");
     *   memcpy(hdr->dst_ip, ip.data(), 4);
     *   if (ip[3] == 255) { }    // check broadcast octet
     * @endcode
     */
    struct mn_ipv4 {
        /** @brief Constructs a zero-initialized address. */
        mn_ipv4() noexcept : bytes_{} {}

        /**
         * @brief Constructs from 4 raw bytes.
         * @param b Pointer to 4 source bytes.
         */
        explicit mn_ipv4(const uint8_t b[4]) noexcept {
            for (int i = 0; i < 4; ++i) bytes_[i] = b[i];
        }

        uint8_t  operator[](int i) const noexcept { return bytes_[i]; }
        uint8_t& operator[](int i)       noexcept { return bytes_[i]; }
        bool operator==(const mn_ipv4& o) const noexcept { return memcmp(bytes_, o.bytes_, 4) == 0; }
        bool operator!=(const mn_ipv4& o) const noexcept { return !(*this == o); }

        /** @brief Returns a pointer to the 4 underlying bytes, for APIs expecting uint8_t[4]. */
        [[nodiscard]] const uint8_t* data() const noexcept { return bytes_; }

        private:
            uint8_t bytes_[4];
    };

    /**
     * @brief Human-readable IPv6 address string (full uncompressed form).
     * @details Implicitly converts to const char*.
     */
    struct hr_ipv6 {
        /**
         * @brief Constructs from an existing null-terminated string.
         * @param s Null-terminated source string, truncated if longer than 39 characters.
         */
        explicit hr_ipv6(const char* s) noexcept {
            size_t i = 0;
            for (; i < sizeof(buf_) - 1 && s[i]; ++i) buf_[i] = s[i];
            buf_[i] = '\0';
        }

        operator const char*() const noexcept { return buf_; }

        /** @brief Returns the formatted, null-terminated string. */
        [[nodiscard]] const char* c_str() const noexcept { return buf_; }

        private:
            char buf_[40];
    };

    /**
     * @brief Raw 16-byte IPv6 address.
     * @details Supports index access and equality comparison.
     */
    struct mn_ipv6 {
        /** @brief Constructs a zero-initialized address. */
        mn_ipv6() noexcept : bytes_{} {}

        /**
         * @brief Constructs from 16 raw bytes.
         * @param b Pointer to 16 source bytes.
         */
        explicit mn_ipv6(const uint8_t b[16]) noexcept {
            for (int i = 0; i < 16; ++i) bytes_[i] = b[i];
        }

        uint8_t  operator[](int i) const noexcept { return bytes_[i]; }
        uint8_t& operator[](int i)       noexcept { return bytes_[i]; }
        bool operator==(const mn_ipv6& o) const noexcept { return memcmp(bytes_, o.bytes_, 16) == 0; }
        bool operator!=(const mn_ipv6& o) const noexcept { return !(*this == o); }

        /** @brief Returns a pointer to the 16 underlying bytes, for APIs expecting uint8_t[16]. */
        [[nodiscard]] const uint8_t* data() const noexcept { return bytes_; }

        private:
            uint8_t bytes_[16];
    };

    /**
     * @brief Identifies the link-layer frame encapsulation.
     *
     * @details The type describes the outer framing used to encapsulate the payload
     * at the link layer.
     */
    enum class frame_type : uint8_t {
        Unknown = 0,
        Eth,
        Dot1Q,
        PPPoE,
        PPP,
        QinQ,
    };
} // namespace lynx

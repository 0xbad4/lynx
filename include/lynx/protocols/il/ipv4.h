// RFC-791
#pragma once

#include "lynx/protocols/il/packet.h"


namespace lynx::proto
{
    icu16 IPV4_ETHERTYPE = 0x0800;  ///> Internet Protocol v4

    // sizes
    icu32 IPV4_HDR_LEN   =  20;    ///> base header, no options
    icu32 IPV4_MAX_LEN   = 65535;  ///> maximum total IP datagram

    // default values
    icu8  IPV4_VERSION   =  4;
    icu8  IPV4_TTL_DEF   = 64;     ///> sensible default TTL

    // predefined addresses
    icu32 IPV4_BROADCAST = 0xFFFFFFFF;  ///> 255.255.255.255
    icu32 IPV4_LOOPBACK  = 0x7F000001;  ///> 127.0.0.1
    icu32 IPV4_ANY       = 0x00000000;  ///> 0.0.0.0

    // flags masks
    icu8 IPV4_FLAG_DF   = 0x02;  ///> don't fragment
    icu8 IPV4_FLAG_MF   = 0x01;  ///> more fragments

    /**
     * @note IPv4 options are not supported in this implementation.
     */
    class IPv4 : public Packet {
        public:
            /**
             * @brief Constructs an IPv4 packet from a byte view.
             * @param v Byte view containing the IPv4 header and optional payload.
             */
            IPv4(const view& v) noexcept {
                dissect(v);
            }

            /**
             * @brief Constructs an IPv4 packet with specified fields.
             * @param src_val Source IPv4 address.
             * @param dst_val Destination IPv4 address.
             * @param proto_val Protocol number (6=TCP, 17=UDP, 1=ICMP), defaults to 0.
             * @param ttl_val Time to Live, defaults to IPV4_TTL_DEF (64).
             * @param id_val Identification for fragmentation, defaults to 0.
             * @param total_len_val Total length, defaults to 0.
             * @param dscp_val DSCP value, defaults to 0.
             * @param ecn_val ECN value, defaults to 0.
             * @param flags_val Flags value, defaults to 0.
             */
            IPv4(const mn_ipv4& src_val,
                 const mn_ipv4& dst_val,
                 uint8_t proto_val = 0,
                 uint8_t ttl_val = IPV4_TTL_DEF,
                 uint16_t id_val = 0,
                 uint16_t total_len_val = 0,
                 uint8_t dscp_val = 0,
                 uint8_t ecn_val = 0,
                 uint8_t flags_val = 0) noexcept {
                
                INIT_HDR
                
                if (!ok()) {
                    return;
                }

                version(IPV4_VERSION);
                ihl(5);
                src(src_val);
                dst(dst_val);
                proto(proto_val);
                ttl(ttl_val);
                identification(id_val);
                total_len(total_len_val);
                dscp(dscp_val);
                ecn(ecn_val);
                flags(flags_val);
                checksum(0);
            }

            /**
             * @brief Constructs an empty IPv4 packet with default values.
             */
            IPv4() noexcept {
                INIT_HDR
                
                if (!ok()) {
                    return;
                }

                // set attrs
                version(IPV4_VERSION);
                ihl(5);  // 20 bytes, no options
                ttl(IPV4_TTL_DEF);
                checksum(0);
            }

            /**
             * @brief Returns the IPv4 header length in bytes.
             * @return 20 bytes for standard IPv4 header (no options).
             */
            [[nodiscard]] uint32_t hsize() const noexcept {
                return IPV4_HDR_LEN;
            }

            /**
             * @brief Returns the EtherType for IPv4.
             * @return 0x0800 (IPv4 in Ethernet).
             */
            [[nodiscard]] uint16_t ethertype() const noexcept {
                return IPV4_ETHERTYPE;
            }

            [[nodiscard]] const uint8_t* adst() noexcept {
                return m_origin_view.slice(16, 20).data();
            }

            /**
             * @brief Sets the destination IPv4 address.
             * @param d IPv4 address to set.
             */
            void dst(const mn_ipv4& d) noexcept {
                utils::mem::copy(m_origin_view.begin() + 16, d.data(), 4);
            }

            /**
             * @brief Gets the destination IPv4 address.
             * @return The destination IPv4 address.
             */
            mn_ipv4 dst() noexcept {
                return mn_ipv4(m_origin_view.slice(16, 20).data());
            }

            /**
             * @brief Sets the source IPv4 address.
             * @param s IPv4 address to set.
             */
            void src(const mn_ipv4& s) noexcept {
                utils::mem::copy(m_origin_view.begin() + 12, s.data(), 4);
            }

            /**
             * @brief Gets the source IPv4 address.
             * @return The source IPv4 address.
             */
            mn_ipv4 src() noexcept {
                return mn_ipv4(m_origin_view.slice(12, 16).data());
            }

            /**
             * @brief Sets the version field (4 bits).
             * @param v Version to set (0-15).
             */
            void version(uint8_t v) noexcept {
                uint8_t byte = m_origin_view[0];
                byte = (byte & 0x0F) | ((v & 0x0F) << 4);
                utils::mem::copy(m_origin_view.begin(), &byte, 1);
            }

            /**
             * @brief Gets the version field (4 bits).
             * @return The version (should be 4).
             */
            uint8_t version() noexcept {
                uint8_t byte = m_origin_view[0];
                return (byte >> 4) & 0x0F;
            }

            /**
             * @brief Sets the IHL field (4 bits, header length in 32-bit words).
             * @param h IHL value to set (0-15).
             */
            void ihl(uint8_t h) noexcept {
                uint8_t byte = m_origin_view[0];
                byte = (byte & 0xF0) | (h & 0x0F);
                utils::mem::copy(m_origin_view.begin(), &byte, 1);
            }

            /**
             * @brief Gets the IHL field (4 bits, header length in 32-bit words).
             * @return The IHL value.
             */
            uint8_t ihl() noexcept {
                uint8_t byte = m_origin_view[0];
                return byte & 0x0F;
            }

            /**
             * @brief Sets the TTL (Time to Live) field.
             * @param t TTL value to set.
             */
            void ttl(uint8_t t) noexcept {
                utils::mem::copy(m_origin_view.begin() + 8, &t, 1);
            }

            /**
             * @brief Gets the TTL (Time to Live) field.
             * @return The TTL value.
             */
            uint8_t ttl() noexcept {
                return m_origin_view[8];
            }

            /**
             * @brief Sets the protocol field.
             * @param p Protocol number to set.
             */
            void proto(uint8_t p) noexcept {
                utils::mem::copy(m_origin_view.begin() + 9, &p, 1);
            }

            /**
             * @brief Gets the protocol field.
             * @return The protocol number (e.g., 6 for TCP, 17 for UDP, 1 for ICMP).
             */
            uint8_t proto() noexcept {
                return m_origin_view[9];
            }

            /**
             * @brief Sets the total length field.
             * @param len Total length in host byte order.
             */
            void total_len(uint16_t len) noexcept {
                uint16_t net_len = utils::mem::bswap<uint16_t>(len);
                utils::mem::copy(m_origin_view.begin() + 2, &net_len, 2);
            }

            /**
             * @brief Gets the total length field.
             * @return The total length in host byte order.
             */
            uint16_t total_len() noexcept {
                uint16_t len = 0;
                utils::mem::copy(&len, m_origin_view.begin() + 2, 2);
                return utils::mem::bswap<uint16_t>(len);
            }

            /**
             * @brief Sets the identification field (fragmentation).
             * @param id Identification in host byte order.
             */
            void identification(uint16_t id) noexcept {
                uint16_t net_id = utils::mem::bswap<uint16_t>(id);
                utils::mem::copy(m_origin_view.begin() + 4, &net_id, 2);
            }

            /**
             * @brief Gets the identification field (fragmentation).
             * @return The identification in host byte order.
             */
            uint16_t identification() noexcept {
                uint16_t id = 0;
                utils::mem::copy(&id, m_origin_view.begin() + 4, 2);
                return utils::mem::bswap<uint16_t>(id);
            }

            /**
             * @brief Sets the checksum field.
             * @param cs Checksum in host byte order.
             */
            void checksum(uint16_t cs) noexcept {
                uint16_t net_cs = utils::mem::bswap<uint16_t>(cs);
                utils::mem::copy(m_origin_view.begin() + 10, &net_cs, 2);
            }

            /**
             * @brief Gets the checksum field.
             * @return The checksum in host byte order.
             */
            uint16_t checksum() noexcept {
                uint16_t cs = 0;
                utils::mem::copy(&cs, m_origin_view.begin() + 10, 2);
                return utils::mem::bswap<uint16_t>(cs);
            }

            /**
             * @brief Sets the DSCP field (6 bits, Differentiated Services Code Point).
             * @param d DSCP value to set (0-63).
             */
            void dscp(uint8_t d) noexcept {
                uint8_t byte = m_origin_view[1];
                byte = (byte & 0x03) | ((d & 0x3F) << 2);
                utils::mem::copy(m_origin_view.begin() + 1, &byte, 1);
            }

            /**
             * @brief Gets the DSCP field (6 bits, Differentiated Services Code Point).
             * @return The DSCP value.
             */
            uint8_t dscp() noexcept {
                uint8_t byte = m_origin_view[1];
                return (byte >> 2) & 0x3F;
            }

            /**
             * @brief Sets the ECN field (2 bits, Explicit Congestion Notification).
             * @param e ECN value to set (0-3).
             */
            void ecn(uint8_t e) noexcept {
                uint8_t byte = m_origin_view[1];
                byte = (byte & 0xFC) | (e & 0x03);
                utils::mem::copy(m_origin_view.begin() + 1, &byte, 1);
            }

            /**
             * @brief Gets the ECN field (2 bits, Explicit Congestion Notification).
             * @return The ECN value.
             */
            uint8_t ecn() noexcept {
                uint8_t byte = m_origin_view[1];
                return byte & 0x03;
            }

            /**
             * @brief Sets the Flags field (3 bits).
             * @param f Flags value to set (0-7).
             */
            void flags(uint8_t f) noexcept {
                uint16_t word = 0;
                utils::mem::copy(&word, m_origin_view.begin() + 6, 2);
                word = utils::mem::bswap<uint16_t>(word);
                word = (word & 0x1FFF) | ((f & 0x07) << 13);
                word = utils::mem::bswap<uint16_t>(word);
                utils::mem::copy(m_origin_view.begin() + 6, &word, 2);
            }

            /**
             * @brief Gets the Flags field (3 bits).
             * @return The Flags value (bit 2=DF, bit 1=MF, bit 0=reserved).
             */
            uint8_t flags() noexcept {
                uint16_t word = 0;
                utils::mem::copy(&word, m_origin_view.begin() + 6, 2);
                word = utils::mem::bswap<uint16_t>(word);
                return (word >> 13) & 0x07;
            }

            /**
             * @brief Sets the Fragment Offset field (13 bits).
             * @param o Fragment offset value to set.
             */
            void offs(uint16_t o) noexcept {
                uint16_t word = 0;
                utils::mem::copy(&word, m_origin_view.begin() + 6, 2);
                word = utils::mem::bswap<uint16_t>(word);
                word = (word & 0xE000) | (o & 0x1FFF);
                word = utils::mem::bswap<uint16_t>(word);
                utils::mem::copy(m_origin_view.begin() + 6, &word, 2);
            }

            /**
             * @brief Gets the Fragment Offset field (13 bits).
             * @return The fragment offset value.
             */
            uint16_t offs() noexcept {
                uint16_t word = 0;
                utils::mem::copy(&word, m_origin_view.begin() + 6, 2);
                word = utils::mem::bswap<uint16_t>(word);
                return word & 0x1FFF;
            }

        protected:
            /**
             * @brief Patches the checksum field after serialization.
             * @param buffer The buffer containing the serialized packet.
             * @param hoff The header offset within the buffer.
             */
            void patch(Buffer& buffer, uint32_t hoff) const noexcept {
                // compute IPv4 header checksum over the first 20 bytes starting at hoff
                if (hoff + IPV4_HDR_LEN <= buffer.cap()) {
                    // zero checksum
                    utils::mem::zero(buffer.begin() + hoff + 10, 2);

                    // calc
                    uint16_t computed = utils::checksum::inet(buffer.begin() + hoff, IPV4_HDR_LEN);

                    // patch
                    buffer.patch(hoff + 10, reinterpret_cast<uint8_t*>(computed), 2);
                }
            }
    };
} // namespace lynx::proto


// RFC-8200
#pragma once

#include "lynx/protocols/il/packet.h"
#include "lynx/core/utils.h"


namespace lynx::proto
{
    icu16 IPV6_ETHERTYPE = 0x86DD;  ///> Internet Protocol v6

    icu32 IPV6_HDR_LEN      = 40;   ///> Fixed header only
    icu8  IPV6_VERSION      =  6;
    icu8  IPV6_HOP_DEF      = 64;   ///> Sensible default hop limit
    icu8  IPV6_PROTO_NONXT  = 59;   ///> No Next Header

    class IPv6 : public Packet {
        public:
            /**
             * @brief Constructs an IPv6 packet from a byte view.
             * @param v Byte view containing the IPv6 header and optional payload.
             */
            IPv6(const view& v) noexcept {
                dissect(v);
            }

            /**
             * @brief Constructs an IPv6 packet with specified fields.
             * @param src_val Source IPv6 address.
             * @param dst_val Destination IPv6 address.
             * @param next_hdr_val Next header type (6=TCP, 17=UDP, 1=ICMP), defaults to 0.
             * @param hop_limit_val Hop limit, defaults to IPV6_HOP_DEF (64).
             * @param payload_len_val Payload length, defaults to 0.
             * @param traffic_class_val Traffic class value, defaults to 0.
             * @param flow_label_val Flow label value, defaults to 0.
             */
            IPv6(const mn_ipv6& src_val,
                 const mn_ipv6& dst_val,
                 uint8_t next_hdr_val = 0,
                 uint8_t hop_limit_val = IPV6_HOP_DEF,
                 uint16_t payload_len_val = 0,
                 uint8_t traffic_class_val = 0,
                 uint32_t flow_label_val = 0) noexcept {
                
                INIT_HDR
                
                if (!ok()) {
                    return;
                }

                version(IPV6_VERSION);
                src(src_val);
                dst(dst_val);
                next_hdr(next_hdr_val);
                hop_limit(hop_limit_val);
                payload_len(payload_len_val);
                traffic_class(traffic_class_val);
                flow_label(flow_label_val);
            }

            /**
             * @brief Constructs an empty IPv6 packet with default values.
             */
            IPv6() noexcept {
                INIT_HDR
                
                if (!ok()) {
                    return;
                }

                // Initialize with defaults
                version(IPV6_VERSION);
                hop_limit(IPV6_HOP_DEF);
            }

            /**
             * @brief Returns the IPv6 header length in bytes.
             * @return 40 bytes for standard IPv6 header.
             */
            [[nodiscard]] uint32_t hsize() const noexcept {
                return IPV6_HDR_LEN;
            }

            /**
             * @brief Returns the EtherType for IPv6.
             * @return 0x86DD (IPv6 in Ethernet).
             */
            [[nodiscard]] uint16_t ethertype() const noexcept {
                return IPV6_ETHERTYPE;
            }

            [[nodiscard]] const uint8_t* adst() noexcept {
                return m_origin_view.slice(24, 40).data();
            }

            /**
             * @brief Sets the destination IPv6 address.
             * @param d IPv6 address to set.
             */
            void dst(const mn_ipv6& d) noexcept {
                utils::mem::copy(m_origin_view.begin() + 24, d.data(), 16);
            }

            /**
             * @brief Gets the destination IPv6 address.
             * @return The destination IPv6 address.
             */
            mn_ipv6 dst() noexcept {
                return mn_ipv6(m_origin_view.slice(24, 40).data());
            }

            /**
             * @brief Sets the source IPv6 address.
             * @param s IPv6 address to set.
             */
            void src(const mn_ipv6& s) noexcept {
                utils::mem::copy(m_origin_view.begin() + 8, s.data(), 16);
            }

            /**
             * @brief Gets the source IPv6 address.
             * @return The source IPv6 address.
             */
            mn_ipv6 src() noexcept {
                return mn_ipv6(m_origin_view.slice(8, 24).data());
            }

            /**
             * @brief Sets the version field (4 bits).
             * @param v Version to set (0-15).
             */
            void version(uint8_t v) noexcept {
                uint32_t dword = 0;
                utils::mem::copy(&dword, m_origin_view.begin(), 4);
                dword = utils::mem::bswap<uint32_t>(dword);
                dword = (dword & 0x0FFFFFFF) | ((v & 0x0F) << 28);
                dword = utils::mem::bswap<uint32_t>(dword);
                utils::mem::copy(m_origin_view.begin(), &dword, 4);
            }

            /**
             * @brief Gets the version field (4 bits).
             * @return The version (should be 6).
             */
            uint8_t version() noexcept {
                uint32_t dword = 0;
                utils::mem::copy(&dword, m_origin_view.begin(), 4);
                dword = utils::mem::bswap<uint32_t>(dword);
                return (dword >> 28) & 0x0F;
            }

            /**
             * @brief Sets the Traffic Class field (8 bits).
             * @param tc Traffic class value to set.
             */
            void traffic_class(uint8_t tc) noexcept {
                uint32_t dword = 0;
                utils::mem::copy(&dword, m_origin_view.begin(), 4);
                dword = utils::mem::bswap<uint32_t>(dword);
                dword = (dword & 0xF00FFFFF) | ((tc & 0xFF) << 20);
                dword = utils::mem::bswap<uint32_t>(dword);
                utils::mem::copy(m_origin_view.begin(), &dword, 4);
            }

            /**
             * @brief Gets the Traffic Class field (8 bits).
             * @return The traffic class value.
             */
            uint8_t traffic_class() noexcept {
                uint32_t dword = 0;
                utils::mem::copy(&dword, m_origin_view.begin(), 4);
                dword = utils::mem::bswap<uint32_t>(dword);
                return (dword >> 20) & 0xFF;
            }

            /**
             * @brief Sets the Flow Label field (20 bits).
             * @param fl Flow label value to set.
             */
            void flow_label(uint32_t fl) noexcept {
                uint32_t dword = 0;
                utils::mem::copy(&dword, m_origin_view.begin(), 4);
                dword = utils::mem::bswap<uint32_t>(dword);
                dword = (dword & 0xFFF00000) | (fl & 0x000FFFFF);
                dword = utils::mem::bswap<uint32_t>(dword);
                utils::mem::copy(m_origin_view.begin(), &dword, 4);
            }

            /**
             * @brief Gets the Flow Label field (20 bits).
             * @return The flow label value (0-1048575).
             */
            uint32_t flow_label() noexcept {
                uint32_t dword = 0;
                utils::mem::copy(&dword, m_origin_view.begin(), 4);
                dword = utils::mem::bswap<uint32_t>(dword);
                return dword & 0x000FFFFF;
            }

            /**
             * @brief Sets the Payload Length field (16 bits).
             * @param len Payload length in host byte order.
             */
            void payload_len(uint16_t len) noexcept {
                uint16_t net_len = utils::mem::bswap<uint16_t>(len);
                utils::mem::copy(m_origin_view.begin() + 4, &net_len, 2);
            }

            /**
             * @brief Gets the Payload Length field (16 bits).
             * @return The payload length in host byte order.
             */
            uint16_t payload_len() noexcept {
                uint16_t len = 0;
                utils::mem::copy(&len, m_origin_view.begin() + 4, 2);
                return utils::mem::bswap<uint16_t>(len);
            }

            /**
             * @brief Sets the Next Header field (8 bits).
             * @param nh Next header type to set.
             */
            void next_hdr(uint8_t nh) noexcept {
                utils::mem::copy(m_origin_view.begin() + 6, &nh, 1);
            }

            /**
             * @brief Gets the Next Header field (8 bits).
             * @return The next header type.
             */
            uint8_t next_hdr() noexcept {
                return m_origin_view[6];
            }

            /**
             * @brief Sets the Hop Limit field (8 bits).
             * @param h Hop limit value to set.
             */
            void hop_limit(uint8_t h) noexcept {
                utils::mem::copy(m_origin_view.begin() + 7, &h, 1);
            }

            /**
             * @brief Gets the Hop Limit field (8 bits).
             * @return The hop limit value.
             */
            uint8_t hop_limit() noexcept {
                return m_origin_view[7];
            }
    };
} // namespace lynx::proto


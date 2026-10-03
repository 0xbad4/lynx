// RFC-1112
#pragma once

#include "lynx/protocols/tl/segment.h"

namespace lynx::proto {
    /**
     * @brief IPv4 protocol number used by IGMP packets.
     */
    icu8 IGMP_IP_PROTO = 2;

    /**
     * @brief Fixed length of an IGMP header in bytes.
     */
    icu32 IGMP_HDR_LEN = 8;

    // Type values
    icu8 IGMP_QUERY     = 0x11;
    icu8 IGMP_V2_REPORT = 0x16;
    icu8 IGMP_V2_LEAVE  = 0x17;
    icu8 IGMP_V3_REPORT = 0x22;

    /**
     * @brief IGMP message header for IPv4 multicast membership management.
     */
    class IGMP : public Segment {
        public:
            /**
             * @brief Constructs an IGMP header from an existing byte view.
             * @param v Bytes containing the IGMP header and optional payload.
             */
            IGMP(const view& v) noexcept {
                dissect(v);
            }

            /**
             * @brief Constructs an empty IGMP header ready for crafting.
             */
            IGMP() noexcept {
                INIT_HDR

                if (!ok()) {
                    return;
                }

                type(IGMP_QUERY);
                max_resp(0);
                checksum(0);
                gaddr(0);
            }

            /**
             * @brief Constructs a crafted IGMP message with explicit fields.
             * @param type_ IGMP message type.
             * @param max_resp_ Maximum response time value.
             * @param group_addr Group address to encode in the header.
             */
            IGMP(const uint8_t &type_, uint8_t max_resp_ = 0, uint32_t group_addr = 0) noexcept {
                INIT_HDR
                
                if (!ok()) {
                    return;
                }

                type(type_);
                max_resp(max_resp_);
                checksum(0);
                gaddr(view(reinterpret_cast<uint8_t*>(&group_addr), 4));
            }

            /**
             * @brief Returns the IGMP header size.
             * @return 8 bytes.
             */
            [[nodiscard]] uint32_t hsize() const noexcept override {
                return IGMP_HDR_LEN;
            }

            /**
             * @brief Returns the IPv4 protocol number for IGMP.
             * @return 2 (IPPROTO_IGMP).
             */
            [[nodiscard]] uint8_t proto() const noexcept override {
                return IGMP_IP_PROTO;
            }

            /**
             * @brief Sets the IGMP message type field.
             * @param t New type value.
             */
            void type(uint8_t t) noexcept {
                m_origin_view[0] = t;
            }

            /**
             * @brief Returns the IGMP message type field.
             * @return Current IGMP type.
             */
            uint8_t type() noexcept {
                return m_origin_view[0];
            }

            /**
             * @brief Sets the IGMP maximum response time field.
             * @param r New response time value.
             */
            void max_resp(uint8_t r) noexcept {
                m_origin_view[1] = r;
            }

            /**
             * @brief Returns the IGMP maximum response time field.
             * @return Current response time value.
             */
            uint8_t max_resp() noexcept {
                return m_origin_view[1];
            }

            /**
             * @brief Sets the IGMP checksum field.
             * @param cs New checksum value in host byte order.
             */
            void checksum(uint16_t cs) noexcept {
                uint16_t net_cs = utils::mem::bswap<uint16_t>(cs);
                utils::mem::copy(m_origin_view.begin() + 2, &net_cs, 2);
            }

            /**
             * @brief Returns the IGMP checksum field.
             * @return Current checksum in host byte order.
             */
            uint16_t checksum() noexcept {
                uint16_t cs = 0;
                utils::mem::copy(&cs, m_origin_view.begin() + 2, 2);
                return utils::mem::bswap<uint16_t>(cs);
            }

            /**
             * @brief Sets the group-address field.
             * @param g New address view.
             */
            void gaddr(view g) noexcept {
                if (g.valid() && g.size() >= 4) {
                    utils::mem::copy(m_origin_view.begin() + 4, g.data(), 4);
                }
            }

            /**
             * @brief Returns the group-address field.
             * @return Current group-address view.
             */
            view gaddr() noexcept {
                return m_origin_view.last(4);
            }

        protected:
            /**
             * @brief Patches the serialized IGMP checksum in a packet buffer.
             *
             * The checksum covers the IGMP header and any payload bytes that follow,
             * with the checksum field cleared before computing the standard RFC 1071
             * one's-complement sum.
             *
             * @param buffer Packet buffer containing the serialized packet.
             * @param hoff Byte offset where this header begins inside @p buffer.
             */
            void patch(Buffer &buffer, uint32_t hoff) const noexcept {
                if (buffer.len() <= hoff) {
                    return;
                }

                uint32_t total = buffer.len() - hoff;
                if (total < hsize()) {
                    return;
                }

                uint8_t* start = buffer.begin() + hoff;
                uint8_t zero[2] = {0, 0};
                buffer.patch(hoff + 2, zero, 2);

                uint16_t sum = utils::checksum::inet(view(start, total));
                uint16_t net_sum = utils::mem::bswap<uint16_t>(sum);
                buffer.patch(hoff + 2, reinterpret_cast<const uint8_t*>(&net_sum), 2);
            }
    };
}
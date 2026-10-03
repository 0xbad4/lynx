// RFC-792
#pragma once

#include "lynx/protocols/tl/segment.h"

namespace lynx::proto {
    /**
     * @brief IPv4 protocol number used by ICMP packets.
     */
    icu8 ICMP_IP_PROTO = 1;

    /**
     * @brief Fixed length of an ICMP header in bytes.
     */
    icu32 ICMP_HDR_LEN = 8;

    // Codes/Types
    icu8 ICMP_ECHO_REPLY   =  0;
    icu8 ICMP_DST_UNREACH  =  3;
    icu8 ICMP_REDIRECT     =  5;
    icu8 ICMP_ECHO_REQUEST =  8;
    icu8 ICMP_TIME_EXCEED  = 11;

    icu8 ICMP_UNREACH_NET      = 0;
    icu8 ICMP_UNREACH_HOST     = 1;
    icu8 ICMP_UNREACH_PROTO    = 2;
    icu8 ICMP_UNREACH_PORT     = 3;
    icu8 ICMP_UNREACH_NEEDFRAG = 4;

    icu8 ICMP_TIMEX_TTL  = 0;
    icu8 ICMP_TIMEX_FRAG = 1;

    /**
     * @brief ICMP message header for IPv4 transport.
     */
    class ICMP : public Segment {
        public:
            /**
             * @brief Constructs an ICMP header from an existing byte view.
             * @param v Bytes containing the ICMP header and optional payload.
             */
            ICMP(const view& v) noexcept {
                dissect(v);
            }

            /**
             * @brief Constructs an empty ICMP header ready for crafting.
             */
            ICMP() noexcept {
                INIT_HDR

                if (!ok()) {
                    return;
                }

                type(ICMP_ECHO_REPLY);
                code(0);
                checksum(0);
                rest(0);
            }

            /**
             * @brief Constructs a crafted ICMP message with common echo-style fields.
             * @param type_ ICMP type.
             * @param code_ ICMP code.
             * @param id_ Identifier value stored in the high 16 bits of the rest field.
             * @param seq_ Sequence value stored in the low 16 bits of the rest field.
             */
            ICMP(const uint8_t &type_, const uint8_t &code_, uint16_t id_ = 0, uint16_t seq_ = 0) noexcept {
                INIT_HDR
                
                if (!ok()) {
                    return;
                }

                type(type_);
                code(code_);
                checksum(0);
                rest(static_cast<uint32_t>(id_) << 16 | static_cast<uint32_t>(seq_));
            }

            /**
             * @brief Returns the ICMP header size.
             * @return 8 bytes.
             */
            [[nodiscard]] uint32_t hsize() const noexcept override {
                return ICMP_HDR_LEN;
            }

            /**
             * @brief Returns the IPv4 protocol number for ICMP.
             * @return 1 (IPPROTO_ICMP).
             */
            [[nodiscard]] uint8_t proto() const noexcept override {
                return ICMP_IP_PROTO;
            }

            /**
             * @brief Sets the ICMP type field.
             * @param t New type value.
             */
            void type(uint8_t t) noexcept {
                m_origin_view[0] = t;
            }

            /**
             * @brief Returns the ICMP type field.
             * @return Current ICMP type.
             */
            uint8_t type() noexcept {
                return m_origin_view[0];
            }

            /**
             * @brief Sets the ICMP code field.
             * @param c New code value.
             */
            void code(uint8_t c) noexcept {
                m_origin_view[1] = c;
            }

            /**
             * @brief Returns the ICMP code field.
             * @return Current ICMP code.
             */
            uint8_t code() noexcept {
                return m_origin_view[1];
            }

            /**
             * @brief Sets the ICMP checksum field.
             * @param cs New checksum value in host byte order.
             */
            void checksum(uint16_t cs) noexcept {
                uint16_t net_cs = utils::mem::bswap<uint16_t>(cs);
                utils::mem::copy(m_origin_view.begin() + 2, &net_cs, 2);
            }

            /**
             * @brief Returns the ICMP checksum field.
             * @return Current checksum in host byte order.
             */
            uint16_t checksum() noexcept {
                uint16_t cs = 0;
                utils::mem::copy(&cs, m_origin_view.begin() + 2, 2);
                return utils::mem::bswap<uint16_t>(cs);
            }

            /**
             * @brief Sets the 32-bit trailing field of the ICMP header.
             * @param r New value in host byte order.
             */
            void rest(uint32_t r) noexcept {
                uint32_t net_r = utils::mem::bswap<uint32_t>(r);
                utils::mem::copy(m_origin_view.begin() + 4, &net_r, 4);
            }

            /**
             * @brief Returns the 32-bit trailing field of the ICMP header.
             * @return Current 32-bit value in host byte order.
             */
            uint32_t rest() noexcept {
                uint32_t r = 0;
                utils::mem::copy(&r, m_origin_view.begin() + 4, 4);
                return utils::mem::bswap<uint32_t>(r);
            }

            /**
             * @brief Sets the high 16 bits of the ICMP rest field.
             * @param i Identifier value.
             */
            void id(uint16_t i) noexcept {
                uint32_t r = rest();
                r &= 0x0000FFFFu;
                r |= (static_cast<uint32_t>(i) << 16);
                rest(r);
            }

            /**
             * @brief Returns the high 16 bits of the ICMP rest field.
             * @return Identifier value in host byte order.
             */
            uint16_t id() noexcept {
                uint32_t r = rest();
                return static_cast<uint16_t>(r >> 16);
            }

            /**
             * @brief Sets the low 16 bits of the ICMP rest field.
             * @param s Sequence number.
             */
            void seq(uint16_t s) noexcept {
                uint32_t r = rest();
                r &= 0xFFFF0000u;
                r |= static_cast<uint32_t>(s);
                rest(r);
            }

            /**
             * @brief Returns the low 16 bits of the ICMP rest field.
             * @return Sequence value in host byte order.
             */
            uint16_t seq() noexcept {
                uint32_t r = rest();
                return static_cast<uint16_t>(r & 0x0000FFFFu);
            }

        protected:
            /**
             * @brief Patches the serialized ICMP checksum in a packet buffer.
             *
             * The checksum covers the ICMP header and any payload bytes following it,
             * with the checksum field temporarily zeroed before computing the RFC 1071
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
                
                // zero checksum
                utils::mem::zero(buffer.begin() + hoff + 2, 2);
                uint16_t sum = utils::checksum::inet(view(start, total));
                uint16_t net_sum = utils::mem::bswap<uint16_t>(sum);
                buffer.patch(hoff + 2, reinterpret_cast<const uint8_t*>(&net_sum), 2);
            }
    };
}
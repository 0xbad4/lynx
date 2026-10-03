// RFC-4443
#pragma once

#include "lynx/protocols/il/ipv6.h"
#include "lynx/protocols/tl/icmp.h"

namespace lynx::proto {
    /**
     * @brief IPv6 protocol number used by ICMPv6 packets.
     */
    icu8 ICMPV6_IP_PROTO = 58;

    /**
     * @brief Fixed length of an ICMPv6 header in bytes.
     */
    icu32 ICMPV6_HDR_LEN = 8;

    /**
     * @brief ICMPv6 message header for IPv6 transport.
     *
     * ICMPv6 uses the same basic 8-byte header as ICMPv4, but its checksum is
     * computed over an IPv6 pseudo-header followed by the message bytes.
     */
    class ICMPv6 : public ICMP {
        public:
            /**
             * @brief Constructs an ICMPv6 header from an existing byte view.
             * @param v Bytes containing the ICMPv6 header and optional payload.
             */
            ICMPv6(const view& v) noexcept : ICMP(v) {}

            /**
             * @brief Constructs an empty ICMPv6 header ready for crafting.
             */
            ICMPv6() noexcept {
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
             * @brief Constructs a crafted ICMPv6 message with common echo-style fields.
             * @param type_ ICMPv6 type.
             * @param code_ ICMPv6 code.
             * @param id_ Identifier value stored in the high 16 bits of the rest field.
             * @param seq_ Sequence value stored in the low 16 bits of the rest field.
             */
            ICMPv6(const uint8_t &type_, const uint8_t &code_, uint16_t id_ = 0, uint16_t seq_ = 0) noexcept {
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
             * @brief Returns the ICMPv6 header size.
             * @return 8 bytes.
             */
            [[nodiscard]] uint32_t hsize() const noexcept {
                return ICMPV6_HDR_LEN;
            }

            /**
             * @brief Returns the IPv6 protocol number for ICMPv6.
             * @return 58 (IPPROTO_ICMPV6).
             */
            [[nodiscard]] uint8_t proto() const noexcept {
                return ICMPV6_IP_PROTO;
            }

        protected:
            /**
             * @brief Patches the serialized ICMPv6 checksum using the IPv6 pseudo-header.
             *
             * The checksum covers the IPv6 source+destination addresses, the payload
             * length, the next-header field (58), followed by the ICMPv6 header and
             * payload bytes. The checksum field is zeroed before the computation.
             *
             * @param buffer Packet buffer containing the serialized packet.
             * @param hoff Byte offset where this header begins inside @p buffer.
             * 
             * @note Falls back to the standard ICMP checksum routine if the IPv6
             *       pseudo-header or underlayer IPv6 address data is unavailable.
             */
            void patch(Buffer& buffer, uint32_t hoff) const noexcept {
                 if (buffer.len() <= hoff) {
                    return;
                }   

                auto* ip6 = dynamic_cast<IPv6*>(m_underlayer_ptr);

                // fallback to ICMP's standard
                if (!ip6) {
                    ICMP::patch(buffer, hoff);
                    return;
                }

                // total includes upperlayer/load size
                uint32_t total = buffer.len() - hoff;

                if (total < hsize()) {
                    return;
                }

                const mn_ipv6 src = ip6->src();
                const mn_ipv6 dst = ip6->dst();

                Buffer pseudo = Buffer::alloc(40 + total);

                if (!pseudo.valid()) {
                    return;
                }

                // zero checksum field before summing
                utils::mem::zero(buffer.at(hoff + 2), 2);

                (void)pseudo.reserve(40 + total);
                uint8_t* p = pseudo.begin();

                utils::mem::copy(p, src.data(), 16);
                utils::mem::copy(p + 16, dst.data(), 16);

                p[32] = static_cast<uint8_t>((total >> 24) & 0xFFu);
                p[33] = static_cast<uint8_t>((total >> 16) & 0xFFu);
                p[34] = static_cast<uint8_t>((total >> 8) & 0xFFu);
                p[35] = static_cast<uint8_t>(total & 0xFFu);
                p[39] = static_cast<uint8_t>(ICMPV6_IP_PROTO);

                utils::mem::copy(p + 40, buffer.begin() + hoff, total);

                uint16_t sum = utils::checksum::inet(view(pseudo.begin(), pseudo.len()));
                uint16_t net_sum = utils::mem::bswap<uint16_t>(sum);
                buffer.patch(hoff + 2, reinterpret_cast<const uint8_t*>(&net_sum), 2);
            }
    };
}
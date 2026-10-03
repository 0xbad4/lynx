// RFC-768
#pragma once

#include "lynx/protocols/tl/segment.h"
#include "lynx/protocols/il/ipv4.h"
#include "lynx/protocols/il/ipv6.h"

namespace lynx::proto {
    /**
     * @brief IPv4 protocol number used by UDP.
     */
    icu8 UDP_IP_PROTO = 17;

    /**
     * @brief Fixed length of a UDP header in bytes.
     */
    icu32 UDP_HDR_LEN = 8;

    /**
     * @brief UDP datagram header for connectionless transport.
     */
    class UDP : public Segment {
        public:
            /**
             * @brief Constructs a UDP header from an existing byte view.
             * @param v Bytes containing the UDP header and optional payload.
             */
            UDP(const view& v) noexcept {
                dissect(v);
            }

            /**
             * @brief Constructs an empty UDP header ready for crafting.
             */
            UDP() noexcept {
                INIT_HDR

                if (!ok()) {
                    return;
                }

                sport(0);
                dport(0);
                length(0);
                checksum(0);
            }

            /**
             * @brief Constructs a crafted UDP datagram with explicit fields.
             * @param sport_ Source port.
             * @param dport_ Destination port.
             * @param len_ Datagram length (header + payload).
             */
            UDP(uint16_t sport_, uint16_t dport_, uint16_t len_ = 0) noexcept {
                INIT_HDR
                
                if (!ok()) {
                    return;
                }

                sport(sport_);
                dport(dport_);
                length(len_);
                checksum(0);
            }

            /**
             * @brief Returns the UDP header size in bytes.
             * @return 8 bytes.
             */
            [[nodiscard]] uint32_t hsize() const noexcept override {
                return UDP_HDR_LEN;
            }

            /**
             * @brief Returns the IPv4 protocol number for UDP.
             * @return 17 (IPPROTO_UDP).
             */
            [[nodiscard]] uint8_t proto() const noexcept override {
                return UDP_IP_PROTO;
            }

            /**
             * @brief Sets the source port field.
             * @param p Port value in host byte order.
             */
            void sport(uint16_t p) noexcept {
                uint16_t net_p = utils::mem::bswap<uint16_t>(p);
                utils::mem::copy(m_origin_view.begin(), &net_p, 2);
            }

            /**
             * @brief Returns the source port field.
             * @return Current source port in host byte order.
             */
            uint16_t sport() noexcept {
                uint16_t p = 0;
                utils::mem::copy(&p, m_origin_view.begin(), 2);
                return utils::mem::bswap<uint16_t>(p);
            }

            /**
             * @brief Sets the destination port field.
             * @param p Port value in host byte order.
             */
            void dport(uint16_t p) noexcept {
                uint16_t net_p = utils::mem::bswap<uint16_t>(p);
                utils::mem::copy(m_origin_view.begin() + 2, &net_p, 2);
            }

            /**
             * @brief Returns the destination port field.
             * @return Current destination port in host byte order.
             */
            uint16_t dport() noexcept {
                uint16_t p = 0;
                utils::mem::copy(&p, m_origin_view.begin() + 2, 2);
                return utils::mem::bswap<uint16_t>(p);
            }

            /**
             * @brief Sets the length field (header + payload).
             * @param len Length in host byte order.
             */
            void length(uint16_t len) noexcept {
                uint16_t net_len = utils::mem::bswap<uint16_t>(len);
                utils::mem::copy(m_origin_view.begin() + 4, &net_len, 2);
            }

            /**
             * @brief Returns the length field (header + payload).
             * @return Current length in host byte order.
             */
            uint16_t length() noexcept {
                uint16_t len = 0;
                utils::mem::copy(&len, m_origin_view.begin() + 4, 2);
                return utils::mem::bswap<uint16_t>(len);
            }

            /**
             * @brief Sets the checksum field.
             * @param cs Checksum in host byte order.
             */
            void checksum(uint16_t cs) noexcept {
                uint16_t net_cs = utils::mem::bswap<uint16_t>(cs);
                utils::mem::copy(m_origin_view.begin() + 6, &net_cs, 2);
            }

            /**
             * @brief Returns the checksum field.
             * @return Current checksum in host byte order.
             */
            uint16_t checksum() noexcept {
                uint16_t cs = 0;
                utils::mem::copy(&cs, m_origin_view.begin() + 6, 2);
                return utils::mem::bswap<uint16_t>(cs);
            }

        protected:
            /**
             * @brief Patches the serialized UDP checksum using IPv4 or IPv6 pseudo-header.
             *
             * The checksum covers a pseudo-header (IP addresses + protocol + length)
             * followed by the UDP header and payload. The checksum field is zeroed
             * before computation. In IPv6, a zero checksum is converted to 0xFFFF.
             *
             * @param buffer Packet buffer containing the serialized packet.
             * @param hoff Byte offset where this header begins inside @p buffer.
             */
            void patch(Buffer &buffer, uint32_t hoff) const noexcept {
                if (buffer.len() <= hoff) {
                    return;
                }

                auto* ip = dynamic_cast<Packet*>(m_underlayer_ptr);
                if (!ip) {
                    return;
                }

                uint32_t total = buffer.len() - hoff;
                if (total < UDP_HDR_LEN) {
                    return;
                }

                utils::mem::zero(buffer.at(hoff + 6), 2);

                auto* ipv4 = dynamic_cast<IPv4*>(ip);
                auto* ipv6 = dynamic_cast<IPv6*>(ip);

                uint32_t pseudo_len = 0;
                Buffer pseudo;

                if (ipv4) {
                    pseudo_len = 12 + total;
                    pseudo = Buffer::alloc(pseudo_len);
                    if (!pseudo.valid()) {
                        return;
                    }

                    uint8_t* p = pseudo.reserve(pseudo_len);
                    if (!p) {
                        return;
                    }

                    const mn_ipv4 src = ipv4->src();
                    const mn_ipv4 dst = ipv4->dst();

                    utils::mem::copy(p, src.data(), 4);
                    utils::mem::copy(p + 4, dst.data(), 4);
                    p[8] = 0;
                    p[9] = UDP_IP_PROTO;
                    p[10] = static_cast<uint8_t>((total >> 8) & 0xFFu);
                    p[11] = static_cast<uint8_t>(total & 0xFFu);

                    utils::mem::copy(p + 12, buffer.begin() + hoff, total);

                    uint16_t sum = utils::checksum::inet(view(pseudo.begin(), pseudo.len()));
                    uint16_t net_sum = utils::mem::bswap<uint16_t>(sum);
                    buffer.patch(hoff + 6, reinterpret_cast<const uint8_t*>(&net_sum), 2);

                } else if (ipv6) {
                    pseudo_len = 40 + total;
                    pseudo = Buffer::alloc(pseudo_len);
                    if (!pseudo.valid()) {
                        return;
                    }

                    uint8_t* p = pseudo.reserve(pseudo_len);
                    if (!p) {
                        return;
                    }

                    const mn_ipv6 src = ipv6->src();
                    const mn_ipv6 dst = ipv6->dst();

                    utils::mem::copy(p, src.data(), 16);
                    utils::mem::copy(p + 16, dst.data(), 16);
                    p[32] = static_cast<uint8_t>((total >> 24) & 0xFFu);
                    p[33] = static_cast<uint8_t>((total >> 16) & 0xFFu);
                    p[34] = static_cast<uint8_t>((total >> 8) & 0xFFu);
                    p[35] = static_cast<uint8_t>(total & 0xFFu);
                    p[36] = 0;
                    p[37] = 0;
                    p[38] = 0;
                    p[39] = UDP_IP_PROTO;

                    utils::mem::copy(p + 40, buffer.begin() + hoff, total);

                    uint16_t sum = utils::checksum::inet(view(pseudo.begin(), pseudo.len()));
                    uint16_t net_sum = utils::mem::bswap<uint16_t>(sum);
                    // In IPv6, UDP checksum cannot be zero
                    if (net_sum == 0) {
                        net_sum = 0xFFFFu;
                    }
                    buffer.patch(hoff + 6, reinterpret_cast<const uint8_t*>(&net_sum), 2);
                }
            }
    };
}

// RFC-9293
#pragma once

#include "lynx/protocols/tl/segment.h"
#include "lynx/protocols/il/ipv4.h"
#include "lynx/protocols/il/ipv6.h"

namespace lynx::proto {
    /**
     * @brief IPv4 protocol number used by TCP.
     */
    icu8 TCP_IP_PROTO = 6;

    /**
     * @brief Fixed length of a TCP header in bytes (minimum, without options).
     */
    icu32 TCP_HDR_LEN = 20;

    /**
     * @brief TCP flags (only 8).
     * 
     * the low byte holds the classic 8 flags. NS lives in the high nibble of
     * the data_off byte. combine with bitwise OR: TCP_FLAG_SYN | TCP_FLAG_ACK
     */
    icu8 TCP_FLAG_SYN = 0x02;
    icu8 TCP_FLAG_FIN = 0x01;
    icu8 TCP_FLAG_RST = 0x04;
    icu8 TCP_FLAG_PSH = 0x08;
    icu8 TCP_FLAG_ACK = 0x10;
    icu8 TCP_FLAG_URG = 0x20;
    icu8 TCP_FLAG_ECE = 0x40;
    icu8 TCP_FLAG_CWR = 0x80;

    // common flag combos
    icu8 TCP_FLAG_SYN_ACK = TCP_FLAG_SYN | TCP_FLAG_ACK;
    icu8 TCP_FLAG_FIN_ACK = TCP_FLAG_FIN | TCP_FLAG_ACK;
    icu8 TCP_FLAG_RST_ACK = TCP_FLAG_RST | TCP_FLAG_ACK;

    /**
     * @brief TCP segment header for transmission control.
     */
    class TCP : public Segment {
        public:
            /**
             * @brief Constructs a TCP header from an existing byte view.
             * @param v Bytes containing the TCP header and optional payload.
             */
            TCP(const view& v) noexcept {
                dissect(v);
            }

            /**
             * @brief Constructs an empty TCP header ready for crafting.
             */
            TCP() noexcept {
                INIT_HDR

                if (!ok()) {
                    return;
                }

                sport(0);
                dport(0);
                seq(0);
                ack(0);
                data_offset(5);
                flags(0);
                window(0);
                checksum(0);
                urgent_ptr(0);
            }

            /**
             * @brief Constructs a crafted TCP segment with explicit fields.
             * @param sport_ Source port.
             * @param dport_ Destination port.
             * @param seq_ Sequence number.
             * @param ack_ Acknowledgment number.
             * @param flags_ TCP flags byte.
             * @param win_ Window size.
             * @param urgent_ptr_ Urgent pointer (default 0).
             */
            TCP(uint16_t sport_, uint16_t dport_, uint32_t seq_,
                uint32_t ack_, uint8_t flags_, uint16_t win_,
                uint16_t urgent_ptr_ = 0) noexcept {
                
                INIT_HDR
                
                if (!ok()) {
                    return;
                }

                sport(sport_);
                dport(dport_);
                seq(seq_);
                ack(ack_);
                data_offset(5);
                flags(flags_);
                window(win_);
                checksum(0);
                urgent_ptr(urgent_ptr_);
            }

            /**
             * @brief Returns the TCP header size in bytes.
             * @return Header length based on data offset field (min 20, max 60).
             */
            [[nodiscard]] uint32_t hsize() const noexcept override {
                // if crafting there is no view yet, so return the minimum header size
                if (!m_origin_view.ok() || m_origin_view.size() < 20) {
                    return TCP_HDR_LEN; // minimum header size
                }
                uint8_t offset = (m_origin_view[12] >> 4) & 0x0F;
                return offset * 4;
            }

            /**
             * @brief Returns the IPv4 protocol number for TCP.
             * @return 6 (IPPROTO_TCP).
             */
            [[nodiscard]] uint8_t proto() const noexcept override {
                return TCP_IP_PROTO;
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
             * @brief Sets the sequence number field.
             * @param s Sequence number in host byte order.
             */
            void seq(uint32_t s) noexcept {
                uint32_t net_s = utils::mem::bswap<uint32_t>(s);
                utils::mem::copy(m_origin_view.begin() + 4, &net_s, 4);
            }

            /**
             * @brief Returns the sequence number field.
             * @return Current sequence number in host byte order.
             */
            uint32_t seq() noexcept {
                uint32_t s = 0;
                utils::mem::copy(&s, m_origin_view.begin() + 4, 4);
                return utils::mem::bswap<uint32_t>(s);
            }

            /**
             * @brief Sets the acknowledgment number field.
             * @param a Acknowledgment number in host byte order.
             */
            void ack(uint32_t a) noexcept {
                uint32_t net_a = utils::mem::bswap<uint32_t>(a);
                utils::mem::copy(m_origin_view.begin() + 8, &net_a, 4);
            }

            /**
             * @brief Returns the acknowledgment number field.
             * @return Current acknowledgment number in host byte order.
             */
            uint32_t ack() noexcept {
                uint32_t a = 0;
                utils::mem::copy(&a, m_origin_view.begin() + 8, 4);
                return utils::mem::bswap<uint32_t>(a);
            }

            /**
             * @brief Sets the data offset field.
             * @param offset Data offset value in 32-bit words.
             */
            void data_offset(uint8_t offset) noexcept {
                uint8_t val = m_origin_view[12];
                val = (val & 0x0F) | ((offset & 0x0F) << 4);
                m_origin_view[12] = val;
            }

            /**
             * @brief Returns the data offset field.
             * @return Current data offset in 32-bit words.
             */
            uint8_t data_offset() noexcept {
                return (m_origin_view[12] >> 4) & 0x0F;
            }

            /**
             * @brief Sets the TCP flags byte.
             * @param f Flags value.
             */
            void flags(uint8_t f) noexcept {
                m_origin_view[13] = f;
            }

            /**
             * @brief Returns the TCP flags byte.
             * @return Current flags value.
             */
            uint8_t flags() noexcept {
                return m_origin_view[13];
            }

            /**
             * @brief Sets the window size field.
             * @param w Window size in host byte order.
             */
            void window(uint16_t w) noexcept {
                uint16_t net_w = utils::mem::bswap<uint16_t>(w);
                utils::mem::copy(m_origin_view.begin() + 14, &net_w, 2);
            }

            /**
             * @brief Returns the window size field.
             * @return Current window size in host byte order.
             */
            uint16_t window() noexcept {
                uint16_t w = 0;
                utils::mem::copy(&w, m_origin_view.begin() + 14, 2);
                return utils::mem::bswap<uint16_t>(w);
            }

            /**
             * @brief Sets the checksum field.
             * @param cs Checksum in host byte order.
             */
            void checksum(uint16_t cs) noexcept {
                uint16_t net_cs = utils::mem::bswap<uint16_t>(cs);
                utils::mem::copy(m_origin_view.begin() + 16, &net_cs, 2);
            }

            /**
             * @brief Returns the checksum field.
             * @return Current checksum in host byte order.
             */
            uint16_t checksum() noexcept {
                uint16_t cs = 0;
                utils::mem::copy(&cs, m_origin_view.begin() + 16, 2);
                return utils::mem::bswap<uint16_t>(cs);
            }

            /**
             * @brief Sets the urgent pointer field.
             * @param up Urgent pointer in host byte order.
             */
            void urgent_ptr(uint16_t up) noexcept {
                uint16_t net_up = utils::mem::bswap<uint16_t>(up);
                utils::mem::copy(m_origin_view.begin() + 18, &net_up, 2);
            }

            /**
             * @brief Returns the urgent pointer field.
             * @return Current urgent pointer in host byte order.
             */
            uint16_t urgent_ptr() noexcept {
                uint16_t up = 0;
                utils::mem::copy(&up, m_origin_view.begin() + 18, 2);
                return utils::mem::bswap<uint16_t>(up);
            }

        protected:
            /**
             * @brief Patches the serialized TCP checksum using IPv4 or IPv6 pseudo-header.
             *
             * The checksum covers a pseudo-header (IP addresses + protocol + length)
             * followed by the TCP header and payload. The checksum field is zeroed
             * before computation.
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
                if (total < TCP_HDR_LEN) {
                    return;
                }

                utils::mem::zero(buffer.at(hoff + 16), 2);

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
                    p[9] = TCP_IP_PROTO;
                    p[10] = static_cast<uint8_t>((total >> 8) & 0xFFu);
                    p[11] = static_cast<uint8_t>(total & 0xFFu);

                    utils::mem::copy(p + 12, buffer.begin() + hoff, total);

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
                    p[39] = TCP_IP_PROTO;

                    utils::mem::copy(p + 40, buffer.begin() + hoff, total);
                } else {
                    return;
                }

                uint16_t sum = utils::checksum::inet(view(pseudo.begin(), pseudo.len()));
                uint16_t net_sum = utils::mem::bswap<uint16_t>(sum);
                buffer.patch(hoff + 16, reinterpret_cast<const uint8_t*>(&net_sum), 2);
            }
    };
}

// RFC-9260
#pragma once

#include "lynx/protocols/tl/segment.h"

namespace lynx::proto {
    /**
     * @brief IPv4/IPv6 protocol number used by SCTP.
     */
    icu8 SCTP_IP_PROTO = 132;

    /**
     * @brief Fixed length of an SCTP common header in bytes.
     */
    icu32 SCTP_HDR_LEN = 12;

    /**
     * @brief Fixed length of an SCTP chunk header in bytes.
     */
    icu32 SCTP_CHUNK_HDR_LEN = 4;

    /**
     * @brief Chunk types.
     */
    inline constexpr uint8_t  SCTP_CHUNK_DATA          = 0;
    inline constexpr uint8_t  SCTP_CHUNK_INIT          = 1;
    inline constexpr uint8_t  SCTP_CHUNK_INIT_ACK      = 2;
    inline constexpr uint8_t  SCTP_CHUNK_SACK          = 3;
    inline constexpr uint8_t  SCTP_CHUNK_HEARTBEAT     = 4;
    inline constexpr uint8_t  SCTP_CHUNK_HEARTBEAT_ACK = 5;
    inline constexpr uint8_t  SCTP_CHUNK_ABORT         = 6;
    inline constexpr uint8_t  SCTP_CHUNK_SHUTDOWN      = 7;
    inline constexpr uint8_t  SCTP_CHUNK_SHUTDOWN_ACK  = 8;
    inline constexpr uint8_t  SCTP_CHUNK_ERROR         = 9;
    inline constexpr uint8_t  SCTP_CHUNK_COOKIE_ECHO   = 10;
    inline constexpr uint8_t  SCTP_CHUNK_COOKIE_ACK    = 11;
    inline constexpr uint8_t  SCTP_CHUNK_SHUTDOWN_COMPLETE = 14;

    /**
     * @brief Chunk flags.
     */
    inline constexpr uint8_t  SCTP_DATA_FLAG_E = 0x01;
    inline constexpr uint8_t  SCTP_DATA_FLAG_B = 0x02;
    inline constexpr uint8_t  SCTP_DATA_FLAG_U = 0x04;

    /**
     * @brief INIT chunk fixed parameters.
     */
    inline constexpr uint16_t SCTP_DEFAULT_OUT_STREAMS = 10;
    inline constexpr uint16_t SCTP_DEFAULT_IN_STREAMS  = 65535;
    inline constexpr uint32_t SCTP_DEFAULT_RWND        = 106496;

    /**
     * @brief SCTP chunk header for stream control transmission.
     *
     * Each SCTP packet contains one or more chunks, each with its own type, flags, and length.
     * The chunk header is followed by the chunk payload, which varies based on the chunk type.
     */
    class sctp_chunk : public view {
        public:
            using view::view;

            [[nodiscard]] uint8_t type() const noexcept {
                if (size() < SCTP_CHUNK_HDR_LEN) {
                    return 0;
                }
                return (*this)[0];
            }

            [[nodiscard]] uint8_t flags() const noexcept {
                if (size() < SCTP_CHUNK_HDR_LEN) {
                    return 0;
                }
                return (*this)[1];
            }

            [[nodiscard]] uint16_t length() const noexcept {
                if (size() < SCTP_CHUNK_HDR_LEN) {
                    return 0;
                }
                uint16_t len;
                utils::mem::copy(&len, data() + 2, 2);
                return utils::mem::bswap<uint16_t>(len);
            }

            [[nodiscard]] view payload() const noexcept {
                if (size() < SCTP_CHUNK_HDR_LEN) {
                    return view();
                }
                return last(SCTP_CHUNK_HDR_LEN);
            }
    };

    /**
     * @brief SCTP common header for stream control transmission.
     *
     * SCTP checksums use CRC-32c (Castagnoli), not RFC 1071 like TCP/UDP.
     * The checksum field is computed over the entire SCTP packet (header + chunks).
     * No pseudo-header is used, SCTP differs fundamentally from TCP/UDP in this regard.
     */
    class SCTP : public Segment {
        public:
            /**
             * @brief Constructs an SCTP header from an existing byte view.
             * @param v Bytes containing the SCTP header and optional chunks/payload.
             */
            SCTP(const view& v) noexcept {
                dissect(v);
            }

            /**
             * @brief Constructs an empty SCTP header ready for crafting.
             */
            SCTP() noexcept {
                INIT_HDR

                if (!ok()) {
                    return;
                }

                sport(0);
                dport(0);
                vtag(0);
                checksum(0);
            }

            /**
             * @brief Constructs a crafted SCTP header with explicit fields.
             * @param src_port_ Source port.
             * @param dst_port_ Destination port.
             * @param vtag_ Verification tag.
             */
            SCTP(uint16_t src_port_, uint16_t dst_port_, uint32_t vtag_ = 0) noexcept {
                INIT_HDR
                
                if (!ok()) {
                    return;
                }

                sport(src_port_);
                dport(dst_port_);
                vtag(vtag_);
                checksum(0);
            }

            /**
             * @brief Returns the SCTP header size in bytes.
             * @return 12 bytes (common header only, chunks follow separately).
             */
            [[nodiscard]] uint32_t hsize() const noexcept override {
                return SCTP_HDR_LEN;
            }

            /**
             * @brief Returns the IPv4/IPv6 protocol number for SCTP.
             * @return 132 (IPPROTO_SCTP).
             */
            [[nodiscard]] uint8_t proto() const noexcept override {
                return SCTP_IP_PROTO;
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
             * @brief Sets the verification tag field.
             * @param tag Tag value in host byte order.
             */
            void vtag(uint32_t tag) noexcept {
                uint32_t net_tag = utils::mem::bswap<uint32_t>(tag);
                utils::mem::copy(m_origin_view.begin() + 4, &net_tag, 4);
            }

            /**
             * @brief Returns the verification tag field.
             * @return Current verification tag in host byte order.
             */
            uint32_t vtag() noexcept {
                uint32_t tag = 0;
                utils::mem::copy(&tag, m_origin_view.begin() + 4, 4);
                return utils::mem::bswap<uint32_t>(tag);
            }

            /**
             * @brief Sets the checksum field (CRC-32c).
             * @param cs Checksum in host byte order.
             */
            void checksum(uint32_t cs) noexcept {
                uint32_t net_cs = utils::mem::bswap<uint32_t>(cs);
                utils::mem::copy(m_origin_view.begin() + 8, &net_cs, 4);
            }

            /**
             * @brief Returns the checksum field (CRC-32c).
             * @return Current checksum in host byte order.
             */
            uint32_t checksum() noexcept {
                uint32_t cs = 0;
                utils::mem::copy(&cs, m_origin_view.begin() + 8, 4);
                return utils::mem::bswap<uint32_t>(cs);
            }

            /**
             * @brief Advances to the next SCTP chunk.
             *
             * @return @c true if another chunk is available; @c false when the
             *         traversal is exhausted or a malformed chunk length overruns
             *         the available payload.
             */
            bool next() noexcept {
                view payload = m_origin_view.last(hsize());

                if (m_chunk_offset + SCTP_CHUNK_HDR_LEN > payload.size()) {
                    return false;
                }

                uint8_t* base = payload.begin() + m_chunk_offset;

                // get chunk length
                uint16_t len = 0;
                utils::mem::copy(&len, base + 2, 2);
                len = utils::mem::bswap<uint16_t>(len);

                if (len < SCTP_CHUNK_HDR_LEN || m_chunk_offset + len > payload.size()) {
                    m_malformed = true;
                    return false;
                }

                m_current_chunk = sctp_chunk(base, len);
                m_chunk_offset += (len + 3u) & ~3u;
                return true;
            }

            /**
             * @brief Returns the current SCTP chunk without advancing.
             *
             * @param ok If non-null, set to @c true for a valid chunk or when the
             *           traversal has ended cleanly; set to @c false only when next()
             *           encountered a malformed chunk length that ran past the payload.
             * @return The current SCTP chunk.
             */
            sctp_chunk current(bool* ok = nullptr) const noexcept {
                if (ok) {
                    *ok = !m_malformed;
                }
                return m_current_chunk;
            }

            /**
             * @brief Resets SCTP chunk traversal to the first chunk.
             */
            void reset() noexcept {
                m_chunk_offset = 0;
                m_current_chunk = sctp_chunk{};
                m_malformed = false;
            }

        protected:
            /**
             * @brief Patches the serialized SCTP checksum using CRC-32c.
             *
             * The checksum covers the entire SCTP packet (common header + all chunks),
             * with the checksum field zeroed before computation. No pseudo-header or
             * underlayer information is used — SCTP CRC-32c is self-contained.
             *
             * @param buffer Packet buffer containing the serialized packet.
             * @param hoff Byte offset where this header begins inside @p buffer.
             */
            void patch(Buffer &buffer, uint32_t hoff) const noexcept {
                if (buffer.len() <= hoff) {
                    return;
                }

                uint32_t total = buffer.len() - hoff;
                if (total < SCTP_HDR_LEN) {
                    return;
                }

                utils::mem::zero(buffer.at(hoff + 8), 4);

                uint32_t sum = utils::checksum::crc32c(buffer.begin() + hoff, total);
                uint32_t net_sum = utils::mem::bswap<uint32_t>(sum);
                buffer.patch(hoff + 8, reinterpret_cast<const uint8_t*>(&net_sum), 4);
            }

            uint32_t m_chunk_offset = 0;
            sctp_chunk m_current_chunk{};
            bool m_malformed = false;
    };
}

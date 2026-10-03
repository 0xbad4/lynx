// RFC-894
#pragma once

#include "lynx/protocols/ll/frame.h"

namespace lynx::proto
{
    icu32 ETH_HDR_LEN = 0x000E;  // 14

    class Eth : public Frame {
        public:
            Eth(const view& v = {}) noexcept {
                dissect(v);
            }

            /**
             * @brief Constructs an Ethernet frame header.
             *
             * @param dst   Destination MAC address.
             * @param src   Source MAC address.
             * @param etype EtherType in host byte order.
             */
            Eth(const mn_mac &dst_, const mn_mac &src_, const uint16_t& etype) {
                INIT_HDR

                if (!ok()) { 
                    return;
                }

                // copy attributes to header
                // dst mac addr
                dst(dst_);

                // src mac addr
                src(src_);

                // ethernet type
                ethertype(etype);
            }

            [[nodiscard]] uint32_t hsize() const noexcept {
                return ETH_HDR_LEN;
            }

            [[nodiscard]] frame_type type() const noexcept {
                return frame_type::Eth;
            }

            /**
             * @brief Sets the destination MAC address.
             * @param d MAC address to set.
             */
            void dst(const mn_mac& d) noexcept {
                utils::mem::copy(m_origin_view.begin(), d.data(), 6);
            }

            /**
             * @brief Gets the destination MAC address.
             * @return The destination MAC address.
             */
            mn_mac dst() noexcept {
                return mn_mac(m_origin_view.first(6).data());
            }
    
            /**
             * @brief Sets the source MAC address.
             * @param s MAC address to set.
             */
            void src(const mn_mac& s) noexcept {
                utils::mem::copy(m_origin_view.begin() + 6, s.data(), 6);
            }

            /**
             * @brief Gets the source MAC address.
             * @return The source MAC address.
             */
            mn_mac src() noexcept {
                return mn_mac(m_origin_view.slice(6, 12).data());
            }
    
            /**
             * @brief Sets the Ethernet EtherType.
             * @param etype EtherType in host byte order.
             */
            void ethertype(uint16_t etype) noexcept {
                uint16_t et = utils::mem::bswap<uint16_t>(etype);
                utils::mem::copy(m_origin_view.begin() + m_ethertype_begin, &et, 2);
            }

            /**
             * @brief Gets the Ethernet EtherType.
             * @return EtherType in host byte order.
             */
            uint16_t ethertype() noexcept {
                uint16_t etype = 0;
                std::printf("ethertype offset: %u\n", m_ethertype_begin);
                utils::mem::copy(&etype, m_origin_view.begin() + m_ethertype_begin, 2);
                return utils::mem::bswap<uint16_t>(etype);
            }

        protected:
            uint8_t m_ethertype_begin = 12; ///< Byte offset of the EtherType field, from the start of the frame.
    };
} // namespace lynx::proto

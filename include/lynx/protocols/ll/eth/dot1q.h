// RFC-802.1Q
#pragma once

#include "lynx/protocols/ll/eth/eth.h"

namespace lynx::proto
{
    icu32 DOT1Q_HDR_LEN           = 0x0012;  // 18
    icu32 DOT1Q_TPID              = 0x8100;
    icu32 DOT1Q_TAG_BEGIN         = 12;
    icu32 DOT1Q_ETHERTYPE_BEGIN   = 16;
    
    /**
     * @brief Represents the fields of an IEEE 802.1Q VLAN tag.
     *
     * Contains the Tag Protocol Identifier (TPID) and Tag Control Information
     * (TCI) fields of an 802.1Q tag. PCP and DEI are represented separately
     * even though they are encoded in the upper bits of the 16-bit TCI field.
     *
     * @note @p pcp and @p dei contain the logical field values, not their
     *       bit-shifted positions within the TCI field.
     *
     * @note @p id contains the VLAN Identifier (VID).
     * @note Incomplete fields are encoded in the lower bits of their respective storage types.
     */
    LYNX_PACKED vlan_tag {
        uint16_t type     = 0;  // Tag Protocol Identifier (TPID)
        uint8_t  pcp : 3  = 0;  // Priority Code Point (3 bits)
        uint8_t  dei : 1  = 0;  // Drop Eligible Indicator (1 bit)
        uint16_t id  : 12 = 0;  // VLAN Identifier (12 bits)
    };
    
    class Dot1Q : public Eth {
        public:
            Dot1Q(const view& v = {}) noexcept {
                m_ethertype_begin = DOT1Q_ETHERTYPE_BEGIN;
                dissect(v);
            }

            /**
             * @brief Constructs an IEEE 802.1Q VLAN-tagged Ethernet frame header.
             *
             * @param dst   Destination MAC address.
             * @param src   Source MAC address.
             * @param tag_  IEEE 802.1Q VLAN tag.
             * @param etype EtherType in host byte order.
             */
            Dot1Q(const mn_mac &dst_, const mn_mac &src_, const vlan_tag &tag_, const uint16_t &etype) {
                // change ethertype offset
                m_ethertype_begin = DOT1Q_ETHERTYPE_BEGIN;

                INIT_HDR

                if (!ok()) {
                    return;
                }

                // copy attributes to header
                // dst mac addr
                dst(dst_);

                // src mac addr
                src(src_);

                // 802.1Q tag
                tag(tag_);

                // ethernet type
                ethertype(etype);
            }

            [[nodiscard]] uint32_t hsize() const noexcept {
                return DOT1Q_HDR_LEN;
            }

            /**
             * @brief Sets the IEEE 802.1Q VLAN tag.
             * @param t VLAN tag to set.
             */
            [[nodiscard]] frame_type type() const noexcept {
                return frame_type::Eth;
            } 

            /**
             * @brief Sets the IEEE 802.1Q VLAN tag.
             * @param t VLAN tag to set.
             */
            void tag(const vlan_tag& t) {
                set_tag(t, m_1q_tag_begin);
            }

            /**
             * @brief Gets the IEEE 802.1Q VLAN tag.
             * @return The VLAN tag in host representation.
             */
            vlan_tag tag() {
                return get_tag(m_1q_tag_begin);
            }

        protected:
            uint8_t m_1q_tag_begin = DOT1Q_TAG_BEGIN;

            /**
             * @brief Sets the tag fields stored at a specific offset.
             * @param t VLAN tag to set.
             * @param off Field offset in the frame.
             */
            void set_tag(const vlan_tag& t, uint32_t off) {
                uint32_t tag_ = 0;

                // convert to int32 (4bytes)
                tag_ |= static_cast<uint32_t>(t.type) << 16;
                tag_ |= static_cast<uint32_t>(t.pcp)  << 13;
                tag_ |= static_cast<uint32_t>(t.dei)  << 12;
                tag_ |= static_cast<uint32_t>(t.id);

                // to network order
                tag_ = utils::mem::bswap<uint32_t>(tag_);

                // set
                utils::mem::copy(m_origin_view.begin() + off, &tag_, 4);
            }

            /**
             * @brief Gets the tag fields stored at a specific offset.
             * @param off Field offset in the frame.
             * @return The VLAN tag in host representation.
             */
            vlan_tag get_tag(uint32_t off) {
                uint32_t tag_ = 0;

                // get
                utils::mem::copy(&tag_, m_origin_view.begin() + off, 4);

                // to host order
                tag_ = utils::mem::bswap<uint32_t>(tag_);

                // populate
                return {
                    .type = static_cast<uint16_t>(tag_ >> 16),
                    .pcp  = static_cast<uint8_t>((tag_ >> 13) & 0x07),
                    .dei  = static_cast<uint8_t>((tag_ >> 12) & 0x01),
                    .id   = static_cast<uint16_t>(tag_ & 0x0FFF)
                };
            }
    
    };
} // namespace lynx::proto

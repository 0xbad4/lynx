// RFC-802.1ad
#pragma once

#include "lynx/protocols/ll/eth/dot1q.h"

namespace lynx::proto
{
    icu32 QINQ_HDR_LEN         = 0x0016;  // 22
    icu32 QINQ_TPID            = 0x88A8;
    icu32 QINQ_OUTER_TAG_BEGIN = 12;
    icu32 QINQ_INNER_TAG_BEGIN = 16;
    icu32 QINQ_ETHERTYPE_BEGIN = 20;

    class QinQ : public Dot1Q {
        public:
            QinQ(const view& v = {}) noexcept {
                m_1q_tag_begin    = QINQ_INNER_TAG_BEGIN;
                m_ethertype_begin = QINQ_ETHERTYPE_BEGIN;
                dissect(v);
            }

            /**
             * @brief Constructs an IEEE 802.1ad (QinQ) VLAN-tagged Ethernet frame header.
             *
             * @param dst_    Destination MAC address.
             * @param src_    Source MAC address.
             * @param tag_ad  IEEE 802.1ad outer VLAN tag.
             * @param tag_1q_ IEEE 802.1Q inner VLAN tag.
             * @param etype EtherType in host byte order.
             */
            QinQ(const mn_mac &dst_, const mn_mac &src_, const vlan_tag &tag_ad, const vlan_tag &tag_1q_, const uint16_t &etype) {
                // change Dot1Q tag offset
                m_1q_tag_begin    = QINQ_INNER_TAG_BEGIN;

                // change ethertype offset
                m_ethertype_begin = QINQ_ETHERTYPE_BEGIN;

                INIT_HDR

                if (!ok()) {
                    return;
                }

                // copy attributes to header
                // dst mac addr
                dst(dst_);

                // src mac addr
                src(src_);

                // 802.1ad tag
                tag(tag_ad);

                // 802.1q tag
                tag1q(tag_1q_);

                // ethernet type
                ethertype(etype);
            }

            [[nodiscard]] uint32_t hsize() const noexcept {
                return QINQ_HDR_LEN;
            }

            [[nodiscard]] bool check() noexcept override {
                if (!Dot1Q::check()) {
                    return false;
                }
                return tag().type == QINQ_TPID;
            }

            [[nodiscard]] frame_type type() const noexcept {
                return frame_type::Eth;
            }
    
            /**
             * @brief Sets the inner (customer) 802.1Q tag.
             * @param t VLAN tag to set.
             */
            void tag1q(const vlan_tag& t) {
                Dot1Q::tag(t);
            }

            /**
             * @brief Gets the inner (customer) 802.1Q tag.
             * @return The inner tag in host representation.
             */
            vlan_tag tag1q() {
                return Dot1Q::tag();
            }

            /**
             * @brief Sets the outer (service-provider) 802.1ad tag.
             * @param t VLAN tag to set.
             */
            void tag(const vlan_tag& t) {
                set_tag(t, QINQ_OUTER_TAG_BEGIN);
            }

            /**
             * @brief Gets the outer (service-provider) 802.1ad tag.
             * @return The outer tag in host representation.
             */
            vlan_tag tag() {
                return get_tag(QINQ_OUTER_TAG_BEGIN);
            }
    };
} // namespace lynx::proto

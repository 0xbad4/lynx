// IEEE 802.2 SNAP
#pragma once

#include "lynx/protocols/ll/llc.h"
#include "lynx/core/utils.h"

namespace lynx::proto
{
    icu32 SNAP_HDR_LEN     = 5;          // OUI (3) + PID (2)

    icu32 SNAP_OUI_RFC1042 = 0x000000;   // EtherType bridging
    icu32 SNAP_OUI_CISCO   = 0x00000C;   // Cisco protocols (PVST+, CDP, ...)

    icu16 SNAP_PID_PVST    = 0x010B;     // Cisco PVST+ / Rapid-PVST+
    icu16 SNAP_PID_VLAN    = 0x8100;     // 802.1Q when SNAP-encapsulated

    /**
     * @brief IEEE 802.2 Subnetwork Access Protocol header.
     *
     * Follows an LLC header with DSAP = SSAP = 0xAA and Control = UI (0x03).
     * PVST+ BPDUs are carried in SNAP with Cisco OUI 00:00:0C and PID 0x010B.
     */
    class SNAP : public ProtocolBaseObject {
        public:
            SNAP(view v = {}) noexcept {
                dissect(v);
            }

            /**
             * @brief Crafts a SNAP header.
             * @param oui_ Organizationally Unique Identifier (24-bit, stored in the low 24 bits).
             * @param pid_ Protocol identifier in host byte order.
             */
            SNAP(uint32_t oui_, uint16_t pid_) noexcept {
                dissect(hsize());

                if (!ok()) {
                    return;
                }

                oui(oui_);
                pid(pid_);
            }

            [[nodiscard]] uint32_t hsize() const noexcept override {
                return SNAP_HDR_LEN;
            }

            /// @return 24-bit OUI in the low 24 bits of the value.
            [[nodiscard]] uint32_t oui() const noexcept {
                return (uint32_t(m_origin_view[0]) << 16)
                     | (uint32_t(m_origin_view[1]) << 8)
                     |  uint32_t(m_origin_view[2]);
            }

            void oui(uint32_t v) noexcept {
                m_origin_view[0] = static_cast<uint8_t>((v >> 16) & 0xFF);
                m_origin_view[1] = static_cast<uint8_t>((v >> 8)  & 0xFF);
                m_origin_view[2] = static_cast<uint8_t>( v        & 0xFF);
            }

            /// @return Protocol ID in host byte order.
            [[nodiscard]] uint16_t pid() const noexcept {
                uint16_t v = 0;
                utils::mem::copy(&v, m_origin_view.begin() + 3, 2);
                return utils::mem::bswap<uint16_t>(v);
            }

            void pid(uint16_t v) noexcept {
                uint16_t n = utils::mem::bswap<uint16_t>(v);
                utils::mem::copy(m_origin_view.begin() + 3, &n, 2);
            }

            [[nodiscard]] bool is_pvst() const noexcept {
                return oui() == SNAP_OUI_CISCO && pid() == SNAP_PID_PVST;
            }
    };
} // namespace lynx::proto

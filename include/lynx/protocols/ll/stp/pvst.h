// Cisco PVST+ / Rapid-PVST+
#pragma once

namespace lynx::proto
{
    icu32 PVST_HDR_LEN = 4;      // reserved (2) + VLAN ID (2)

    /// Cisco PVST+ / Rapid-PVST+ group address (01:00:0C:CC:CC:CD).
    [[nodiscard]] inline mn_mac pvst_group_mac() noexcept {
        const uint8_t b[6] = { 0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCD };
        return mn_mac(b);
    }

    /**
     * @brief Cisco PVST+ / Rapid-PVST+ VLAN header.
     *
     * Carried after LLC+SNAP (OUI 00:00:0C, PID 0x010B). The 4-octet header
     * is followed by a standard STP (PVST+) or RSTP (Rapid-PVST+) BPDU.
     *
     * Layout:
     *   0-1  Reserved (0)
     *   2-3  VLAN ID (host order via accessors)
     */
    class PVST : public ProtocolBaseObject {
        public:
            PVST(view v = {}) noexcept {
                dissect(v);

                if (ok() && !v.ok()) {
                    reserved(0);
                    vlan(1);
                }
            }

            explicit PVST(uint16_t vlan_id) noexcept {
                dissect(hsize());

                if (!ok()) {
                    return;
                }

                reserved(0);
                vlan(vlan_id);
            }

            [[nodiscard]] uint32_t hsize() const noexcept override {
                return PVST_HDR_LEN;
            }

            [[nodiscard]] uint16_t reserved() const noexcept {
                uint16_t v = 0;
                utils::mem::copy(&v, m_origin_view.begin(), 2);
                return utils::mem::bswap<uint16_t>(v);
            }

            void reserved(uint16_t v) noexcept {
                uint16_t n = utils::mem::bswap<uint16_t>(v);
                utils::mem::copy(m_origin_view.begin(), &n, 2);
            }

            [[nodiscard]] uint16_t vlan() const noexcept {
                uint16_t v = 0;
                utils::mem::copy(&v, m_origin_view.begin() + 2, 2);
                return utils::mem::bswap<uint16_t>(v);
            }

            void vlan(uint16_t v) noexcept {
                uint16_t n = utils::mem::bswap<uint16_t>(v);
                utils::mem::copy(m_origin_view.begin() + 2, &n, 2);
            }
    };
} // namespace lynx::proto

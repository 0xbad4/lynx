// IEEE 802.2
#pragma once

#include "lynx/core/base/proto.h"

namespace lynx::proto
{
    icu32 LLC_HDR_LEN  = 3;     // DSAP + SSAP + Control (1-byte control)

    icu8  LLC_SAP_STP  = 0x42;  // Spanning Tree / GARP
    icu8  LLC_SAP_SNAP = 0xAA;  // SNAP (used by PVST+)
    icu8  LLC_CTRL_UI  = 0x03;  // Unnumbered Information

    /**
     * @brief IEEE 802.2 Logical Link Control header.
     *
     * Carried directly after an Ethernet header whose Type/Length field
     * holds a length (<= 1500) instead of an EtherType.
     *
     * @note Only the 1-byte Control form (U-format) is supported. I- and
     *       S-format frames use a 2-byte Control field and are not parsed.
     */
    class LLC : public ProtocolBaseObject {
        public:
            /**
             * @brief Captures from @p v, or allocates a zeroed header if @p v is empty.
             */
            LLC(view v = {}) noexcept {
                dissect(v);
            }

            LLC(uint8_t dsap_, uint8_t ssap_, uint8_t ctrl_) noexcept {
                dissect({});

                if (!ok()) {
                    return;
                }

                dsap(dsap_);
                ssap(ssap_);
                control(ctrl_);
            }

            [[nodiscard]] uint32_t hsize() const noexcept override {
                return LLC_HDR_LEN;
            }
            
            /// @return Destination Service Access Point.
            [[nodiscard]] uint8_t dsap() const noexcept { return m_origin_view[0]; }
            void dsap(uint8_t v) noexcept { m_origin_view[0] = v; }

            /// @return Source Service Access Point.
            [[nodiscard]] uint8_t ssap() const noexcept { return m_origin_view[1]; }
            void ssap(uint8_t v) noexcept { m_origin_view[1] = v; }

            /// @return Control field.
            [[nodiscard]] uint8_t control() const noexcept { return m_origin_view[2]; }
            void control(uint8_t v) noexcept { m_origin_view[2] = v; }
    };
} // namespace lynx::proto
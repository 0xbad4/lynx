// IEEE 802.1w / 802.1D-2004
#pragma once

namespace lynx::proto
{
    icu32 RSTP_HDR_LEN = 36;     // Configuration BPDU + Version 1 Length

    /**
     * @brief IEEE 802.1w Rapid Spanning Tree BPDU.
     *
     * Identical to the 802.1D Configuration BPDU with one extra octet:
     * Version 1 Length, which is always 0 (no version-1 parameters follow).
     *
     * Protocol Version Identifier is 2. BPDU Type is 2.
     */
    class RSTP : public STP {
        protected:
            explicit RSTP(derived_init tag) noexcept : STP(tag) {}

        public:
            RSTP(view v = {}) noexcept : STP(derived_init{}) {
                dissect(v);

                if (ok() && !v.ok()) {
                    protocol_id(STP_PROTO_ID);
                    version(STP_VERSION_RSTP);
                    type(STP_TYPE_RSTP);
                    version_1_length(0);
                }
            }

            RSTP(uint8_t flags_,
                 uint64_t root_id_,
                 uint32_t root_path_cost_,
                 uint64_t bridge_id_,
                 uint16_t port_id_,
                 uint16_t message_age_,
                 uint16_t max_age_,
                 uint16_t hello_time_,
                 uint16_t forward_delay_) noexcept
                : STP(derived_init{}) {

                dissect(hsize());

                if (!ok()) {
                    return;
                }

                protocol_id(STP_PROTO_ID);
                version(STP_VERSION_RSTP);
                type(STP_TYPE_RSTP);
                flags(flags_);
                root_id(root_id_);
                root_path_cost(root_path_cost_);
                bridge_id(bridge_id_);
                port_id(port_id_);
                message_age(message_age_);
                max_age(max_age_);
                hello_time(hello_time_);
                forward_delay(forward_delay_);
                version_1_length(0);
            }

            [[nodiscard]] uint32_t hsize() const noexcept override {
                return RSTP_HDR_LEN;
            }

            [[nodiscard]] uint8_t version_1_length() const noexcept {
                return m_origin_view[35];
            }

            void version_1_length(uint8_t v) noexcept {
                m_origin_view[35] = v;
            }
    };
} // namespace lynx::proto

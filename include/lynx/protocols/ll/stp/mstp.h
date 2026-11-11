// IEEE 802.1s / 802.1Q
#pragma once

namespace lynx::proto
{
    icu32 MSTP_CFG_ID_LEN      = 51;     // format + name + revision + digest
    icu32 MSTP_CFG_NAME_LEN    = 32;
    icu32 MSTP_CFG_DIGEST_LEN  = 16;
    icu32 MSTP_MSTI_LEN        = 16;
    icu32 MSTP_V3_FIXED_LEN    = 64;     // config id + CIST IRPC + CIST bridge + hops
    icu32 MSTP_HDR_LEN         = 102;    // RSTP (36) + Version 3 Length (2) + 64

    /**
     * @brief One MSTI Configuration Message (16 octets).
     */
    class mstp_msti : public view {
        public:
            using view::view;

            [[nodiscard]] uint8_t flags() const noexcept {
                return size() ? (*this)[0] : 0;
            }

            [[nodiscard]] uint64_t regional_root() const noexcept {
                if (size() < MSTP_MSTI_LEN) {
                    return 0;
                }
                uint64_t v = 0;
                utils::mem::copy(&v, data() + 1, 8);
                return utils::mem::bswap<uint64_t>(v);
            }

            [[nodiscard]] uint32_t internal_path_cost() const noexcept {
                if (size() < MSTP_MSTI_LEN) {
                    return 0;
                }
                uint32_t v = 0;
                utils::mem::copy(&v, data() + 9, 4);
                return utils::mem::bswap<uint32_t>(v);
            }

            [[nodiscard]] uint8_t bridge_priority() const noexcept {
                return size() >= 14 ? (*this)[13] : 0;
            }

            [[nodiscard]] uint8_t port_priority() const noexcept {
                return size() >= 15 ? (*this)[14] : 0;
            }

            [[nodiscard]] uint8_t remaining_hops() const noexcept {
                return size() >= 16 ? (*this)[15] : 0;
            }
    };

    /**
     * @brief IEEE 802.1s / 802.1Q Multiple Spanning Tree BPDU.
     * 
     * @note hsize() is 102 plus 16 times the number of MSTI messages implied
     *       by Version 3 Length when capturing; crafted objects start at 102.
     */
    class MSTP : public RSTP {
        public:
            MSTP(view v = {}) noexcept : RSTP(derived_init{}) {
                dissect(v);
            }

            MSTP(uint8_t flags_,
                 uint64_t root_id_,
                 uint32_t root_path_cost_,
                 uint64_t bridge_id_,
                 uint16_t port_id_,
                 uint16_t message_age_,
                 uint16_t max_age_,
                 uint16_t hello_time_,
                 uint16_t forward_delay_) noexcept
                : RSTP(derived_init{}) {

                INIT_HDR

                if (!ok()) {
                    return;
                }

                protocol_id(STP_PROTO_ID);
                version(STP_VERSION_MSTP);
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
                version_3_length(MSTP_V3_FIXED_LEN);
                format_selector(0);
            }

            [[nodiscard]] bool is_msti_present() const noexcept {
                return m_origin_view.size() >= MSTP_HDR_LEN;
            }

            [[nodiscard]] uint32_t hsize() const noexcept override {
                if (m_origin_view.size() < MSTP_HDR_LEN) {
                    return MSTP_HDR_LEN;
                }

                const uint16_t v3 = version_3_length();
                const uint32_t total = RSTP_HDR_LEN + 2 + v3;
                return total < MSTP_HDR_LEN ? MSTP_HDR_LEN : total;
            }

            [[nodiscard]] uint16_t version_3_length() const noexcept {
                return get_u16(36);
            }

            void version_3_length(uint16_t v) noexcept {
                put_u16(36, v);
            }

            [[nodiscard]] uint8_t format_selector() const noexcept {
                return m_origin_view[38];
            }

            void format_selector(uint8_t v) noexcept {
                m_origin_view[38] = v;
            }

            [[nodiscard]] view config_name() const noexcept {
                return m_origin_view.slice(39, 39 + MSTP_CFG_NAME_LEN);
            }

            void config_name(view name) noexcept {
                uint8_t* dst = m_origin_view.begin() + 39;
                utils::mem::zero(dst, MSTP_CFG_NAME_LEN);

                if (!name.ok()) {
                    return;
                }

                const size_t n = name.size() < MSTP_CFG_NAME_LEN
                               ? name.size()
                               : MSTP_CFG_NAME_LEN;
                utils::mem::copy(dst, name.data(), n);
            }

            [[nodiscard]] uint16_t revision() const noexcept {
                return get_u16(71);
            }

            void revision(uint16_t v) noexcept {
                put_u16(71, v);
            }

            [[nodiscard]] view digest() const noexcept {
                return m_origin_view.slice(73, 73 + MSTP_CFG_DIGEST_LEN);
            }

            void digest(view d) noexcept {
                uint8_t* dst = m_origin_view.begin() + 73;
                utils::mem::zero(dst, MSTP_CFG_DIGEST_LEN);

                if (!d.ok()) {
                    return;
                }

                const size_t n = d.size() < MSTP_CFG_DIGEST_LEN
                               ? d.size()
                               : MSTP_CFG_DIGEST_LEN;
                utils::mem::copy(dst, d.data(), n);
            }

            [[nodiscard]] uint32_t cist_internal_path_cost() const noexcept {
                return get_u32(89);
            }

            void cist_internal_path_cost(uint32_t v) noexcept {
                put_u32(89, v);
            }

            [[nodiscard]] uint64_t cist_bridge_id() const noexcept {
                return get_u64(93);
            }

            void cist_bridge_id(uint64_t v) noexcept {
                put_u64(93, v);
            }

            [[nodiscard]] uint8_t remaining_hops() const noexcept {
                return m_origin_view[101];
            }

            void remaining_hops(uint8_t v) noexcept {
                m_origin_view[101] = v;
            }

            /// CIST Regional Root Identifier (RSTP-compatible Bridge Identifier field).
            [[nodiscard]] uint64_t cist_regional_root() const noexcept {
                return bridge_id();
            }

            void cist_regional_root(uint64_t v) noexcept {
                bridge_id(v);
            }

            [[nodiscard]] uint32_t msti_count() const noexcept {
                const uint16_t v3 = version_3_length();

                if (v3 < MSTP_V3_FIXED_LEN) {
                    return 0;
                }
                return (v3 - MSTP_V3_FIXED_LEN) / MSTP_MSTI_LEN;
            }

            [[nodiscard]] mstp_msti msti_at(uint32_t i) const noexcept {
                if (i >= msti_count()) {
                    return mstp_msti();
                }

                const uint32_t off = MSTP_HDR_LEN + i * MSTP_MSTI_LEN;

                if (off + MSTP_MSTI_LEN > m_origin_view.size()) {
                    return mstp_msti();
                }
                return mstp_msti(m_origin_view.begin() + off, MSTP_MSTI_LEN);
            }

            /**
             * @brief Writes one MSTI Configuration Message at index @p i.
             *
             * @note The object must already have enough bytes for that index
             *       (capture of a larger BPDU, or a crafted buffer sized for it).
             */
            void set_msti(uint32_t i,
                          uint8_t flags_,
                          uint64_t regional_root_,
                          uint32_t internal_path_cost_,
                          uint8_t bridge_prio_,
                          uint8_t port_prio_,
                          uint8_t hops_) noexcept {

                const uint32_t off = MSTP_HDR_LEN + i * MSTP_MSTI_LEN;

                if (off + MSTP_MSTI_LEN > m_origin_view.size()) {
                    return;
                }

                m_origin_view[off] = flags_;
                put_u64(off + 1, regional_root_);
                put_u32(off + 9, internal_path_cost_);
                m_origin_view[off + 13] = bridge_prio_;
                m_origin_view[off + 14] = port_prio_;
                m_origin_view[off + 15] = hops_;
            }
    };

    /**
     * @brief IEEE 802.1aq Shortest Path Bridging BPDU.
     *
     * SPT BPDUs reuse the MSTP layout with Protocol Version Identifier 4.
     */
    class SPB : public MSTP {
        public:
            SPB(view v = {}) noexcept : MSTP(v) {
                if (ok() && !v.ok()) {
                    version(STP_VERSION_SPB);
                }
            }
    };
} // namespace lynx::proto

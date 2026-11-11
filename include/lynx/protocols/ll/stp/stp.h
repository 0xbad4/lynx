// IEEE 802.1D
#pragma once

#include "lynx/protocols/ll/llc.h"
#include "lynx/protocols/ll/snap.h"
#include "lynx/core/utils.h"

namespace lynx::proto
{
    icu32 STP_HDR_LEN     = 35;      // Configuration BPDU
    icu32 STP_TCN_HDR_LEN = 4;       // Topology Change Notification BPDU

    icu16 STP_PROTO_ID    = 0x0000;

    icu8  STP_VERSION_STP  = 0;
    icu8  STP_VERSION_RSTP = 2;
    icu8  STP_VERSION_MSTP = 3;
    icu8  STP_VERSION_SPB  = 4;      // IEEE 802.1aq (SPT BPDUs)

    icu8  STP_TYPE_CONFIG  = 0x00;
    icu8  STP_TYPE_RSTP    = 0x02;   // RSTP / MSTP / SPT
    icu8  STP_TYPE_TCN     = 0x80;

    icu8  STP_FLAG_TOPOLOGY_CHANGE     = 0x01;
    icu8  STP_FLAG_PROPOSAL            = 0x02;
    icu8  STP_FLAG_PORT_ROLE_MASK      = 0x0C;
    icu8  STP_FLAG_PORT_ROLE_SHIFT     = 2;
    icu8  STP_FLAG_LEARNING            = 0x10;
    icu8  STP_FLAG_FORWARDING          = 0x20;
    icu8  STP_FLAG_AGREEMENT           = 0x40;
    icu8  STP_FLAG_TOPOLOGY_CHANGE_ACK = 0x80;

    icu8  STP_PORT_ROLE_UNKNOWN    = 0;
    icu8  STP_PORT_ROLE_ALTERNATE  = 1;  // also Backup
    icu8  STP_PORT_ROLE_ROOT       = 2;
    icu8  STP_PORT_ROLE_DESIGNATED = 3;

    /**
     * @brief IEEE 802.1D Configuration BPDU.
     *
     * Encapsulated in IEEE 802.2 LLC (DSAP = SSAP = 0x42, Control = UI).
     * Timer fields are in 1/256 second units, matching the on-wire encoding.
     * 
     * @note STP frames are carried in IEEE 802.3 / LLC, so the Ethernet
     *       type field holds a length, not an EtherType. Use
     *       Eth::ethertype() as the length when dealing with STP.
     */
    class STP : public ProtocolBaseObject {
        public:
            STP(view v = {}) noexcept {
                dissect(v);

                if (ok() && !v.ok()) {
                    protocol_id(STP_PROTO_ID);
                }
            }

            STP(uint8_t version_,
                uint8_t type_,
                uint8_t flags_,
                uint64_t root_id_,
                uint32_t root_path_cost_,
                uint64_t bridge_id_,
                uint16_t port_id_,
                uint16_t message_age_,
                uint16_t max_age_,
                uint16_t hello_time_,
                uint16_t forward_delay_) noexcept {

                INIT_HDR

                if (!ok()) {
                    return;
                }

                protocol_id(STP_PROTO_ID);
                version(version_);
                type(type_);
                flags(flags_);
                root_id(root_id_);
                root_path_cost(root_path_cost_);
                bridge_id(bridge_id_);
                port_id(port_id_);
                message_age(message_age_);
                max_age(max_age_);
                hello_time(hello_time_);
                forward_delay(forward_delay_);
            }

            [[nodiscard]] uint32_t hsize() const noexcept override {
                return STP_HDR_LEN;
            }

            [[nodiscard]] uint16_t protocol_id() const noexcept {
                return get_u16(0); 
            }
            void protocol_id(uint16_t v) noexcept { put_u16(0, v); }

            [[nodiscard]] uint8_t version() const noexcept { return m_origin_view[2]; }
            void version(uint8_t v) noexcept { m_origin_view[2] = v; }

            [[nodiscard]] uint8_t type() const noexcept { return m_origin_view[3]; }
            void type(uint8_t v) noexcept { m_origin_view[3] = v; }

            [[nodiscard]] uint8_t flags() const noexcept { return m_origin_view[4]; }
            void flags(uint8_t v) noexcept { m_origin_view[4] = v; }

            [[nodiscard]] uint64_t root_id() const noexcept { return get_u64(5); }
            void root_id(uint64_t v) noexcept { put_u64(5, v); }

            [[nodiscard]] uint32_t root_path_cost() const noexcept { return get_u32(13); }
            void root_path_cost(uint32_t v) noexcept { put_u32(13, v); }

            [[nodiscard]] uint64_t bridge_id() const noexcept { return get_u64(17); }
            void bridge_id(uint64_t v) noexcept { put_u64(17, v); }

            [[nodiscard]] uint16_t port_id() const noexcept { return get_u16(25); }
            void port_id(uint16_t v) noexcept { put_u16(25, v); }

            [[nodiscard]] uint16_t message_age() const noexcept { return get_u16(27); }
            void message_age(uint16_t v) noexcept { put_u16(27, v); }

            [[nodiscard]] uint16_t max_age() const noexcept { return get_u16(29); }
            void max_age(uint16_t v) noexcept { put_u16(29, v); }

            [[nodiscard]] uint16_t hello_time() const noexcept { return get_u16(31); }
            void hello_time(uint16_t v) noexcept { put_u16(31, v); }

            [[nodiscard]] uint16_t forward_delay() const noexcept { return get_u16(33); }
            void forward_delay(uint16_t v) noexcept { put_u16(33, v); }

            /// High 16 bits of the Root Identifier (priority + system ID extension).
            [[nodiscard]] uint16_t root_priority() const noexcept {
                return static_cast<uint16_t>(root_id() >> 48);
            }

            void root_priority(uint16_t prio) noexcept {
                root_id((root_id() & 0x0000FFFFFFFFFFFFULL)
                      | (static_cast<uint64_t>(prio) << 48));
            }

            [[nodiscard]] mn_mac root_mac() const noexcept {
                return mn_mac(m_origin_view.begin() + 7);
            }

            void root_mac(const mn_mac& mac) noexcept {
                utils::mem::copy(m_origin_view.begin() + 7, mac.data(), 6);
            }

            [[nodiscard]] uint16_t bridge_priority() const noexcept {
                return static_cast<uint16_t>(bridge_id() >> 48);
            }

            void bridge_priority(uint16_t prio) noexcept {
                bridge_id((bridge_id() & 0x0000FFFFFFFFFFFFULL)
                        | (static_cast<uint64_t>(prio) << 48));
            }

            [[nodiscard]] mn_mac bridge_mac() const noexcept {
                return mn_mac(m_origin_view.begin() + 19);
            }

            void bridge_mac(const mn_mac& mac) noexcept {
                utils::mem::copy(m_origin_view.begin() + 19, mac.data(), 6);
            }

            [[nodiscard]] uint8_t port_role() const noexcept {
                return static_cast<uint8_t>((flags() & STP_FLAG_PORT_ROLE_MASK) >> STP_FLAG_PORT_ROLE_SHIFT);
            }

            void port_role(uint8_t role) noexcept {
                flags(static_cast<uint8_t>(
                    (flags() & ~STP_FLAG_PORT_ROLE_MASK)
                  | ((role & 0x03) << STP_FLAG_PORT_ROLE_SHIFT)));
            }

            [[nodiscard]] bool topology_change() const noexcept {
                return (flags() & STP_FLAG_TOPOLOGY_CHANGE) != 0;
            }

            [[nodiscard]] bool proposal() const noexcept {
                return (flags() & STP_FLAG_PROPOSAL) != 0;
            }

            [[nodiscard]] bool learning() const noexcept {
                return (flags() & STP_FLAG_LEARNING) != 0;
            }

            [[nodiscard]] bool forwarding() const noexcept {
                return (flags() & STP_FLAG_FORWARDING) != 0;
            }

            [[nodiscard]] bool agreement() const noexcept {
                return (flags() & STP_FLAG_AGREEMENT) != 0;
            }

            [[nodiscard]] bool topology_change_ack() const noexcept {
                return (flags() & STP_FLAG_TOPOLOGY_CHANGE_ACK) != 0;
            }

        protected:
            [[nodiscard]] uint16_t get_u16(uint32_t off) const noexcept {
                uint16_t v = 0;
                utils::mem::copy(&v, m_origin_view.begin() + off, 2);
                return utils::mem::bswap<uint16_t>(v);
            }

            void put_u16(uint32_t off, uint16_t v) noexcept {
                uint16_t n = utils::mem::bswap<uint16_t>(v);
                utils::mem::copy(m_origin_view.begin() + off, &n, 2);
            }

            [[nodiscard]] uint32_t get_u32(uint32_t off) const noexcept {
                uint32_t v = 0;
                utils::mem::copy(&v, m_origin_view.begin() + off, 4);
                return utils::mem::bswap<uint32_t>(v);
            }

            void put_u32(uint32_t off, uint32_t v) noexcept {
                uint32_t n = utils::mem::bswap<uint32_t>(v);
                utils::mem::copy(m_origin_view.begin() + off, &n, 4);
            }

            [[nodiscard]] uint64_t get_u64(uint32_t off) const noexcept {
                uint64_t v = 0;
                utils::mem::copy(&v, m_origin_view.begin() + off, 8);
                return utils::mem::bswap<uint64_t>(v);
            }

            void put_u64(uint32_t off, uint64_t v) noexcept {
                uint64_t n = utils::mem::bswap<uint64_t>(v);
                utils::mem::copy(m_origin_view.begin() + off, &n, 8);
            }

            /**
             * @brief Leaves the origin view unset so a derived BPDU can
             *        allocate its own header size.
             */
            struct derived_init {};
            explicit STP(derived_init) noexcept {}
    };

    /**
     * @brief IEEE 802.1D Topology Change Notification BPDU (4 octets).
     */
    class STP_TCN : public ProtocolBaseObject {
        public:
            STP_TCN(view v = {}) noexcept {
                dissect(v);
            }

            STP_TCN(uint8_t version_, uint8_t type_) noexcept {
                INIT_HDR

                if (!ok()) {
                    return;
                }

                protocol_id(STP_PROTO_ID);
                version(version_);
                type(type_);
            }

            [[nodiscard]] uint32_t hsize() const noexcept override {
                return STP_TCN_HDR_LEN;
            }
            
            [[nodiscard]] uint16_t protocol_id() const noexcept {
                uint16_t v = 0;
                utils::mem::copy(&v, m_origin_view.begin(), 2);
                return utils::mem::bswap<uint16_t>(v);
            }

            void protocol_id(uint16_t v) noexcept {
                uint16_t n = utils::mem::bswap<uint16_t>(v);
                utils::mem::copy(m_origin_view.begin(), &n, 2);
            }

            [[nodiscard]] uint8_t version() const noexcept { return m_origin_view[2]; }
            void version(uint8_t v) noexcept { m_origin_view[2] = v; }

            [[nodiscard]] uint8_t type() const noexcept { return m_origin_view[3]; }
            void type(uint8_t v) noexcept { m_origin_view[3] = v; }
    };
} // namespace lynx::proto

#include "lynx/protocols/ll/stp/rstp.h"
#include "lynx/protocols/ll/stp/mstp.h"
#include "lynx/protocols/ll/stp/pvst.h"

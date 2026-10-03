// RFC-826
#pragma once

#include "lynx/protocols/il/packet.h"
#include "lynx/core/utils.h"


namespace lynx::proto
{
    icu16 ARP_ETHERTYPE = 0x0806;

    icu32 ARP_HDR_LEN   = 28;

    icu16 ARP_HRD_ETHER = 0x0001;
    icu16 ARP_PRO_IPV4  = 0x0800;

    icu16 ARP_OP_REQUEST = 1;
    icu16 ARP_OP_REPLY   = 2;

    icu8 ARP_HLEN_ETH    = 6;
    icu8 ARP_PLEN_IPV4   = 4;

    /**
     * @brief Address Resolution Protocol (ARP) - Internet Layer classification.
     *
     * @note ARP Classification as Internet Layer:
     *       Although ARP is encapsulated inside Ethernet frames (link layer) and is
     *       sometimes classified as a link-layer protocol, it is placed in the Internet
     *       Layer here because:
     *       1. It operates on network-level addresses (IPv4 addresses), not link-layer
     *       2. It is fundamental to IP communication and address resolution
     *       3. It is logically part of the network architecture, not the physical medium
     *       4. This architecture treats IL as all protocols needed for IP-based networking
     *       
     *       The EtherType 0x0806 in the Ethernet frame identifies ARP as the payload,
     *       making it a peer to IPv4/IPv6 from the media encapsulation perspective.
     */
    class ARP : public Packet {
        public:
            /**
             * @brief Constructs an ARP packet from a byte view.
             * @param v Byte view containing the ARP header.
             */
            ARP(const view& v) noexcept {
                dissect(v);
            }

            /**
             * @brief Constructs an ARP packet with specified fields.
             * @param sha Sender hardware address (MAC).
             * @param spa Sender protocol address (IPv4).
             * @param tha Target hardware address (MAC), defaults to zero.
             * @param tpa Target protocol address (IPv4), defaults to zero.
             * @param oper Operation type, defaults to ARP_OP_REQUEST.
             * @param hrd Hardware type, defaults to ARP_HRD_ETHER.
             * @param pro Protocol type, defaults to ARP_PRO_IPV4.
             */
            ARP(const mn_mac& sha_,
                const mn_ipv4& spa_,
                const mn_mac& tha_ = mn_mac(),
                const mn_ipv4& tpa_ = mn_ipv4(),
                uint16_t oper_ = ARP_OP_REQUEST,
                uint16_t hrd = ARP_HRD_ETHER,
                uint16_t pro = ARP_PRO_IPV4) noexcept {

                INIT_HDR
                
                if (!ok()) {
                    return;
                }

                htype(hrd);
                ptype(pro);
                hlen(ARP_HLEN_ETH);
                plen(ARP_PLEN_IPV4);
                oper(oper_);
                sha(sha_);
                spa(spa_);
                tha(tha_);
                tpa(tpa_);
            }

            /**
             * @brief Constructs an empty ARP packet with default values.
             */
            ARP() noexcept {
                // init header
                dissect(hsize());

                if (!ok()) {
                    return;
                }

                // set attrs
                htype(ARP_HRD_ETHER);
                ptype(ARP_PRO_IPV4);
                hlen(ARP_HLEN_ETH);
                plen(ARP_PLEN_IPV4);
                oper(ARP_OP_REQUEST);
            }

            /**
             * @brief Returns the ARP header length in bytes.
             * @return 28 bytes for Ethernet+IPv4 ARP.
             */
            [[nodiscard]] uint32_t hsize() const noexcept {
                return ARP_HDR_LEN;
            }

            /**
             * @brief Returns the EtherType for ARP.
             * @return 0x0806 (ARP in Ethernet).
             */
            [[nodiscard]] uint16_t ethertype() const noexcept {
                return ARP_ETHERTYPE;
            }

            /**
             * @brief ARP always broadcasts - this overrides Packet's default.
             * @return Always returns true. When true, Interface ignores dst() and
             *         sets the destination MAC to ff:ff:ff:ff:ff:ff.
             */
            [[nodiscard]] bool is_broadcast() const noexcept override {
                return true;
            }

            /**
             * @brief Sets the Hardware Type field (16 bits).
             * @param h Hardware type in host byte order.
             */
            void htype(uint16_t h) noexcept {
                uint16_t net_h = utils::mem::bswap<uint16_t>(h);
                utils::mem::copy(m_origin_view.begin(), &net_h, 2);
            }

            /**
             * @brief Gets the Hardware Type field (16 bits).
             * @return The hardware type in host byte order (0x0001 for Ethernet).
             */
            uint16_t htype() noexcept {
                uint16_t h = 0;
                utils::mem::copy(&h, m_origin_view.begin(), 2);
                return utils::mem::bswap<uint16_t>(h);
            }

            /**
             * @brief Sets the Protocol Type field (16 bits).
             * @param p Protocol type in host byte order.
             */
            void ptype(uint16_t p) noexcept {
                uint16_t net_p = utils::mem::bswap<uint16_t>(p);
                utils::mem::copy(m_origin_view.begin() + 2, &net_p, 2);
            }

            /**
             * @brief Gets the Protocol Type field (16 bits).
             * @return The protocol type in host byte order (0x0800 for IPv4).
             */
            uint16_t ptype() noexcept {
                uint16_t p = 0;
                utils::mem::copy(&p, m_origin_view.begin() + 2, 2);
                return utils::mem::bswap<uint16_t>(p);
            }

            /**
             * @brief Sets the Hardware Address Length field (8 bits).
             * @param h Hardware length.
             */
            void hlen(uint8_t h) noexcept {
                utils::mem::copy(m_origin_view.begin() + 4, &h, 1);
            }

            /**
             * @brief Gets the Hardware Address Length field (8 bits).
             * @return The hardware length (6 for MAC addresses).
             */
            uint8_t hlen() noexcept {
                return m_origin_view[4];
            }

            /**
             * @brief Sets the Protocol Address Length field (8 bits).
             * @param p Protocol length.
             */
            void plen(uint8_t p) noexcept {
                utils::mem::copy(m_origin_view.begin() + 5, &p, 1);
            }

            /**
             * @brief Gets the Protocol Address Length field (8 bits).
             * @return The protocol length (4 for IPv4 addresses).
             */
            uint8_t plen() noexcept {
                return m_origin_view[5];
            }

            /**
             * @brief Sets the Operation field (16 bits).
             * @param o Operation in host byte order.
             */
            void oper(uint16_t o) noexcept {
                uint16_t net_o = utils::mem::bswap<uint16_t>(o);
                utils::mem::copy(m_origin_view.begin() + 6, &net_o, 2);
            }

            /**
             * @brief Gets the Operation field (16 bits).
             * @return The operation (1=Request, 2=Reply).
             */
            uint16_t oper() noexcept {
                uint16_t o = 0;
                utils::mem::copy(&o, m_origin_view.begin() + 6, 2);
                return utils::mem::bswap<uint16_t>(o);
            }

            /**
             * @brief Sets the Sender Hardware Address (MAC).
             * @param a MAC address to set.
             */
            void sha(const mn_mac& a) noexcept {
                utils::mem::copy(m_origin_view.begin() + 8, a.data(), 6);
            }

            /**
             * @brief Gets the Sender Hardware Address (MAC).
             * @return The sender hardware address.
             */
            mn_mac sha() noexcept {
                return mn_mac(m_origin_view.slice(8, 14).data());
            }

            /**
             * @brief Sets the Sender Protocol Address (IPv4).
             * @param a IPv4 address to set.
             */
            void spa(const mn_ipv4& a) noexcept {
                utils::mem::copy(m_origin_view.begin() + 14, a.data(), 4);
            }

            /**
             * @brief Gets the Sender Protocol Address (IPv4).
             * @return The sender protocol address.
             */
            mn_ipv4 spa() noexcept {
                return mn_ipv4(m_origin_view.slice(14, 18).data());
            }

            /**
             * @brief Sets the Target Hardware Address (MAC).
             * @param a MAC address to set.
             */
            void tha(const mn_mac& a) noexcept {
                utils::mem::copy(m_origin_view.begin() + 18, a.data(), 6);
            }

            /**
             * @brief Gets the Target Hardware Address (MAC).
             * @return The target hardware address.
             */
            mn_mac tha() noexcept {
                return mn_mac(m_origin_view.slice(18, 24).data());
            }

            /**
             * @brief Sets the Target Protocol Address (IPv4).
             * @param a IPv4 address to set.
             */
            void tpa(const mn_ipv4& a) noexcept {
                utils::mem::copy(m_origin_view.begin() + 24, a.data(), 4);
            }

            /**
             * @brief Gets the Target Protocol Address (IPv4).
             * @return The target protocol address.
             */
            mn_ipv4 tpa() noexcept {
                return mn_ipv4(m_origin_view.slice(24, 28).data());
            }
    };
} // namespace lynx::proto

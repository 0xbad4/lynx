// RFC-1661
#pragma once

#include "lynx/protocols/ll/frame.h"

namespace lynx::proto
{

    /**
     * @brief Specifies PPP header compression options.
     *
     * Controls compression of the PPP Address/Control and Protocol fields.
     */
    enum ppp_comp {
        NONE = 0,      ///< No header compression.
        ACFC = 1 << 0, ///< Address-and-Control-Field-Compression.
        PFC  = 1 << 1  ///< Protocol-Field-Compression.
    };

    // PPP frame header lengths
    icu32 PPP_HDR_LEN      = 0x0004;
    icu32 PPP_HDR_LEN_ACFC = 0x0002;
    icu32 PPP_HDR_LEN_PFC  = 0x0003;
    icu32 PPP_HDR_LEN_MIN  = 0x0001;

    // fixed field values, present only when ACFC is not negotiated
    icu16 PPP_ADDRESS      = 0xFF;  /// all-stations address (PPP has no real addressing, always this value)
    icu16 PPP_CONTROL      = 0x03;  /// unnumbered information (PPP doesn't use HDLC sequencing, always this value)

    // PPP Protocol field values (identify what the payload carries)
    icu16 PPP_PROTO_IP     = 0x0021;
    icu16 PPP_PROTO_IPV6   = 0x0057;
    icu16 PPP_PROTO_IPCP   = 0x8021;
    icu16 PPP_PROTO_IPV6CP = 0x8057;
    icu16 PPP_PROTO_LCP    = 0xC021;
    icu16 PPP_PROTO_PAP    = 0xC023;
    icu16 PPP_PROTO_CHAP   = 0xC223;
    icu16 PPP_PROTO_EAP    = 0xC227;

    // PPPsp: the Code|Identifier|Length header shared by ppp's subprotocols
    icu32 PPP_SP_HDR_LEN   = 4;

    /**
     * @brief Holds the common header structure for PPP sub-protocols.
     */
    namespace ppp {
        /**
        * @brief Generic base class for PPP sub-protocols.
        *
        * Provides the common header structure shared by PPP sub-protocols.
        *
        * @note Use a protocol-specific class, such as @c PAP, when protocol-specific
        *       functionality is required, such as accessing PAP authentication data.
        */
        class GenCtrl : public ProtocolBaseObject {
            public:
                GenCtrl(const view& v = {}) noexcept {
                    dissect(v);
                }

                /**
                 * @brief Constructs a PPP control subprotocol packet.
                 *
                 * The packet length is calculated automatically from the control header
                 * size and the supplied data length.
                 *
                 * @param c Control code.
                 * @param id Packet identifier.
                 * @param dat Protocol-specific data.
                 */
                GenCtrl(const uint8_t &c, const uint8_t &id, const view &dat) noexcept {
                    uint16_t len = hsize() + dat.size();

                    // allocate
                    dissect(len);

                    if(!ok()) {
                        return;
                    }

                    // set attrs
                    code(c);
                    identifier(id);
                    length(len);

                    // set data
                    utils::mem::copy(origin().begin() + hsize(), dat.begin(), dat.size());
                }

                [[nodiscard]] uint32_t hsize() const noexcept {
                    return PPP_SP_HDR_LEN;
                }

                /**
                 * @brief Validates the PPP subprotocol packet length.
                 * @return @c true if the base protocol is valid and the packet size matches
                 *         the length encoded in the PPP subprotocol header.
                 */
                [[nodiscard]] bool check() noexcept {
                    if (!ProtocolBaseObject::check()) {
                        return false;
                    }
                    
                    return m_origin_view.size() == length();
                }

                /**
                 * @brief Returns the PPP subprotocol identifier.
                 *
                 * The generic implementation does not know which PPP subprotocol is in use
                 * and therefore returns zero. Protocol-specific subclasses should override
                 * this method to return their corresponding PPP protocol identifier.
                 *
                 * @return The PPP protocol identifier, or zero when unspecified.
                 */
                [[nodiscard]] virtual uint16_t protocol() const noexcept {
                    return 0;
                }

                /**
                 * @brief Sets the PPP control subprotocol code field.
                 * @param c Code value.
                 */
                void code(uint8_t c) noexcept {
                    m_origin_view[0] = c;
                }

                /**
                 * @brief Gets the PPP control subprotocol code field.
                 * @return The code value.
                 */
                uint8_t code() noexcept {
                    return m_origin_view[0];
                }

                /**
                 * @brief Sets the PPP control subprotocol identifier field.
                 * @param id Identifier value.
                 */
                void identifier(uint8_t id) noexcept {
                    m_origin_view[1] = id;
                }

                /**
                 * @brief Gets the PPP control subprotocol identifier field.
                 * @return The identifier value.
                 */
                uint8_t identifier() noexcept {
                    return m_origin_view[1];
                }

                /**
                 * @brief Sets the PPP control subprotocol length field.
                 * @param l Length in host byte order.
                 */
                void length(uint16_t l) noexcept {
                    uint16_t ln = utils::mem::bswap<uint16_t>(l);
                    utils::mem::copy(m_origin_view.begin() + 2, &ln, 2);
                }

                /**
                 * @brief Gets the PPP control subprotocol length field.
                 * @return The length in host byte order.
                 */
                uint16_t length() noexcept {
                    uint16_t l = 0;
                    utils::mem::copy(&l, m_origin_view.begin() + 2, 2);
                    return utils::mem::bswap<uint16_t>(l);
                }
        };
    }

    /**
     * @brief Represents a PPP frame.
     *
     * Provides access to the PPP header fields and manages the header compression
     * state for Address-and-Control-Field-Compression (ACFC) and Protocol-Field-Compression (PFC).
     * 
     * @note The PPP protocol is detected automatically during patching if upperlayer is a PPP subprotocol that inherits from @c ppp::GenCtrl.
     * 
     * @note The Address and Control fields are protocol constants and are omitted when ACFC is enabled. 
     * 
     * @note The Protocol field is compressed when PFC is enabled.
     */
    class PPP : public Frame {
        public:
            PPP(const view& v) noexcept { 
                // detect compression BEFORE dissect(), its bounds check reads
                // hsize(), which depends on m_comp_type being set already
                bool acfc = !(v.size() >= 2 && v[0] == PPP_ADDRESS && v[1] == PPP_CONTROL);

                uint32_t proto_off = acfc ? 0 : 2;
                // real protocol numbers always have an odd low byte (0x0021, 0xC021, 0x8057, ...)
                // a compressed single-byte field IS that odd byte
                bool pfc = v.size() > proto_off && (v[proto_off] & 0x01);

                if (acfc && pfc)  { 
                    m_comp_type = (ppp_comp)(ppp_comp::ACFC | ppp_comp::PFC); 
                }
                else if (acfc)    { 
                    m_comp_type = ppp_comp::ACFC; 
                }
                else if (pfc)     { 
                    m_comp_type = ppp_comp::PFC; 
                }
                else              { 
                    m_comp_type = ppp_comp::NONE; 
                }

                dissect(v);
            }

            /**
             * @brief Constructs a PPP frame with the specified header compression.
             *
             * The PPP protocol is detected automatically during patching. The Address and
             * Control fields are protocol constants and are omitted when ACFC is enabled.
             * The Protocol field is compressed when PFC is enabled.
             *
             * @param ct PPP header compression mode.
             */
            PPP(ppp_comp ct = ppp_comp::NONE) noexcept : m_comp_type(ct) {
                INIT_HDR

                if (!ok()) {
                    return;
                }

                // set attrs
                address(PPP_ADDRESS);
                control(PPP_CONTROL);
            }

            /**
             * @brief Returns the PPP header size for the configured compression mode.
             *
             * @return The PPP header size in bytes.
             */
            [[nodiscard]] uint32_t hsize() const noexcept {
                if (is_minimal()) { 
                    return PPP_HDR_LEN_MIN;
                }

                if (is_acfc()) { 
                    return PPP_HDR_LEN_ACFC;
                }

                if (is_pfc()) { 
                    return PPP_HDR_LEN_PFC;
                }

                return PPP_HDR_LEN;
            }

            [[nodiscard]] frame_type type() const noexcept {
                return frame_type::PPP;
            }

            /**
             * @brief Sets the PPP address field.
             * @param a Address value.
             */
            void address(uint8_t a) noexcept {
                if (is_acfc()) {
                    return;
                }
                m_origin_view[0] = a;
            }

            /**
             * @brief Gets the PPP address field.
             * @return The address value.
             */
            uint8_t address() noexcept {
                if (is_acfc()) {
                    return 0;
                }
                return m_origin_view[0];
            }

            /**
             * @brief Sets the PPP control field.
             * @param c Control value.
             */
            void control(uint8_t c) noexcept {
                if (is_acfc()) {
                    return;
                }
                m_origin_view[1] = c;
            }

            /**
             * @brief Gets the PPP control field.
             * @return The control value.
             */
            uint8_t control() noexcept {
                if (is_acfc()) {
                    return 0;
                }
                return m_origin_view[1];
            }

            /**
             * @brief Sets the PPP protocol field.
             * @param p Protocol value in host byte order.
             */
            void protocol(uint16_t p) noexcept {
                uint32_t off = is_acfc() ? 0 : 2;

                if (is_pfc()) {
                    uint8_t p8 = static_cast<uint8_t>(p);
                    utils::mem::copy(m_origin_view.begin() + off, &p8, 1);
                }
                else {
                    uint16_t np = utils::mem::bswap<uint16_t>(p);
                    utils::mem::copy(m_origin_view.begin() + off, &np, 2);
                }
            }

            /**
             * @brief Gets the PPP protocol field.
             * @return The protocol value in host byte order.
             */
            uint16_t protocol() const noexcept {
                uint32_t off = is_acfc() ? 0 : 2;

                if (is_pfc()) {
                    return m_origin_view[off];
                }

                uint16_t np = 0;
                utils::mem::copy(&np, m_origin_view.begin() + off, 2);
                return utils::mem::bswap<uint16_t>(np);
            }

            /**
             * @brief Returns the PPP header compression mode.
             *
             * @return The configured PPP header compression mode.
             */
            ppp_comp compress() const noexcept {
                return m_comp_type;
            }

            /**
             * @brief Checks whether Address-and-Control-Field-Compression is enabled.
             *
             * @return @c true if ACFC is enabled; @c false otherwise.
             */
            bool is_acfc() const noexcept {
                return (m_comp_type&ppp_comp::ACFC) != 0;
            }
    
            /**
             * @brief Checks whether Protocol-Field-Compression is enabled.
             *
             * @return @c true if PFC is enabled; @c false otherwise.
             */
            bool is_pfc() const noexcept {
                return (m_comp_type&ppp_comp::PFC) != 0;
            }
    
            /**
             * @brief Checks whether both PPP header compression modes are enabled.
             *
             * @return @c true if both ACFC and PFC are enabled; @c false otherwise.
             */
            bool is_minimal() const noexcept {
                return m_comp_type == (ppp_comp::ACFC | ppp_comp::PFC);
            }
    
        protected:
            ppp_comp m_comp_type = ppp_comp::NONE;

            /**
             * @brief Patches the PPP protocol field in the provided buffer.
             *
             * If the protocol field is already set, it is not modified. Otherwise, if the
             * upper layer is a PPP subprotocol, its protocol identifier is used to update
             * the protocol field in both the PPP object and the buffer.
             *
             * @param buffer Buffer containing the PPP frame to patch.
             * @param hoff   Offset of the PPP header within the buffer.
             */
            void patch(Buffer& buffer, uint32_t hoff) const noexcept {
                if (protocol() != 0) {
                    return; // already set, respect it, don't override
                }

                auto* sub = dynamic_cast<ppp::GenCtrl*>(m_upperlayer_ptr);

                if (!sub) {
                    return; // upperlayer isn't one of ours (e.g. raw IPv4/IPv6), nothing to detect
                }

                uint16_t proto = sub->protocol();

                // update buffer (network order)
                uint32_t off = hoff + (is_acfc() ? 0 : 2);

                if (is_pfc()) {
                    uint8_t proto8 = proto & 0x00FF;
                    buffer.patch(off, &proto8, 1);
                }
                else {
                    proto = utils::mem::bswap<uint16_t>(proto);
                    buffer.patch(off, reinterpret_cast<const uint8_t*>(&proto), sizeof(proto));
                }
            }
    };

} // namespace lynx::proto

// RFC-3748
#pragma once

#include "lynx/protocols/ll/frame.h"


namespace lynx::proto
{
    icu32 EAP_HDR_LEN      = 0x0004;
    
    // Codes
    icu8 EAP_CODE_REQUEST  = 1;
    icu8 EAP_CODE_RESPONSE = 2;
    icu8 EAP_CODE_SUCCESS  = 3;
    icu8 EAP_CODE_FAILURE  = 4;
    icu8 EAP_CODE_INITIATE = 5;
    icu8 EAP_CODE_FINISH   = 6;

    // Types (IANA)
    icu8 EAP_TYPE_IDENTITY     = 1;
    icu8 EAP_TYPE_NOTIFICATION = 2;
    icu8 EAP_TYPE_LEGACY_NAK   = 3;
    icu8 EAP_TYPE_MD5          = 4;
    icu8 EAP_TYPE_OTP          = 5;
    icu8 EAP_TYPE_GTC          = 6;
    icu8 EAP_TYPE_TLS          = 13;
    icu8 EAP_TYPE_SIM          = 18;
    icu8 EAP_TYPE_TTLS         = 21;
    icu8 EAP_TYPE_AKA          = 23;
    icu8 EAP_TYPE_PEAP         = 25;
    icu8 EAP_TYPE_FAST         = 43;
    icu8 EAP_TYPE_PSK          = 47;
    icu8 EAP_TYPE_AKA_PRIME    = 50;
    icu8 EAP_TYPE_GPSK         = 51;
    icu8 EAP_TYPE_PWD          = 52;
    icu8 EAP_TYPE_TEAP         = 55;
    icu8 EAP_TYPE_NOOB         = 56;
    icu8 EAP_TYPE_EDHOC        = 57;

    class EAP : public ProtocolBaseObject {
        public:
            EAP(const view& v = {}) noexcept {
                dissect(v);
            }

            /**
             * @brief Constructs an EAP packet with an optional Type and Type-Data field.
             *
             * The packet length is calculated automatically from the EAP header and,
             * when present, the Type and Type-Data fields.
             *
             * @param c EAP Code value.
             * @param id EAP Identifier value.
             * @param t EAP Type value, or zero to omit the Type field.
             * @param dat EAP Type-Data field.
             */
            EAP(const uint8_t &c, const uint8_t &id, uint8_t t = 0, view dat = {}) {
                // allocate: HDR-SIZE(4) + TYPE(1) + VALUE(~)
                uint16_t len  = hsize();
                bool has_data = t && dat.ok();

                if (has_data) {
                    len += 1 + dat.size();
                }
                // allocate
                dissect(len);

                if (!ok()) {
                    return;
                }

                // set attrs
                code(c);
                identifier(id);
                length(len);

                // set data
                if (has_data) {
                    uint32_t off = hsize();
                    m_origin_view[off++] = t;
                    
                    utils::mem::copy(m_origin_view.begin() + off, dat.begin(), dat.size());
                }
            }

            uint32_t hsize() const noexcept {
                return EAP_HDR_LEN;
            }
            
            /**
             * @brief Sets the EAP code field.
             * @param c Code value.
             */
            void code(uint8_t c) noexcept {
                m_origin_view[0] = c;
            }

            /**
             * @brief Gets the EAP code field.
             * @return The EAP code.
             */
            uint8_t code() noexcept {
                return m_origin_view[0];
            }

            /**
             * @brief Sets the EAP identifier field.
             * @param id Identifier value.
             */
            void identifier(uint8_t id) noexcept {
                m_origin_view[1] = id;
            }

            /**
             * @brief Gets the EAP identifier field.
             * @return The EAP identifier.
             */
            uint8_t identifier() noexcept {
                return m_origin_view[1];
            }

            /**
             * @brief Sets the EAP length field.
             * @param l Length in host byte order.
             */
            void length(uint16_t l) noexcept {
                uint16_t ln = utils::mem::bswap<uint16_t>(l);
                utils::mem::copy(m_origin_view.begin() + 2, &ln, 2);
            }

            /**
             * @brief Gets the EAP length field.
             * @return The length in host byte order.
             */
            uint16_t length() noexcept {
                uint16_t l = 0;
                utils::mem::copy(&l, m_origin_view.begin() + 2, 2);
                return utils::mem::bswap<uint16_t>(l);
            }

            /**
             * @brief Sets the EAP type field.
             * @param t Type value.
             */
            void type(uint8_t t) {
                m_origin_view[hsize()] = t;
            }

            /**
             * @brief Gets the EAP type field.
             * @return The EAP type.
             */
            uint8_t type() {
                return m_origin_view[hsize()];
            }

            /**
             * @brief Gets the EAP type-data field.
             * @return The EAP type-data field as a view.
             */
            [[nodiscard]] view data() {
                return m_origin_view.last(hsize() + 1);
            }
    };

    namespace eap
    {
        /**
         * @brief Legacy EAP-Nak Type-Data (Type 3), response only.
         *
         * A flat list of Type octets the peer is willing to use instead,
         * one byte per desired type, no length prefixes, no substructure.
         */
        class NAK : public ProtocolBaseObject {
            public:
                /**
                 * @brief Constructs an EAP-Nak object from the loaded payload.
                 *
                 * @param v View of the payload to dissect.
                 * 
                 * @note Does not copy the payload; the view must remain valid for the lifetime of this object.
                 */
                NAK(const view& v = {}) {
                    dissect(v);
                }

                [[nodiscard]] uint32_t hsize() const noexcept override { 
                    return 0;
                }

                /**
                 * @brief Returns the list of acceptable EAP types in this NAK payload.
                 * @return Type list bytes.
                 */
                [[nodiscard]] view types() const noexcept {
                    return origin();
                }

                /// @return How many desired types are listed.
                [[nodiscard]] uint32_t count() const noexcept { 
                    return static_cast<uint32_t>(m_origin_view.size()); 
                }

                /// @return The Type value at position @p i, or 0 if @p i is out of range.
                [[nodiscard]] uint8_t type_at(uint32_t i) const noexcept {
                    return (i < count()) ? m_origin_view[i] : 0;
                }
        };
    } // namespace eap
    
    
} // namespace lynx::proto

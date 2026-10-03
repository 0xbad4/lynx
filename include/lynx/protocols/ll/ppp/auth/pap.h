// RFC-1334
#pragma once

#include "lynx/protocols/ll/ppp/ppp.h"

namespace lynx::proto 
{
    // Code values
    icu8 PAP_CODE_AUTH_REQ = 1;
    icu8 PAP_CODE_AUTH_ACK = 2;
    icu8 PAP_CODE_AUTH_NAK = 3;
    
    /**
     * @note This class deliberately has no field setters beyond construction.
     *       Every field after the header is length-prefixed and positional
     *       (PAP's Password sits wherever Peer-ID's length says it ends,
     *       CHAP's Name wherever Value ends, and so on) - changing one after
     *       the fact means shifting every field that follows it, which is a
     *       lot of memory movement for comparatively little benefit. Setting
     *       every field once at construction, in order, sidesteps that
     *       entirely: nothing has moved yet, so there's nothing to shift.
     */
    class PAP : public ppp::GenCtrl::GenCtrl {
        public:
            using ppp::GenCtrl::GenCtrl;

            /**
             * @brief Constructs a PAP authentication packet.
             *
             * The packet length is calculated automatically from the PAP header,
             * peer identifier, and password fields.
             *
             * @param c PAP Code value.
             * @param id PAP Identifier value.
             * @param pi Peer identifier.
             * @param pw Password.
             */
            PAP(const uint8_t &c, const uint8_t &id, const view &pi, const view &pw) {
                // HDR-SIZE(4) + PEERID-SIZE(1) + PEERID(~) + PASSWORD-SIZE(1) + PASSWORD(~)
                uint16_t len = hsize() + 1 + pi.size() + 1 + pw.size();

                dissect(len);

                if (!ok()) {
                    return;
                }

                // set attr
                code(c);
                identifier(id);
                length(len);

                // set params
                uint32_t off = hsize();

                // - peer-id size
                m_origin_view[off++] = pi.size();

                // - peer id
                utils::mem::copy(origin().begin() + off, pi.begin(), pi.size());
                off += pi.size();

                // - password size
                m_origin_view[off++] = pw.size();

                // - password
                utils::mem::copy(origin().begin() + off, pw.begin(), pw.size());
            }

            [[nodiscard]] uint16_t protocol() const noexcept override {
                return PPP_PROTO_PAP;
            }

            /**
             * @brief Returns the Peer-ID field of an Authenticate-Request.
             *
             * @return The Peer-ID bytes, or an invalid view if the packet is
             *         too short to contain one.
             */
            [[nodiscard]] view peer_id() const noexcept {
                uint32_t off = hsize();

                if (m_origin_view.size() < off + 1) {
                    return view(Error::make(status::MalformedPacket, "pap: packet too short for Peer-ID-Length"));
                }

                uint8_t len = m_origin_view[off++];

                if (off + len > m_origin_view.size()) {
                    return view(Error::make(status::MalformedPacket, "pap: Peer-ID runs past end of packet"));
                }

                return m_origin_view.slice(off, off + len);
            }

            /**
             * @brief Returns the Password field of an Authenticate-Request.
             *
             * Depends on peer_id() to know where the Password-Length byte
             * starts - PAP's fields are positional, not addressable on their
             * own the way a TLV's are.
             *
             * @return The Password bytes, or an invalid view if peer_id()
             *         fails or the packet is too short to contain a password.
             */
            [[nodiscard]] view password() const noexcept {
                view id = peer_id();

                if (!id.ok()) {
                    return view(Error::make(status::MalformedPacket, "pap: peer-id invalid"));
                }

                uint32_t off = hsize() + 1 + static_cast<uint32_t>(id.size());

                if (m_origin_view.size() < off + 1) {
                    return view(Error::make(status::MalformedPacket, "pap: packet too short for Password-Length"));
                }
                uint8_t len = m_origin_view[off++];

                if (off + len > m_origin_view.size()) {
                    return view(Error::make(status::MalformedPacket, "pap: Password runs past end of packet"));
                }

                return m_origin_view.slice(off, off + len);
            }

            [[nodiscard]] bool is_request() noexcept {
                return code() == PAP_CODE_AUTH_REQ;
            }

            [[nodiscard]] bool is_auth_response() noexcept {
                uint8_t c = code();
                return c == PAP_CODE_AUTH_ACK || c == PAP_CODE_AUTH_NAK; 
            }
    };
}
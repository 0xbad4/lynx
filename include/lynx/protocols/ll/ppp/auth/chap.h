// RFC-1994
#pragma once

#include "lynx/protocols/ll/ppp/ppp.h"

namespace lynx::proto
{
    // Code values
    icu8 CHAP_CODE_CHALLENGE = 1;
    icu8 CHAP_CODE_RESPONSE  = 2;
    icu8 CHAP_CODE_SUCCESS   = 3;
    icu8 CHAP_CODE_FAILURE   = 4;
    
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
    class CHAP : public ppp::GenCtrl {
        public:
            using ppp::GenCtrl::GenCtrl;

            /**
             * @brief Constructs a CHAP packet with a fixed value and name.
             *
             * The value and name fields are initialized during construction and cannot
             * be modified afterward. The packet length is calculated automatically.
             *
             * @param c CHAP Code value.
             * @param id CHAP Identifier value.
             * @param val CHAP value field.
             * @param nm CHAP name field.
             */
            CHAP(const uint8_t &c, const uint8_t &id, const view &val, const view &nm) {
                // allocate: HDR(4) + VALUE-SIZE(1) + VALUE(~) + NAME(~)       
                uint16_t len = hsize() + 1 + val.size() + nm.size();
                
                dissect(len);

                if (!ok()) {
                    return;
                }

                // set attrs
                code(c);
                identifier(id);
                length(len);

                // set payload
                uint32_t off = hsize();

                // - value size
                m_origin_view[off++] = static_cast<uint8_t>(val.size());
                
                // - value
                utils::mem::copy(origin().begin() + off, val.begin(), val.size());
                off += val.size();

                // - name
                utils::mem::copy(origin().begin() + off, nm.begin(), nm.size());
            }

            [[nodiscard]] uint16_t protocol() const noexcept override {
                return PPP_PROTO_CHAP;
            }

            /**
             * @brief Returns the Value field of a Challenge or Response packet.
             *
             * @return The Value bytes, or an invalid view if the packet is
             *         too short to contain one.
             */
            [[nodiscard]] view value() const noexcept {
                uint32_t off = hsize();

                if (m_origin_view.size() < off + 1) {
                    return {};
                }

                uint8_t len = m_origin_view[off++];

                if (off + len > m_origin_view.size()) {
                    return {};
                }

                return m_origin_view.slice(off, off + len);
            }

            /**
             * @brief Returns the Name field of a Challenge or Response packet.
             *
             * Name has no length prefix of its own — it runs from right
             * after value() to the packet's own declared Length, so this
             * depends on both value() and length() to find its bounds.
             *
             * @return The Name bytes, or an invalid view if value() fails or
             *         the declared Length doesn't leave room for one.
             */
            [[nodiscard]] view name() noexcept {
                view val = value();

                if (!val.ok()) {
                    return {};
                }

                uint32_t off   = hsize() + 1 + static_cast<uint32_t>(val.size());
                uint16_t total = length();

                if (total < off || total > m_origin_view.size()) {
                    return {};
                }
                
                return m_origin_view.slice(off, total);
            }

            /**
             * @brief Is it a challenge packet.
             * 
             * @returns Yes or NO.
             */
            [[nodiscard]] bool is_challenge() noexcept {
                return code() == CHAP_CODE_CHALLENGE;
            }

            /**
             * @brief Is it a response packet.
             * 
             * @returns Yes or NO.
             */
            [[nodiscard]] bool is_response() noexcept {
                return code() == CHAP_CODE_RESPONSE;
            }

            /**
             * @brief Is it a success packet.
             * 
             * @returns Yes or NO.
             */
            [[nodiscard]] bool is_success() noexcept {
                return code() == CHAP_CODE_SUCCESS;
            }

            /**
             * @brief Is it a failure packet.
             * 
             * @returns Yes or NO.
             */
            [[nodiscard]] bool is_failure() noexcept {
                return code() == CHAP_CODE_FAILURE;
            }
    };
}
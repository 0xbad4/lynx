#pragma once


#include "lynx/core/base/proto.h"

namespace lynx::proto
{
    /**
     * @brief Represents a single TLV node.
     *
     * Extends @c view to provide access to the TLV type code and length fields.
     *
     */
    class tlv_node : public view {
        public:
            using view::view;

            /**
             * @brief Returns the TLV type code.
             * @return The one-byte tag value identifying the TLV field.
             */
            [[nodiscard]] uint8_t code() const noexcept {
                return (*this)[0];
            }

            /**
             * @brief Returns the TLV value length field.
             * @return The one-byte length of the value portion stored in this TLV node.
             */
            [[nodiscard]] uint8_t length() const noexcept {
                return (*this)[1];
            }
    };

    // Conceptually like a protocol
    class TLV : public ProtocolBaseObject {
        public:
            /**
             * @brief Constructs an invalid TLV object.
             *
             * Initializes the object with a malformed-packet error. No protocol header
             * is allocated because the object does not represent a valid TLV node.
             */
            TLV() {
                set_error(status::MalformedPacket, nullptr);
            }
            /**
             * @brief Constructs a TLV buffer from an array of TLV nodes.
             *
             * Calculates the total size of all supplied nodes, allocates a contiguous
             * buffer of exactly that size, and copies each node into the buffer in order.
             *
             * @param head Array of TLV nodes to concatenate.
             * @param size Number of nodes in the array.
             *
             * @note The node data is copied into newly allocated storage; the constructed
             *       TLV object does not depend on the lifetime of the input nodes.
             */
            TLV(tlv_node* head, uint32_t size) {
                // 1. total size across every node, back to back
                uint32_t total = 0;

                for (uint32_t i = 0; i < size; ++i) {
                    total += static_cast<uint32_t>(head[i].size());
                }

                // 2. allocate exactly that many bytes - hsize() is 0, so the
                //    ordinary dissect(view{}) path would allocate nothing
                dissect(total);

                if (!ok()) {
                    return;
                }

                // 3. copy every node's bytes into place
                uint32_t offset = 0;

                for (uint32_t i = 0; i < size; ++i) {
                    utils::mem::copy(m_origin_view.begin() + offset, head[i].data(), head[i].size());
                    
                    offset += static_cast<uint32_t>(head[i].size());
                }
            }

            /**
             * @brief Constructs a TLV container from an existing byte view.
             * @param v Source bytes containing one or more TLV entries.
             */
            TLV(view v) {
                dissect(v);
            }

            /**
             * @brief Returns the total number of bytes currently stored by this TLV object.
             * @return Total size in bytes.
             */
            [[nodiscard]] uint32_t size() const noexcept {
                // override when setters included
                return ProtocolBaseObject::size();
            }

            /**
             * @brief Loads a TLV buffer into this object.
             * @param buf Buffer to load.
             */
            void load(Buffer& buf) noexcept {
                // override when setters included
                return ProtocolBaseObject::load(buf);
            }

            /**
             * @brief Returns the fixed header size of the TLV container.
             * @return Always 0, because this container stores a variable-length sequence of TLV entries.
             */
            [[nodiscard]] uint32_t hsize() const noexcept {
                return 0;
            }

            /**
             * @brief Looks up a TLV by its type code.
             *
             * Returns a view of the TLV value when the requested type is found.
             * This class does not set errors directly. If the lookup encounters a
             * malformed TLV, an empty view carrying the corresponding error is returned.
             *
             * @return A view of the TLV value, or an empty view carrying an error if
             *         the lookup fails.
             */
            [[nodiscard]] view get(uint8_t c) {
                // save previous state
                uint32_t offset_    = m_offset;
                tlv_node current_   = m_current;
                bool     malformed_ = m_malformed;

                reset();

                view result{};

                while (next()) {
                    bool ok_;
                    tlv_node target = current(&ok_);
                    
                    if (target.code() == c) {
                        result = target.last(2);  // strip code and length
                        break;
                    }
                }

                // loop ended without finding it, find out why
                if (result.data() == nullptr) {
                    // check if ended due to an error
                    bool ok_;
                    current(&ok_);

                    if (!ok_) {
                        result = view(Error::make(status::MalformedPacket, "tlv: malformed entry"));
                    }
                }

                // restore previous state
                m_offset    = offset_;
                m_current   = current_;
                m_malformed = malformed_;

                return result;
            }
    
            /**
             * @brief Advances to the next entry.
             *
             * @return @c true if there was a next entry - call current() to get
             *         it. @c false once there's nothing left to advance to, or
             *         once a claimed length has run past the available data;
             *         current() still holds the last valid entry either way, and
             *         current()'s ok parameter tells those two cases apart.
             * @code
             * while(opts.next()) {
             *      auto tlv = opts.current();
             * }
             * opts.reset();
             * @endcode
             */
            bool next() noexcept {
                if (m_offset + 2 > m_origin_view.size()) {
                    return false; // nothing more, current_ stays as the last valid entry
                }

                uint8_t len = m_origin_view[m_offset + 1];

                if (len < 2 || m_offset + len > m_origin_view.size()) {
                    m_malformed = true;
                    return false; // current_ stays put, this bad entry is never made current
                }

                m_current = tlv_node(m_origin_view.begin() + m_offset, len);
                m_offset += len;
                
                return true;
            }

            /**
             * @brief Returns the current entry without advancing.
             *
             * @param ok If non-null: set to @c true for a normal entry or for
             *           having reached the end cleanly. Set to @c false only
             *           once next() has hit a claimed length that ran past the
             *           available data.
             * @return The current entry.
             */
            tlv_node current(bool* ok = nullptr) const noexcept {
                if (ok) *ok = !m_malformed;
                return m_current;
            }

            /**
             * @brief Resets traversal to the first entry.
             */
            void reset() noexcept {
                m_offset    = 0;
                m_current   = tlv_node{};
                m_malformed = false;
            }

        protected:
            uint32_t m_offset = 0;
            tlv_node m_current;
            bool     m_malformed = false;
    };
} // namespace lynx::proto

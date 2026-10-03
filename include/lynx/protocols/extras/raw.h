#pragma once

#include "lynx/core/base/proto.h"


namespace lynx::proto
{
    /**
     * @brief Opaque byte payload with no header of its own.
     *
     * hsize() is always 0 - the entire origin view is payload. Used both as
     * the entry point for a captured frame (before any layer has been
     * interpreted) and as an explicit payload attached at the top of a
     * crafted chain.
     * 
     * @note operator/ is kept for consistency with other protocol layers, but it has no effect on a Raw object. The entire origin view is always treated as payload.
     */
    class Raw : public ProtocolBaseObject {
        public:
            /**
             * @brief Constructs an empty object with no data.
             *
             * Used by get<T>(), which default-constructs T before calling
             * dissect() on it separately.
             */
            Raw() = default;

            /**
             * @brief Constructs an object already carrying an error.
             *
             * No data is set - m_origin_view stays empty. Used to propagate a
             * failure from an earlier step (e.g. a failed Buffer allocation) into a
             * Raw the caller can still return, with ok()/errmsg() reporting it.
             *
             * @param err Error to carry.
             */
            explicit Raw(Error err) noexcept {
                absorb(err);
            }

            /**
             * @brief Constructs from an existing shared allocation without copying.
             *
             * Shares ownership of @p owner directly - unlike set()/the raw-pointer
             * constructor, no copy is made. Useful when the caller already holds a
             * shared_ptr (e.g. from Buffer::owner()) and wants Raw to reference it in
             * place.
             *
             * @param owner  Shared ownership of the underlying allocation.
             * @param offset Byte offset within @p owner where this Raw's data begins.
             * @param len    Number of bytes.
             */
            Raw(ushared8_ptr owner, uint32_t offset, uint32_t len) noexcept {
                m_owner = std::move(owner);
                m_origin_view = { m_owner.get() + offset, len };
            }

            /**
             * @brief Constructs from a captured view.
             *
             * Equivalent to default-constructing and then calling dissect(v).
             *
             * @param v View containing the raw data. Not copied.
             */
            explicit Raw(view v) noexcept { 
                dissect(v); 
            }

            /**
             * @brief Constructs from a null-terminated string.
             *
             * The string's bytes are copied; @p s does not need to remain valid
             * afterward.
             *
             * @param s Null-terminated byte sequence.
             */
            Raw(char* s) noexcept {
                set(view(reinterpret_cast<uint8_t*>(s), std::strlen(s)));
            }

            /**
             * @brief Constructs from a raw byte buffer.
             *
             * The buffer's bytes are copied; @p data does not need to remain
             * valid afterward.
             *
             * @param data Pointer to the source bytes.
             * @param len  Number of bytes.
             */
            Raw(uint8_t* data, size_t len) noexcept {
                set(view(data, len));
            }

            virtual ~Raw() = default;

            /**
             * @return Always 0 - a Raw object has no header, only payload.
             */
            uint32_t hsize() const noexcept override { 
                return 0;
            }

            /**
             * @param v Unused.
             * @return Always @c true - any byte sequence is a valid Raw payload.
             */
            bool check() noexcept {
                return true;
            }

            /**
             * @return View of this object's payload bytes.
             */
            [[nodiscard]] view data() const noexcept {
                return origin();
            }

            /**
             * @brief Replaces this object's payload.
             *
             * Copies @p data into a newly allocated Buffer; @p data does not need to
             * remain valid afterward. Passing an empty view clears the current
             * payload.
             *
             * @param data Source bytes to copy.
             *
             * @note Sets status::BufferAllocFail if allocation fails.
             */
            void set(view data) noexcept {
                if (data.empty()) {
                    m_origin_view = {};
                    return;
                }

                Buffer buffer = Buffer::alloc(static_cast<uint32_t>(data.size()));
                
                if (!buffer.valid()) {
                    set_error(status::BufferAllocFail, "raw: alloc failed");
                    return;
                }

                buffer.write(data.data(), static_cast<uint32_t>(data.size()));

                m_owner       = buffer.owner();
                m_origin_view = buffer.aspan();
            }

            /**
             * @brief Detects the link-layer frame type of this raw frame.
             *
             * @return The detected frame type, or @c frame_type::Unknown if the frame
             *         is too short to contain an Ethernet header.
             */
            frame_type ftype() noexcept {
                return ftype(*this);
            }

            /**
             * @brief Best-effort detection of the link-layer frame type.
             *
             * Inspects the EtherType field of the raw Ethernet frame and returns the
             * corresponding frame type when recognized. Unknown or unsupported
             * EtherTypes are treated as standard Ethernet.
             *
             * @param raw Raw protocol frame to inspect.
             * @return The detected frame type, or @c frame_type::Unknown when the
             *         frame is too short to contain an Ethernet header.
             *
             * @note Detection is best-effort and does not perform complete protocol
             *       validation.
            */
            static frame_type ftype(const lynx::proto::Raw& raw) noexcept {
                view v = raw.origin();

                if (v.size() < 14)
                    return frame_type::Unknown;

                uint16_t t12 = 0;
                utils::mem::copy(&t12, v.begin() + 12, 2);
                t12 = utils::mem::bswap<uint16_t>(t12);

                switch (t12) {
                    case 0x0800: return frame_type::Eth;    // IPv4
                    case 0x0806: return frame_type::Eth;    // ARP
                    case 0x86DD: return frame_type::Eth;    // IPv6
                    case 0x8100: return frame_type::Dot1Q;
                    case 0x88A8: return frame_type::QinQ;
                    case 0x8863:
                    case 0x8864: return frame_type::PPPoE;

                    default:     return frame_type::Unknown;
                }
            }
    };
} // namespace lynx::proto

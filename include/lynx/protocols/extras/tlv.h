#pragma once

#include "lynx/core/base/proto.h"

namespace lynx::proto
{
    /**
     * @brief A single type-length-value entry, viewed in place.
     *
     * The length byte counts the whole entry: type, length and value.
     * An invalid node represents an absent or malformed entry.
     */
    class tlv_node : public view {
        public:
            using view::view;

            /**
             * @brief Returns the type code.
             * @return The type code, or 0 for an invalid node.
             */
            [[nodiscard]] uint8_t code() const noexcept {
                return size() >= 2 ? (*this)[0] : 0;
            }

            /**
             * @brief Returns the length byte.
             * @return Entry size in bytes including the type and length bytes, or 0 for an invalid node.
             */
            [[nodiscard]] uint8_t length() const noexcept {
                return size() >= 2 ? (*this)[1] : 0;
            }

            /**
             * @brief Returns the number of value bytes.
             * @return Value size in bytes, or 0 for an empty value or an invalid node.
             */
            [[nodiscard]] uint8_t vsize() const noexcept {
                return size() >= 2 ? static_cast<uint8_t>(size() - 2) : 0;
            }

            /**
             * @brief Returns the value bytes.
             * @return A view of the value, or an invalid view when the value is empty.
             */
            [[nodiscard]] view value() const noexcept {
                return size() > 2 ? last(2) : view();
            }
    };

    /**
     * @brief Contiguous list of type-length-value entries.
     *
     * Entries are stored back to back in a single allocation. Capacity grows
     * geometrically and is never released by removal. Appending within capacity
     * invalidates nothing. Reallocation invalidates every pointer and view into
     * the list. Removal invalidates those at or after the first removed entry.
     *
     * A list constructed from a view borrows the bytes until its first mutation,
     * which copies them into owned storage. Copies own their bytes; moves
     * transfer them and leave the source empty.
     *
     * Mutators return an Error and leave the list unchanged on failure.
     */
    class TLV : public ProtocolBaseObject {
        private:
            uint32_t m_offset = 0;
            tlv_node m_current;
            bool     m_malformed = false;

            uint32_t m_cap     = 0;
            bool     m_checked = false;

            [[nodiscard]] uint32_t len() const noexcept {
                return static_cast<uint32_t>(m_origin_view.size());
            }

            [[nodiscard]] uint8_t* base() const noexcept {
                return m_owner ? m_owner.get() : m_origin_view.data();
            }

            void steal(TLV& o) noexcept {
                clear_error();

                if (!o.BaseObject::ok()) {
                    absorb(o.BaseObject::error());
                }

                m_owner       = std::move(o.m_owner);
                m_origin_view = o.m_origin_view;
                m_cap         = o.m_cap;
                m_checked     = o.m_checked;
                m_offset      = o.m_offset;
                m_current     = o.m_current;
                m_malformed   = o.m_malformed;

                o.m_owner.reset();
                o.m_origin_view = view();
                o.m_cap         = 0;
                o.m_checked     = true;
                o.reset();
            }

            [[nodiscard]] bool wellformed() noexcept {
                if (m_checked) {
                    return true;
                }

                const uint8_t* b   = base();
                const uint32_t n   = len();
                uint32_t       off = 0;

                while (off < n) {
                    if (n - off < 2) {
                        return false;
                    }

                    const uint8_t l = b[off + 1];

                    if (l < 2 || l > n - off) {
                        return false;
                    }
                    off += l;
                }
                m_checked = true;
                return true;
            }

            [[nodiscard]] Error reallocate(uint32_t cap) noexcept {
                Buffer b = Buffer::alloc(cap);

                if (!b.valid()) {
                    return Error::make(status::BufferAllocFail, "tlv: allocation failed");
                }

                uint8_t*       dst = b.aspan().data();
                const uint32_t n   = len();

                if (n) {
                    utils::mem::copy(dst, m_origin_view.data(), n);
                }

                m_owner       = b.owner();
                m_cap         = cap;
                m_origin_view = n ? view(dst, n) : view();

                return Error::none();
            }

            [[nodiscard]] Error ensure_room(uint32_t extra, bool& moved) noexcept {
                const uint64_t cur  = len();
                const uint64_t need = cur + extra;

                if (need > max_size()) {
                    return Error::make(status::InvalidArgument, "tlv: size exceeds maximum");
                }
                if (m_owner && need <= m_cap) {
                    return Error::none();
                }

                uint64_t cap = need;

                if (extra) {
                    const uint64_t doubled = 2 * static_cast<uint64_t>(m_owner ? m_cap : cur);

                    if (doubled > cap) {
                        cap = doubled;
                    }
                }
                if (cap > max_size()) {
                    cap = max_size();
                }

                Error e = reallocate(static_cast<uint32_t>(cap));

                if (e.ok()) {
                    moved = true;
                }
                return e;
            }
 
        public:
            /// Largest value that fits in one entry.
            static constexpr uint32_t max_value_size = 253;

            /**
             * @brief Returns the largest possible list size in bytes.
             */
            [[nodiscard]] static constexpr uint32_t max_size() noexcept {
                return UINT32_MAX;
            }

            /**
             * @brief Constructs an empty list.
             */
            TLV() noexcept = default;

            /**
             * @brief Constructs an empty list with storage for @p reserve_bytes bytes.
             * @param reserve_bytes Initial capacity in bytes.
             */
            explicit TLV(uint32_t reserve_bytes) noexcept {
                Error e = reserve(reserve_bytes);

                if (!e.ok()) {
                    set_error(e.type, e.msg);
                }
            }

            /**
             * @brief Constructs a list by copying an array of nodes back to back.
             * @param head  Array of nodes.
             * @param count Number of nodes in the array.
             * 
             * @warning Copying data, not borrowing it.
             */
            TLV(tlv_node* head, uint32_t count) {
                uint64_t total = 0;

                for (uint32_t i = 0; head && i < count; ++i) {
                    total += head[i].size();
                }

                if (total == 0 || total > max_size()) {
                    set_error(status::InvalidArgument, "tlv: invalid total size");
                    return;
                }

                dissect(static_cast<uint32_t>(total));

                if (!ok()) {
                    return;
                }
                m_cap = static_cast<uint32_t>(total);

                uint32_t offset = 0;

                for (uint32_t i = 0; i < count; ++i) {
                    if (!head[i].size()) {
                        continue;
                    }
                    utils::mem::copy(m_origin_view.begin() + offset, head[i].data(), head[i].size());
                    offset += static_cast<uint32_t>(head[i].size());
                }
            }

            /**
             * @brief Constructs a list over existing bytes without copying them.
             * @param v Bytes holding zero or more entries.
             */
            TLV(view v) {
                dissect(v);
            }

            /**
             * @brief Constructs an owning copy of another list.
             */
            TLV(const TLV& o) noexcept : ProtocolBaseObject() {
                if (!o.BaseObject::ok()) {
                    set_error(o.BaseObject::sts(), "tlv: source list invalid");
                    return;
                }

                const uint32_t n = o.len();

                if (!n) {
                    return;
                }

                Error e = reallocate(n);

                if (!e.ok()) {
                    set_error(e.type, e.msg);
                    return;
                }
                utils::mem::copy(base(), o.base(), n);
                m_origin_view = view(base(), n);
                m_checked     = o.m_checked;
            }

            /**
             * @brief Constructs a list by taking over another list's storage.
             */
            TLV(TLV&& o) noexcept : ProtocolBaseObject() {
                steal(o);
            }

            /**
             * @brief Replaces the contents with an owning copy of another list.
             */
            TLV& operator=(const TLV& o) noexcept {
                if (this == &o) {
                    return *this;
                }

                TLV tmp(o);

                if (!tmp.BaseObject::ok()) {
                    set_error(tmp.BaseObject::sts(), "tlv: copy failed");
                    return *this;
                }
                steal(tmp);
                return *this;
            }

            /**
             * @brief Replaces the contents by taking over another list's storage.
             */
            TLV& operator=(TLV&& o) noexcept {
                if (this != &o) {
                    steal(o);
                }
                return *this;
            }

            [[nodiscard]] uint32_t hsize() const noexcept {
                return 0;
            }

            /**
             * @brief Returns whether the list holds no entries.
             */
            [[nodiscard]] bool empty() const noexcept {
                return len() == 0;
            }

            /**
             * @brief Returns the bytes of owned storage, or 0 while borrowing.
             */
            [[nodiscard]] uint32_t capacity() const noexcept {
                return m_owner ? m_cap : 0;
            }

            /**
             * @brief Ensures capacity for at least @p total_bytes bytes.
             * @param total_bytes Requested capacity in bytes.
             * @return Error::none() on success.
             */
            [[nodiscard]] Error reserve(uint32_t total_bytes) noexcept {
                const uint32_t want = total_bytes > len() ? total_bytes : len();

                if (!want || (m_owner && want <= m_cap)) {
                    return Error::none();
                }

                Error e = reallocate(want);

                if (e.ok()) {
                    reset();
                }
                return e;
            }

            /**
             * @brief Reduces capacity to the current size, releasing storage when empty.
             * @return Error::none() on success.
             */
            [[nodiscard]] Error fit() noexcept {
                if (!m_owner) {
                    return Error::none();
                }

                const uint32_t n = len();

                if (n == m_cap) {
                    return Error::none();
                }

                if (!n) {
                    m_owner.reset();
                    m_cap         = 0;
                    m_origin_view = view();
                    reset();
                    return Error::none();
                }

                Error e = reallocate(n);

                if (e.ok()) {
                    reset();
                }

                return e;
            }

            /**
             * @brief Removes every entry and keeps the capacity.
             */
            void clear() noexcept {
                m_origin_view = view();
                m_checked     = true;
                reset();
            }

            /**
             * @brief Appends an entry.
             * @param code Type code.
             * @param val  Value bytes; may be nullptr when @p n is 0.
             * @param n    Value size, at most max_value_size.
             * @return Error::none() on success.
             */
            [[nodiscard]] Error append(uint8_t code, const void* val = nullptr, size_t n = 0) noexcept {
                if (n > max_value_size) {
                    return Error::make(status::InvalidArgument, "tlv: value too large");
                }
                if (n && !val) {
                    return Error::make(status::InvalidArgument, "tlv: null value");
                }
                if (!wellformed()) {
                    return Error::make(status::MalformedPacket, "tlv: malformed entry");
                }

                const uint32_t add   = static_cast<uint32_t>(2 + n);
                bool           moved = false;
                Error          e     = ensure_room(add, moved);

                if (!e.ok()) {
                    return e;
                }

                const uint32_t cur = len();
                uint8_t*       p   = base() + cur;

                p[0] = code;
                p[1] = static_cast<uint8_t>(add);

                if (n) {
                    utils::mem::copy(p + 2, val, n);
                }

                m_origin_view = view(base(), cur + add);

                if (moved) {
                    reset();
                }
                return Error::none();
            }

            /**
             * @brief Appends an entry whose value is @p v.
             */
            [[nodiscard]] Error append(uint8_t code, const view& v) noexcept {
                return append(code, v.data(), v.size());
            }

            /**
             * @brief Removes the first entry of type @p code, or every such entry when @p all is set.
             * @param code    Type code.
             * @param all     Remove every match instead of only the first.
             * @param removed Receives the number of entries removed.
             * @return Error::none() on success, including when nothing matched.
             */
            [[nodiscard]] Error remove(uint8_t code, bool all = false, size_t* removed = nullptr) noexcept {
                if (removed) {
                    *removed = 0;
                }
                if (!wellformed()) {
                    return Error::make(status::MalformedPacket, "tlv: malformed entry");
                }

                const uint32_t n     = len();
                uint32_t       first = 0;

                {
                    const uint8_t* b = base();

                    while (first < n && b[first] != code) {
                        first += b[first + 1];
                    }
                }

                if (first >= n) {
                    return Error::none();
                }

                bool  moved = false;
                Error e     = ensure_room(0, moved);

                if (!e.ok()) {
                    return e;
                }

                uint8_t* b   = base();
                uint32_t rd  = first;
                uint32_t wr  = first;
                size_t   cnt = 0;

                while (rd < n) {
                    const uint8_t l = b[rd + 1];

                    if (b[rd] == code && (all || cnt == 0)) {
                        ++cnt;
                        rd += l;
                        continue;
                    }
                    if (wr != rd) {
                        std::memmove(b + wr, b + rd, l);
                    }
                    wr += l;
                    rd += l;
                }

                m_origin_view = wr ? view(b, wr) : view();
                reset();

                if (removed) {
                    *removed = cnt;
                }
                return Error::none();
            }

            /**
             * @brief Finds an entry by type code.
             * @param code Type code.
             * @param nth  Zero-based index among entries with this code.
             * @return The entry, or an invalid node: status::InvalidView when absent,
             *         status::MalformedPacket when a malformed entry precedes the match.
             */
            [[nodiscard]] tlv_node find(uint8_t code, uint32_t nth = 0) const noexcept {
                uint8_t*       b   = base();
                const uint32_t n   = len();
                uint32_t       off = 0;

                while (off < n) {
                    if (n - off < 2) {
                        return tlv_node(Error::make(status::MalformedPacket, "tlv: malformed entry"));
                    }

                    const uint8_t l = b[off + 1];

                    if (l < 2 || l > n - off) {
                        return tlv_node(Error::make(status::MalformedPacket, "tlv: malformed entry"));
                    }

                    if (b[off] == code && nth-- == 0) {
                        return tlv_node(b + off, l);
                    }
                    off += l;
                }
                return tlv_node();
            }

            /**
             * @brief Returns the value of the first entry with type @p c.
             * @return The value, or an invalid view when the entry is absent, malformed or has an empty value.
             */
            [[nodiscard]] view get(uint8_t c) const noexcept {
                tlv_node n = find(c);
                return n.ok() ? n.value() : view(n.error());
            }

            /**
             * @brief Advances to the next entry.
             * @return true when an entry was reached; false at the end or at a malformed entry.
             */
            bool next() noexcept {
                if (m_offset + 2 > m_origin_view.size()) {
                    return false;
                }

                uint8_t len = m_origin_view[m_offset + 1];

                if (len < 2 || m_offset + len > m_origin_view.size()) {
                    m_malformed = true;
                    return false;
                }

                m_current = tlv_node(m_origin_view.begin() + m_offset, len);
                m_offset += len;

                return true;
            }

            /**
             * @brief Returns the entry reached by the last successful next().
             * @param ok Receives false once traversal has hit a malformed entry.
             */
            tlv_node current(bool* ok = nullptr) const noexcept {
                if (ok) *ok = !m_malformed;
                return m_current;
            }

            /**
             * @brief Restarts traversal at the first entry.
             */
            void reset() noexcept {
                m_offset    = 0;
                m_current   = tlv_node{};
                m_malformed = false;
            }
   };
} // namespace lynx::proto
#pragma once

#include "lynx/core/base/obj.h"

#include <cstddef>
#include <cstdint>
#include <cstring>



namespace lynx {

    /**
     * @brief Non-owning view over a contiguous run of bytes.
     *
     * Holds a pointer and a length; never allocates, copies, or frees
     * anything. The memory it points to must outlive the view.
     * 
     * @note
     *    view deliberately mirrors std::span's own semantics on one point that's
     *    easy to assume is a bug: a const view locks the view (pointer + length)
     *    against reassignment, but never locks the bytes it points to - operator[]
     *    returns a mutable reference even through a const view, same as
     *    std::span<T>. Constness of the bytes themselves is std::span<const T>'s
     *    job, which this class does not attempt to provide.
     */
    class view : public BaseObject {
        public:
            /**
             * @brief Constructs an empty view (error state).
             */
            constexpr view() noexcept {
                set_error(status::InvalidView, "view: invalid");
            }

            /**
             * @brief Constructs an empty view with a custom error.
             */
            constexpr view(Error e) noexcept {
                absorb(e);
            }

            /**
             * @brief Constructs a view over a null-terminated character string.
             *
             * The input string must be null-terminated. The view references the existing
             * string storage and does not copy its contents.
             *
             * @param data Null-terminated character string.
             *
             * @note The referenced string storage must remain valid for the lifetime of
             *       the view.
             */
            constexpr view(char* data) {
                if (!data) {
                    set_error(status::InvalidView, "view: invalid data");
                    data_ = nullptr;
                    len_  = 0; 
                    return;
                }
                data_ = reinterpret_cast<uint8_t*>(data);
                
                while (data[len_] != '\0') {
                    ++len_;
                }
            }

            /**
             * @brief Constructs a view over @p len bytes starting at @p data.
             *
             * @param data Pointer to the first byte. May be @c nullptr only if
             *             @p len is 0.
             * @param len  Number of bytes.
             * 
             * @note The referenced string storage must remain valid for the lifetime of
             *       the view.
             */
            constexpr view(uint8_t* data, size_t len) noexcept : data_(data), len_(len) {
                if (!len_ || !data_) {
                    set_error(status::InvalidView, "view: invalid data or length");
                    data_ = nullptr;
                    len_ = 0;
                }
            }

            /**
             * @brief Constructs a view over a fixed-size array.
             *
             * @param arr Array to view, in its entirety.
             */
            template <size_t N>
            constexpr view(uint8_t (&arr)[N]) noexcept
                : data_(arr), len_(N) {}

            /**
             * @return Pointer to the first byte, or @c nullptr for an empty view.
             */
            [[nodiscard]] constexpr uint8_t* data() const noexcept { return data_; }

            /**
             * @return Number of bytes in the view.
             */
            [[nodiscard]] constexpr size_t size() const noexcept { return len_; }

            /**
             * @return @c true if the view has no bytes.
             */
            [[nodiscard]] constexpr bool empty() const noexcept { return len_ == 0; }

            /**
             * @return @c true if the view is valid (not in an error state).
             */
            [[nodiscard]] constexpr bool valid() const noexcept { return !ok() && !empty(); }
            
            /**
             * @brief Accesses the byte at @p i.
             *
             * @param i Index, counted from 0.
             * @return Reference to the byte.
             *
             * @note Performs no bounds checking. The caller must ensure
             *       @p i < size().
             */
            [[nodiscard]] constexpr uint8_t& operator[](size_t i) const noexcept { return data_[i]; }

            /// @return Pointer to the first byte, for range-based for.
            [[nodiscard]] constexpr uint8_t* begin() const noexcept { return data_; }

            /// @return Pointer past the last byte, for range-based for.
            [[nodiscard]] constexpr uint8_t* end() const noexcept { return data_ + len_; }

            /**
             * @brief Returns a view of the first @p n bytes.
             *
             * @param n Number of bytes to keep, from the start.
             * @return A view over @c [0, n).
             *
             * @note Does not check that @p n <= size(). A view constructed
             *       with too large an @p n reports a length past the end of
             *       the actual data.
             */
            [[nodiscard]] constexpr view first(size_t n) const noexcept {
                return view(data_, n);
            }

            /**
             * @brief Returns a view of @c [begin, size()).
             *
             * @param begin Index of the first byte to keep.
             * @return A view from @p begin to the end of this view.
             *
             * @note Does not check that @p begin <= size().
             */
            [[nodiscard]] constexpr view last(size_t begin) const noexcept {
                return view(data_ + begin, len_ - begin);
            }

            /**
             * @brief Returns a view of @c [begin, end).
             *
             * @param begin Index of the first byte to keep.
             * @param end   Index one past the last byte to keep.
             * @return A view over @c [begin, end).
             *
             * @note Does not check that @p begin <= @p end or that either
             *       stays within size(). Values past the end of the actual
             *       data produce a view that reports more than is really there.
             * 
             * @note Two invalid views (carrying error, no matter which) are considered same.
             * 
             */
            [[nodiscard]] constexpr view slice(size_t begin, size_t end) const noexcept {
                return view(data_ + begin, end - begin);
            }

            /**
             * @brief Compares two views for equality.
             *
             * @param other View to compare against.
             * @return @c true if both views have the same length and the same
             *         bytes.
             */
            [[nodiscard]] bool operator==(const view& other) const noexcept {
                if (!ok() && !other.ok())
                    return true;

                if (!ok() || !other.ok())
                    return false;

                if (len_ != other.len_)
                    return false;

                if (len_ == 0) 
                    return true;

                return std::memcmp(data_, other.data_, len_) == 0;
            }

            [[nodiscard]] bool operator!=(const view& other) const noexcept {
                return !(*this == other);
            }

            /**
             * @brief Reinterprets this view as a C string.
             *
             * @return This view's data, reinterpreted as @c const @c char*.
             *
             * @warning Only valid to read as a string if the view's last byte
             *          is a null terminator. This is a plain reinterpret cast
             *          - it does not check that for you, and reading past the
             *          view's actual data if it isn't null-terminated is
             *          undefined behavior, same as any other unterminated
             *          buffer treated as a string.
             */
            [[nodiscard]] const char* c_str() const noexcept {
                return reinterpret_cast<const char*>(data_);
            }

            /**
             * @brief Reinterprets this view as a C string.
             *
             * Equivalent to c_str(), usable via an explicit cast:
             * @code
             *   auto s = static_cast<const char*>(some_view);
             * @endcode
             *
             * @warning Same precondition as c_str() - only meaningful when the
             *          view's last byte is a null terminator.
             * @warning This operator is not seen by variadic functions like
             *          printf: passing a view directly as a %s argument does
             *          not invoke it, and reads the view's raw bytes as if
             *          they were a pointer instead. Use c_str() explicitly in
             *          a printf-style call.
             */
            [[nodiscard]] explicit operator const char*() const noexcept {
                return c_str();
            }

        protected:
            uint8_t* data_ = nullptr;
            size_t   len_  = 0;
    };

} // namespace lynx
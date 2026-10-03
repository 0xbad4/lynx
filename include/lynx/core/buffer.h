#pragma once

#include "lynx/core/base/obj.h"
#include "lynx/core/utils.h"

#include <memory>

namespace lynx {

    /**
     * @brief Reference-counted byte buffer.
     *
     * Buffer provides shared storage for packet data while avoiding per-layer
     * allocations and copies. Protocol layers operate on offsets within the
     * same underlying byte slab.
     *
     * Ownership is shared using @c std::shared_ptr<uint8_t[]>.
     * Buffer inherits BaseObject and reports errors such as BufferTooSmall and
     * BufferAllocFail through its common error state.
     *
     * @note len() only reflects what write()/reserve() have advanced it to.
     *       Writing through a raw pointer obtained via begin()/at() (e.g.
     *       handing it to a C API like recvfrom() that has no notion of
     *       Buffer) fills memory but does not move len() at all - nothing
     *       observes that write happening. If you must write through a raw
     *       pointer, use reserve() first to both get the pointer and advance
     *       len() by the amount you intend to write, then correct len() (or
     *       build the final view yourself from that pointer and the real
     *       byte count) once you know how much was actually written, since
     *       reserve() has no way to know that in advance.
     * 
     * @warning Buffer does not clean up or zero memory on destruction. Owner/SmartPtr is responsible for that. 
     *          This is intentional to avoid unnecessary overhead in high-performance packet processing.
     * 
     */
    class Buffer : public BaseObject {
        private:
            std::shared_ptr<uint8_t[]> data_;
            uint32_t offset_ = 0;      // byte offset within data_ where our view starts
            uint32_t len_    = 0;      // bytes written / valid
            uint32_t cap_    = 0;      // max bytes from offset_ (alloc size - offset_)
            
        public:
            Buffer() = default;

            /**
             * @brief Allocates a new zero-initialized byte buffer.
             *
             * Creates a heap-allocated buffer with the specified capacity. Intended for
             * packet crafting and transmission.
             *
             * @param capacity Buffer capacity in bytes.
             *
             * @return A newly allocated Buffer, or a Buffer containing
             *         status::BufferAllocFail if allocation fails.
             * 
             */
            [[nodiscard]] static Buffer alloc(uint32_t capacity) noexcept {
                Buffer b;

                if (capacity <= 0) {
                    b.set_error(status::InvalidArgument, "buffer: capacity must be > 0");
                    return b;
                }

                b.data_ = std::shared_ptr<uint8_t[]>(new (std::nothrow) uint8_t[capacity]{});
                
                if (!b.data_) {
                    b.set_error(status::BufferAllocFail, "buffer: new returned null");
                    return b;
                }
                b.cap_ = capacity;
                b.len_ = 0;
                return b;
            }

            /**
             * @brief Creates a buffer view over an existing shared byte slab.
             *
             * Takes shared ownership of the supplied buffer and creates a view beginning
             * at the specified offset. No data is copied or allocated.
             *
             * Intended for the zero-copy receive and packet dissection path, where
             * protocol layers can create independent views into the same underlying slab.
             *
             * @param owner Shared pointer that keeps the underlying byte slab alive.
             * @param offset Byte offset within @p owner where this buffer begins.
             * @param length Number of valid bytes in the buffer view.
             *
             * @return A Buffer representing the specified view.
             *
             * @note The capacity of a wrapped buffer is equal to its length.
             */
            [[nodiscard]] static Buffer wrap(ushared8_ptr owner, uint32_t offset, uint32_t length) noexcept {
                Buffer b;
                b.data_   = std::move(owner);
                b.offset_ = offset;
                b.len_    = length;
                b.cap_    = length;   // wrap is read-only - cap == len, no room to grow
                return b;
            }

            /**
             * @brief Appends bytes to the current write cursor.
             *
             * Copies @p n bytes from @p src at the current position and advances
             * the write cursor by @p n on success.
             *
             * @param src Source buffer containing the bytes to append.
             * @param n Number of bytes to append.
             *
             * @return @c true if the bytes were written successfully; otherwise @c false.
             *
             * @note Sets status::BufferTooSmall if the write would exceed the buffer
             *       capacity.
             */
            bool write(const uint8_t* src, uint32_t n) noexcept {
                if (!src) {
                    set_error(status::InvalidArgument, "buffer: null src");
                    return false;
                }
                if (len_ + n > cap_) {
                    set_error(status::BufferTooSmall, "buffer: write would exceed capacity");
                    return false;
                }
                utils::mem::copy(data_.get() + offset_ + len_, src, n);
                len_ += n;
                return true;
            }

            /**
             * @brief Reserves uninitialized space at the current write cursor.
             *
             * Advances the write cursor by @p n bytes and returns a pointer to the
             * reserved region, allowing the caller to write directly into the buffer.
             *
             * @param n Number of bytes to reserve.
             *
             * @return Pointer to the reserved region, or @c nullptr if the requested
             *         space exceeds the buffer capacity.
             *
             * @note Sets status::BufferTooSmall if the reservation exceeds the
             *       available capacity.
             */
            [[nodiscard]] uint8_t* reserve(uint32_t n) noexcept {
                if (len_ + n > cap_) {
                    set_error(status::BufferTooSmall, "buffer: exceeds capacity");
                    return nullptr;
                }
                uint8_t* ptr = data_.get() + offset_ + len_;
                len_ += n;
                return ptr;
            }

            /**
             * @brief Overwrites bytes at a specified position within the buffer.
             *
             * Copies @p n bytes from @p src to the buffer at @p pos without advancing
             * the write cursor.
             *
             * @param pos Position within the buffer where the bytes are written.
             * @param src Source buffer containing the bytes to copy.
             * @param n Number of bytes to overwrite.
             *
             * @return @c true if the bytes were written successfully; otherwise @c false.
             *
             * @note Sets status::BufferTooSmall if the patch range exceeds the buffer
             *       capacity.
             */
            bool patch(uint32_t pos, const uint8_t* src, uint32_t n) noexcept {
                if (!src) {
                    set_error(status::InvalidArgument, "buffer: null src");
                    return false;
                }
                if (pos + n > cap_) {
                    set_error(status::BufferTooSmall, "buffer: range exceeds capacity");
                    return false;
                }
                utils::mem::copy(data_.get() + offset_ + pos, src, n);
                return true;
            }


            /**
             * @brief Reads bytes from a specified position into a destination buffer.
             *
             * Copies @p n bytes starting at @p pos into @p dst.
             *
             * @param pos Position within the valid buffer data to begin reading.
             * @param dst Destination buffer for the copied bytes.
             * @param n Number of bytes to read.
             *
             * @return @c true if the requested range was read successfully; otherwise
             *         @c false.
             *
             * @note The read operation does not modify the buffer or its write cursor.
             */
            bool read(uint32_t pos, uint8_t* dst, uint32_t n) const noexcept {
                if (!dst) {
                    return false;
                }
                if (pos + n > len_) {
                    return false;
                }
                utils::mem::copy(dst, data_.get() + offset_ + pos, n);
                return true;
            }

            /**
             * @brief Returns a pointer to the beginning of the valid buffer data.
             *
             * @return Pointer to the first valid byte.
             */
            [[nodiscard]] uint8_t*       begin()       noexcept { return data_.get() + offset_; }
            
            /**
             * @brief Returns a read-only pointer to the beginning of the valid buffer data.
             *
             * @return Pointer to the first valid byte.
             */
            [[nodiscard]] const uint8_t* begin() const noexcept { return data_.get() + offset_; }

            /**
             * @brief Returns a pointer one past the last valid byte.
             *
             * @return Pointer past the end of the valid buffer data.
             */
            [[nodiscard]] uint8_t*       end()         noexcept { return data_.get() + offset_ + len_; }

            /**
             * @brief Returns a read-only pointer one past the last valid byte.
             *
             * @return Pointer past the end of the valid buffer data.
             */
            [[nodiscard]] const uint8_t* end()   const noexcept { return data_.get() + offset_ + len_; }

            /**
             * @brief Returns a pointer to a byte at the specified position.
             *
             * @param pos Position relative to the beginning of the valid buffer data.
             *
             * @return Pointer to the byte at @p pos.
             *
             * @note Performs no bounds checking. The caller must ensure that
             *       @p pos is within the valid buffer length.
             */
            [[nodiscard]] uint8_t*       at(uint32_t pos)       noexcept { return data_.get() + offset_ + pos; }

            /**
             * @brief Returns a read-only pointer to a byte at the specified position.
             *
             * @param pos Position relative to the beginning of the valid buffer data.
             *
             * @return Pointer to the byte at @p pos.
             *
             * @note Performs no bounds checking. The caller must ensure that
             *       @p pos is within the valid buffer length.
             */
            [[nodiscard]] const uint8_t* at(uint32_t pos) const noexcept { return data_.get() + offset_ + pos; }

            /**
             * @brief Returns a mutable view of all valid buffer.
             *
             * @return A view spanning all valid bytes in the buffer.
             */
            [[nodiscard]] view span() noexcept { return { begin(), len_ }; }

            /**
             * @brief Returns a mutable view of the entire buffer capacity.
             *
             * @return A view spanning the complete allocated buffer capacity.
             */
            [[nodiscard]] view aspan() noexcept { return { begin(), cap_ }; }

            /**
             * @brief Returns the shared ownership handle for the underlying byte slab.
             *
             * @return Shared pointer owning the underlying byte storage.
             */
            [[nodiscard]] ushared8_ptr owner() const noexcept { return data_; }

            /**
             * @brief Returns the number of valid bytes in the buffer.
             *
             * @return Number of valid bytes.
             */
            [[nodiscard]] uint32_t len() const noexcept { return len_; }

            /**
             * @brief Returns the buffer capacity.
             *
             * @return Maximum number of bytes available from the buffer's offset.
             */
            [[nodiscard]] uint32_t cap() const noexcept { return cap_; }

            /**
             * @brief Returns the starting offset within the underlying byte slab.
             *
             * @return Byte offset where this buffer's view begins.
             */
            [[nodiscard]] uint32_t offset() const noexcept { return offset_; }

            /**
             * @brief Returns the remaining writable capacity.
             *
             * @return Number of unused bytes remaining in the buffer.
             */
            [[nodiscard]] uint32_t remaining() const noexcept { return cap_ - len_; }

            /**
             * @brief Checks whether the buffer contains no valid data.
             *
             * @return @c true if the buffer length is zero; otherwise @c false.
             */
            [[nodiscard]] bool empty() const noexcept { return len_ == 0; }

            /**
             * @brief Checks whether the buffer has underlying storage.
             *
             * @return @c true if the underlying storage is valid; otherwise @c false.
             */
            [[nodiscard]] bool valid() const noexcept { return data_ != nullptr; }

            /**
             * @brief Resets the write cursor.
             *
             * Sets the valid data length to zero without clearing the underlying memory
             * or reallocating the buffer.
             */
            void reset() noexcept { len_ = 0; }
    };
} // namespace lynx

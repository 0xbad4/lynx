#pragma once

#include "lynx/core/base/obj.h"
#include "lynx/core/buffer.h"

namespace lynx
{

    /**
     * @brief Convenience macro to initialize a protocol header view.
     *
     * The macro calls @c dissect(hsize()) to set up the origin view for a newly
     * constructed protocol object.
     */
    #define INIT_HDR dissect(hsize());

    /**
     * @brief Common base for every protocol layer (Ether, IPv4, TCP, ...).
     *
     * @warning Header bytes are stored in network byte order at all times, in
     *          both craft and capture mode. A protocol's field accessors are 
     *          responsible for swapping on every access. 
     *          If a derived class instead keeps host-order fields and expects a
     *          swap-on-serialize step, load() will write the wrong bytes
     *          silently, since it has no protocol-specific knowledge to
     *          catch that.
     *
     * A chain is built with operator/, which only links pointers - it does
     * not serialize, checksum, or allocate anything. Bytes are produced once,
     * on demand, by load() into a caller-provided Buffer.
     *
     * Buffer has fixed capacity - allocate it with size() before
     * calling load(), or just use to_buffer():
     *
     *   - capture: get<T>() default-constructs T, then calls dissect(v) with
     *              a view sliced out of this layer's own payload. No
     *              allocation, no copy - m_origin_view just borrows a slice
     *              of it.
     *   - craft:   a freshly default-constructed object
     *              needs to allocate its own header bytes.
     *
     * @warning A captured object's origin view aliases the receive buffer it
     *          was sliced from. That buffer is typically only guaranteed
     *          valid for the duration of the capture scope it was produced
     *          in. Chaining a captured object with operator/ and calling
     *          load() on it later (e.g. to modify and resend a captured
     *          packet) reads through a pointer that may already have been
     *          reused by the next captured frame - the object itself is still
     *          alive, what it points to is not guaranteed to still hold any
     *          data.
     *
     * @warning Attaching an upper layer with operator/ truncates that
     *          object's origin view down to its own header (the first
     *          hsize() bytes); any data that previously followed it is no
     *          longer reachable through origin(). get<T>() attaches an upper
     *          layer through a separate path and does not perform the same
     *          truncation, so an object whose upper layer came from get<T>()
     *          may still report trailing data through origin() that load()
     *          and size() no longer use.
     */
    class ProtocolBaseObject : public BaseObject {
        public:
            /**
             * @brief Destroys the protocol base object.
             *
             * Provides a virtual destructor so derived protocol objects can be
             * destroyed correctly through a base-class pointer.
             */
            virtual ~ProtocolBaseObject() = default;
        
            /**
             * @brief Constructs a protocol object from the loaded payload.
             *
             * Creates an instance of the requested protocol type and dissects
             * this layer's payload view into it, then links it above this
             * layer (as if by operator/) so m_underlayer_ptr / m_upperlayer_ptr
             * stay consistent for later use (e.g. checksum pseudo-headers).
             *
             * @tparam T Protocol type to construct. Must derive from ProtocolBaseObject.
             *
             * @return A unique pointer to the constructed protocol object, or @c nullptr
             *         if the payload is empty or allocation fails.
             *
             * @note Only meaningful on a captured object with an un-dissected
             *       payload view - see the class-level warning about that
             *       view's lifetime before holding onto the result.
             */
            template<typename T>
            [[nodiscard]] std::unique_ptr<T> get() noexcept {
                ASSERT_PROTOCOL

                // 1. validate packet origin (not null) and if its size is bigger than hsize(),
                //    this is separate from check(): it's just "is there
                //    anything left to hand T at all", not "is it a valid T"
                if (!m_origin_view.data() || m_origin_view.size() <= hsize()) {
                    return nullptr;
                }
                view upper = m_origin_view.last(hsize());
 
                // 2. create
                std::unique_ptr<T> t(new (std::nothrow) T(upper));
 
                // memory failure
                if (!t) {
                    return nullptr;
                }

                // internal error
                if (!t->ok()) {
                    return nullptr;
                }
 
                // protocol-specific validity
                if (!t->check()) {
                    return nullptr;
                }
 
                // set upper layer
                m_upperlayer_ptr = t.get();
 
                // set underlayer
                t->m_underlayer_ptr = this;
 
                return t;
            }

            /**
             * @brief Links this protocol layer with an upper protocol layer.
             *
             * Only links m_underlayer_ptr / m_upperlayer_ptr in both directions.
             * Does not serialize, checksum, or copy anything - that happens
             * once, lazily, when load() is eventually called.
             *
             * @param rhs Upper protocol layer to attach above this protocol.
             *
             * @warning Assigning an upper layer with operator/ truncates that object's origin view down to its own header (the first hsize() bytes); 
             *       any data that previously followed it is no longer reachable through origin(). 
             *       get<T>() attaches an upper layer through a separate path and does not perform the same truncation, 
             *       so an object whose upper layer came from get<T>() may still report trailing data through origin() that load() and size() no longer use.
             *
             * @note Chaining protocols does not alter their properties/header attributes in any way. 
             * 
             * @return Reference to this protocol layer.
             */
            ProtocolBaseObject& operator/(ProtocolBaseObject& rhs) noexcept {
                // rhs knows who is beneath it
                rhs.m_underlayer_ptr = this;
 
                // this knows who is above it
                m_upperlayer_ptr = &rhs;

                 // rhs owns everything past our own header
                 unload(true);
 
                return *this;
            }

            /**
             * @brief Detaches the upper layer or un-dissected payload from this layer.
             *
             * If @p ud is @c true, detaches any un-dissected payload bytes that
             * remain after this layer's header. If @p ud is @c false, detaches
             * the upper layer (if any) that was linked with operator/ or get<T>().
             *
             * After this call, size() will return hsize() if @p ud is @c true,
             * or hsize() + whatever trailing bytes remain in m_origin_view if
             * @p ud is @c false and no upper layer was attached.
             *
             * @param ud If @c true, detaches un-dissected payload; otherwise detaches
             *          the upper layer.
             */
            void unload(bool ud=false) noexcept {
                // detach un-dissected bytes
                if (ud && m_origin_view.size() > hsize()) {
                    m_origin_view = m_origin_view.first(hsize());
                }

                // detach upper layer
                else if (m_upperlayer_ptr) {
                    m_upperlayer_ptr->m_underlayer_ptr = nullptr;
                    m_upperlayer_ptr = nullptr;
                }
            }

            /**
             * @brief Writes this layer and everything chained above it into @p buf.
             *
             * @p buf must already have at least size() bytes of capacity from
             * its current write cursor - Buffer does not grow. Use to_buffer()
             * if you don't want to size and allocate it yourself.
             *
             * Writes exactly hsize() bytes from the start of m_origin_view, 
             * recurses into the linked upper layer (if operator/ or get()
             * attached one), or, if this layer is still holding onto an
             * un-dissected captured remainder past its own header, writes
             * that back out as-is. A crafted layer with no upper layer has
             * nothing past its own header (m_origin_view is exactly
             * hsize() bytes), so that branch is a no-op for it - matches
             * size()'s zero contribution in the same case. Explicit
             * payload attachment (e.g. TCP application data) is not a base
             * concern; that's what a dedicated Raw layer chained on top is for.
             *
             * Once the full extent belonging to this layer and everything
             * above it has been written, patch() is called with the
             * offset this layer's header started at, so it can read the now-
             * complete bytes and patch its fields in place with
             * buf.patch() - which does not move the write cursor, so this
             * happens safely after the recursive call above has already
             * advanced past this layer's own bytes.
             *
             * Every Buffer::write() call inside this chain sets an error on
             * @p buf if it runs out of capacity (check buf.ok() afterward);
             * it does not throw or crash.
             *
             * @param buf Buffer to write this layer's serialized bytes into.
             * 
             * @warning Load set by operator/ is preferred over any un-dissected captured remainder, 
             *          so if a captured object has an upper layer attached, 
             *          any trailing bytes in m_origin_view are ignored by load() and size().
             */
            void load(Buffer& buf) noexcept {
                const uint32_t header_offset = buf.len();
 
                // write header
                buf.write(m_origin_view.data(), hsize());
 
                // write load:
                // 1. has an upper layer
                if (m_upperlayer_ptr) {
                    m_upperlayer_ptr->load(buf);
                }
                // 2. no upper layer, but maybe has un-dissected captured remainder
                else {
                    view tail = m_origin_view.last(hsize());
                
                    if (!tail.empty()) {
                        buf.write(tail.data(), static_cast<uint32_t>(tail.size()));
                    }
                }
 
                patch(buf, header_offset);
            }
        
            /**
             * @brief Allocates a correctly sized Buffer and writes into it.
             *
             * Convenience wrapper around Buffer::alloc(size()) + load().
             *
             * @return A Buffer containing the fully written chain, or one
             *         holding status::BufferAllocFail if allocation failed.
             */
            [[nodiscard]] Buffer to_buffer() noexcept {
                Buffer buf = Buffer::alloc(size());

                if (!buf.valid()) {
                    return buf;
                }
                load(buf);
                return buf;
            }

            /**
             * @brief Returns this layer's bytes.
             *
             * The first hsize() bytes are this layer's header. Anything
             * past that is either an un-dissected captured remainder or, on a crafted object,
             * nothing at all - m_origin_view is exactly hsize() bytes until
             * something is chained above it.
             *
             * @note If bytes remain past hsize() but operator/ has attached an upper
             *       layer, those trailing bytes in origin() are ignored by load()/size()
             *       and are effectively dead, even though they are still physically present.
             * @return This layer's origin view.
             */
            [[nodiscard]] view origin() const noexcept {
                return m_origin_view;
            }

            /**
             * @brief Returns a view of the protocol payload.
             *
             * @return A non-owning view of the bytes following the protocol header.
             */
            [[nodiscard]] view payload() const noexcept {
                return origin().last(hsize());
            }

            /**
             * @brief Returns the total size of this layer and everything above it.
             *
             * This is what Buffer::alloc() needs before load() can run, since Buffer
             * does not grow. This layer's header size, plus recursively whatever is chained above it, 
             * or - if nothing is chained - whatever's left in m_origin_view past this layer's 
             * own header (an un-dissected captured remainder, or nothing at all on a crafted
             * object, where that's always empty).
             *
             * @return Total size in bytes, as load() would produce.
             */
            [[nodiscard]] uint32_t size() const noexcept {
                uint32_t total = hsize();

                // upperlayer is preferred
                if (m_upperlayer_ptr) {
                    total += m_upperlayer_ptr->size();
                }
                else {
                    // whatever is beyond header size (can be valid if captured packet, 0 otherwise)
                    total += static_cast<uint32_t>(hsize() ? m_origin_view.last(hsize()).size() : m_origin_view.size());
                }

                return total;
            }   
 
            /**
             * @brief Returns the header size of this layer.
             *
             * @return Header size in bytes.
             */
            [[nodiscard]] virtual uint32_t hsize() const noexcept = 0;

            /**
             * @brief Validates that the current view is well-formed for this protocol.
             *
             * The base implementation checks that the internal view contains at least
             * hsize() bytes. Protocols with additional structural requirements, such as
             * a version field or header-length field, override this method to perform
             * those checks.
             * 
             * @note Minimum requirement is that the view has at least hsize() bytes; additional checks may be protocol-specific.
             * 
             * @note This method does not set any internal error state; it only returns a boolean indicating validity.
             *
             * @return @c true if the current view is valid for this protocol;
             *         @c false otherwise.
             */
            [[nodiscard]] virtual bool check() noexcept {
                return m_origin_view.size() >= hsize();
            }

            /**
             * @brief Checks whether the protocol object is valid.
             *
             * Extends the base object validation by checking that protocol data is
             * available and satisfies the protocol-specific structural requirements.
             *
             * @return @c true if the base object, protocol data, and protocol structure
             *         are valid; @c false otherwise.
             */
            [[nodiscard]] bool ok() noexcept {
                return BaseObject::ok() && m_origin_view.ok() && check();
            }

            /**
             * @brief Returns the first error detected by the object.
             *
             * Checks the base object state, the protocol view state, and the protocol
             * structure in that order, returning the corresponding error when validation
             * fails.
             *
             * @return The first detected error, or an empty error if the object is valid.
             */
            [[nodiscard]] Error error() noexcept {
                if (!BaseObject::ok()) {
                    return BaseObject::error();
                }
                if (!m_origin_view.ok()) {
                    return m_origin_view.error();
                }
                if (!check()) {
                    return Error(status::MalformedPacket, "malformed packet");
                }
                return Error::none();
            }

            [[nodiscard]] const char* errmsg() noexcept { 
                return error().what(); 
            }

        protected:
            // packet origin
            view m_origin_view   {};
 
            // keeps craft-mode header bytes alive (m_origin_view never
            // carries ownership itself). Stays null in capture mode, where
            // m_origin_view just borrows from whatever produced it - see
            // the class-level warning about that borrow's lifetime.
            ushared8_ptr m_owner {};
 
            // underlayer access - mutable: linked by operator/ and by the
            // const get(), which does not otherwise change observable state
            mutable ProtocolBaseObject* m_underlayer_ptr = nullptr;
 
            // upperlayer access - mutable, same reason
            mutable ProtocolBaseObject* m_upperlayer_ptr = nullptr;

           /**
             * @brief Dissects raw data into this object's origin view.
             *
             * @param v View containing the raw protocol data. Must contain at least
             *          hsize() bytes.
             *
             * @note m_origin_view borrows @p v; no data is copied.
             * @note Sets status::BufferTooSmall if @p v is smaller than hsize().
             */
            void dissect(view v) noexcept {
                if (v.ok()) {
                    if (v.size() < hsize()) {
                        set_error(status::BufferTooSmall, "proto: view smaller than header size");
                        return;
                    }
                    m_origin_view = v;
                }
                else {
                    dissect(hsize());
                }
            }

            /**
             * @brief Allocates and initializes the protocol view.
             *
             * Allocates a buffer of the requested size and assigns its ownership and
             * byte span to the protocol object. On invalid input or allocation failure,
             * the object is left in an invalid state and an error is recorded.
             *
             * @param sz Size in bytes to allocate.
             */
            void dissect(uint32_t sz) {
                if (!sz) {
                    m_origin_view = view();  // caries an error
                    set_error(status::InvalidArgument, "proto: header size must be > 0");
                    return;
                }

                Buffer header_buf = Buffer::alloc(sz);

                if (!header_buf.valid()) {
                    set_error(status::BufferAllocFail, "proto: alloc failed");
                    return;
                }
                m_owner       = header_buf.owner();
                m_origin_view = header_buf.aspan();
            }

            /**
             * @brief Performs post-write validation or modification of this layer.
             *
             * Default implementation performs no operation.
             *
             * Called by load() after this layer and all upper layers have been written
             * to @p buf. Implementations may inspect or modify the serialized frame,
             * including calculating checksums, validating or correcting addresses, or
             * applying other protocol-specific adjustments.
             *
             * @param buf Buffer containing the serialized frame.
             * @param header_offset Byte offset in @p buf where this layer's header begins.
             * 
             * @warning This is a constant method, thus it only patches the serialized bytes in @p buf and does not modify the protocol object's internal state.
             */
            virtual void patch(Buffer& buf, uint32_t header_offset) const noexcept {
                (void)buf;
                (void)header_offset;
            }
    };
} // namespace lynx

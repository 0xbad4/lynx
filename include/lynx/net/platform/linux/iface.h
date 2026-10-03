#pragma once


#include "lynx/core/config/config.h"
#include "lynx/core/error.h"
#include "lynx/protocols/all.h"

#include "lynx/net/platform/linux/socket.h"
 
#include <atomic>
#include <functional>
#include <cstdint>

/**
 * @brief Network interface for raw Layer 2 frame transmission and capture on Linux.
 */
namespace lynx::uni::io {
    /**
     * @brief Represents a network interface for raw Layer 2 frame transmission and capture.
     *
     * UniInterface binds to a network interface card (NIC) and manages the send and
     * capture lifecycle. It provides methods to open, close, and configure the
     * interface, as well as to resolve MAC addresses via kernel cache.
     *
     * @note The interface operates at Layer 2 and 3. 
     *       All transmitted packets are ultimately represented as complete Ethernet frames.
     * 
     * @note When sending a layer 3 packet (IPv4, ...etc), UniInterface uses defined POLICIES to resolve
     *       source and destination MAC addresses.
     * 
     * @warning The interface is not thread-safe. Concurrent access must be externally synchronized.
     * 
     * @note Resource cleanup is controlled by LYNX_CLOSE_ON_DESTROY configuration:
     *       if enabled, the destructor automatically closes the interface and disables
     *       promiscuous mode; otherwise, manual close() is required.
     * @see lynx/net/platform/linux/socket.h for underlying socket operations
     * @see lynx/core/config/config.h for configuration options
     */
    class UniInterface : public BaseObject {
        public:

            /**
             * @brief Constructs an interface bound to the specified network interface.
             *
             * @param name Name of the network interface to bind to.
             *
             * @note The interface name is stored as provided; the constructor does not
             *       perform interface lookup or initialization.
             *
             * @param name Must point to a valid null-terminated string for the lifetime
             *             of the constructed object.
             */
            explicit UniInterface(const char* name) noexcept : name_(name) {}

            /**
             * @brief Destroys the interface.
             *
             * The interface closure behavior is controlled by the
             * @c LYNX_CLOSE_ON_DESTROY configuration option defined in @c config.h.
             */
            ~UniInterface() noexcept {
                #if LYNX_CLOSE_ON_DESTROY == 1
                    if (is_open()) {
                        if (promisc_) {
                            sock::set_promiscuous(fd_, ifindex_, false);
                        }
                        sock::close_fd(fd_);
                    }
                #endif
            }

            /**
             * @brief Copy constructor is deleted.
             *
             * UniInterface objects own a file descriptor and therefore cannot be copied.
             */
            UniInterface(const UniInterface&) = delete;

            /**
             * @brief Copy assignment operator is deleted.
             *
             * UniInterface objects own a file descriptor and therefore cannot be copied.
             */
            UniInterface& operator=(const UniInterface&) = delete;
            
            /**
             * @brief Move-constructs an interface.
             *
             * Transfers ownership of the underlying file descriptor from @p o to the
             * newly constructed interface.
             *
             * @param o UniInterface to move from.
             */
            UniInterface(UniInterface&& o) noexcept
                : name_(o.name_), 
                fd_(o.fd_), 
                ifindex_(o.ifindex_), 
                promisc_(o.promisc_), 
                snaplen_(o.snaplen_), 
                timeout_ms_(o.timeout_ms_), 
                direction_(o.direction_), 
                rcvbuf_size_(o.rcvbuf_size_)
            {
                o.fd_      = sock::INVALID_FD;
                o.ifindex_ = sock::INVALID_IDX;
            }

            /**
             * @brief Opens and initializes the network interface.
             *
             * Creates the underlying socket, resolves the interface index, binds the
             * socket to the interface, and applies all pending socket tuning options
             * queued before opening.
             */
            void open() noexcept {
                if (is_open()) {
                    set_error(status::IfaceAlreadyOpen, "iface: already open");
                    return;
                }

                absorb(sock::open_raw(fd_));                      if (!ok()) return;
                absorb(sock::get_ifindex(name_, ifindex_));       if (!ok()) return;
                absorb(sock::bind_to_iface(fd_, ifindex_));       if (!ok()) return;
                absorb(sock::set_recv_timeout(fd_, timeout_ms_)); if (!ok()) return;
                absorb(sock::set_recv_buffer(fd_, rcvbuf_size_)); if (!ok()) return;
                absorb(sock::set_io_direction(fd_, direction_));     if (!ok()) return;

                if (promisc_) {
                    absorb(sock::set_promiscuous(fd_, ifindex_, true));
                }
            }

            /**
             * @brief Closes the network interface.
             *
             * Disables promiscuous mode if it is currently active, then closes the
             * underlying file descriptor.
             *
             * This operation is safe to call multiple times.
             */
            void close() noexcept {
                if (!is_open()) {
                    return;
                }

                if (promisc_) {
                    sock::set_promiscuous(fd_, ifindex_, false);
                }

                sock::close_fd(fd_);
                ifindex_ = sock::INVALID_IDX;
            }

            /**
             * @brief Checks whether the interface is currently open.
             *
             * @return @c true if the underlying socket is open; otherwise @c false.
             */
            [[nodiscard]] bool is_open() const noexcept { 
                return fd_ != sock::INVALID_FD; 
            }

            /**
             * @brief Verifies that the network interface is open.
             *
             * Sets the current error state if the interface is not open.
             *
             * @return @c true if the interface is open; otherwise @c false.
             */
            [[nodiscard]] bool check_open() noexcept {
                if (!is_open()) { 
                    set_error(status::IfaceNotOpen, "iface: not open"); 
                    return false;
                }
                return true;
            }

            /**
             * @brief Resolves the destination MAC address for a given IPv4 address.
             *
             * Uses the kernel ARP cache to resolve the MAC address corresponding to
             * the provided IPv4 address. If no valid ARP entry exists, an error is
             * recorded in the interface's error state.
             *
             * @param dst_ip Destination IPv4 address in network byte order.
             * @param err If @c true, records an error in the interface's error state
             *            if resolution fails; otherwise, errors are ignored.
             *
             * @return The resolved MAC address, or an empty MAC address if resolution fails.
             */
            mn_mac arp_entry(const uint8_t dst_ip[4], bool err=false) noexcept {
                uint8_t mac[6]{};

                auto error = sock::get_arp_entry(fd_, name_, dst_ip, mac);

                if (err && !error.ok()) {
                    absorb(error);
                }

                return mn_mac(mac);
            }

            /**
             * @brief Resolves the MAC address of the bound network interface.
             *
             * Uses the kernel to retrieve the MAC address of the interface. If
             * resolution fails, an error is recorded in the interface's error state
             * if @p err is @c true.
             *
             * @param err If @c true, records an error in the interface's error state
             *            if resolution fails; otherwise, errors are ignored.
             *
             * @return The resolved MAC address, or an empty MAC address if resolution fails.
             */

            mn_mac mac_addr(bool err=false) noexcept {
                uint8_t mac[6]{};

                auto error = sock::get_iface_mac(fd_, name_, mac);

                if (err && !error.ok()) {
                    absorb(error);
                }

                return mn_mac(mac);
            }

            /**
             * @brief Returns the IPv4 address assigned to the interface.
             *
             * Queries the operating system for the interface's IPv4 address and returns
             * it as an IPv4 address object.
             *
             * @param err If @c true, absorbs the query error into the interface object
             *            when the address lookup fails.
             *
             * @return The interface's IPv4 address.
             */
            mn_ipv4 ip_addr(bool err=false) {
                uint8_t ip[4]{};

                auto error = sock::get_iface_ip(fd_, name_, ip);

                if (err && !error.ok()) {
                    absorb(error);
                }

                return mn_ipv4(ip);
            }

            /**
             * @brief Enables or disables promiscuous mode on the interface.
             *
             * If called before @c open(), the option is stored and applied when the
             * interface is opened. If called after @c open(), the option is applied
             * immediately to the active socket.
             *
             * @param enable @c true to enable promiscuous mode, @c false to disable it.
             */
            void set_promiscuous(bool enable) noexcept {
                promisc_ = enable;

                if (is_open()) {
                    absorb(sock::set_promiscuous(fd_, ifindex_, enable));
                }
            }

            /**
             * @brief Sets the maximum number of bytes captured per packet.
             *
             * @param bytes Maximum number of packet bytes to capture.
             */
            void set_snaplen(int bytes) noexcept {
                if (bytes <= 0) {
                    set_error(status::InvalidArgument, "iface: snaplen must be > 0"); 
                    return;
                }
                snaplen_ = bytes;
            }

            /**
             * @brief Sets the packet capture timeout.
             *
             * @param ms Timeout duration in milliseconds.
             */
            void set_timeout(int ms) noexcept {
                if (ms < 0) { 
                    set_error(status::InvalidArgument, "iface: timeout must be >= 0");
                    return;
                }
                timeout_ms_ = ms;
                
                if (is_open()) {
                    absorb(sock::set_recv_timeout(fd_, ms));
                }
            }

            /**
             * @brief Specifies the direction of captured network traffic.
             *
             * Controls whether incoming, outgoing, or both directions of traffic are
             * delivered during packet capture.
             * @c direction enum defined in @c linux/socket.h.
             */
            void set_direction(io_direction dir) noexcept {
                direction_ = dir;
                if (is_open()) {
                    absorb(sock::set_io_direction(fd_, dir));
                }
            }

            /**
             * @brief Sets the receive buffer size.
             *
             * @param bytes Size of the receive buffer in bytes.
             */
            void set_buffer_size(int bytes) noexcept {
                if (bytes < 0) { 
                    set_error(status::InvalidArgument, "iface: buffer size must be >= 0"); 
                    return; 
                }
                
                rcvbuf_size_ = bytes;

                if (is_open()) {
                    absorb(sock::set_recv_buffer(fd_, bytes));
                }
            }

            /**
             * @brief Sends the contents of @p buffer as a single raw frame.
             *
             * @param buffer Buffer holding the complete frame to send, from offset 0 through len().
             */
            void write(Buffer& buffer) noexcept {
                // Abort if interface not open, this method set error automatically
                if (!check_open()) {
                    return;
                }

                // dst MAC sits at offset 0 in every L2 frame
                absorb(sock::raw_send(fd_, ifindex_, buffer.begin(), buffer.len(), buffer.begin()));
            }

            /**
             * @brief Writes a raw protocol frame to the network interface.
             * 
             * @param raw Raw protocol frame to transmit.
             * @param outbuffer Optional pointer receiving shared ownership of the
             *                  serialized frame buffer.
             */
            void write(proto::Raw &raw, ushared8_ptr* outbuffer=nullptr) noexcept {
                if (!check_open()) {
                    return;
                }

                // 1. run ProtocolBaseObject::check
                if (!raw.check()) {
                    set_error(status::MalformedPacket, "iface: check failed");
                    return;
                }

                // 2. export to buffer
                Buffer buffer = raw.to_buffer();

                // 3. write buffer
                write(buffer);

                // 4. export buffer
                if (outbuffer) {
                    *outbuffer = std::move(buffer.owner());
                }
            }

            /**
             * @brief Transmits a protocol frame through the network interface.
             *
             * The frame is validated through its protocol-defined check() implementation
             * before being serialized and transmitted. Protocol-specific validation is
             * delegated to the frame and is not performed directly by this method.
             *
             * The serialized frame is written through the interface and, when @p outbuffer
             * is provided, ownership of the underlying buffer storage is transferred to
             * the caller through the shared pointer.
             *
             * The returned buffer remains valid independently of the local Buffer object's
             * lifetime and is released automatically when the last owning shared pointer
             * is destroyed.
             *
             * @param frame Frame to transmit.
             * @param outbuffer Optional pointer receiving shared ownership of the
             *                  serialized frame buffer.
             */
            void write(proto::Frame& frame, ushared8_ptr* outbuffer=nullptr) noexcept {
                if (!check_open()) {
                    return;
                }

                // 1. run ProtocolBaseObject::check
                if (!frame.check()) {
                    set_error(status::MalformedPacket, "iface: Frame check failed");
                    return;
                }

                // 2. export to buffer
                Buffer buffer = frame.to_buffer();

                // 3. write buffer
                write(buffer);

                // 4. export buffer
                if (outbuffer) {
                    *outbuffer = std::move(buffer.owner());
                }
            }

            /**
             * @brief Transmits an L3 packet through the network interface.
             *
             * Automatically constructs the required Ethernet layer using the packet's
             * protocol type and destination addressing information. Ethernet source and
             * destination MAC address resolution follows the configured interface
             * policies.
             *
             * @param pkt Layer 3 packet to transmit.
             * @param outbuffer Optional pointer receiving shared ownership of the
             *                  serialized frame buffer.
             */
            void write(proto::Packet &pkt, ushared8_ptr* outbuffer=nullptr) noexcept {
                if (!check_open()) {
                    return;
                }
                
                // 1. run ProtocolBaseObject::check
                if (!pkt.check()) {
                    set_error(status::MalformedPacket, "iface: Packet check failed");
                    return;
                }

                // 2. create Ethernet frame (fill in attrs)
                // dst mac
                mn_mac dst = resolve_dst_mac(pkt.adst(), pkt.ethertype(), pkt.is_broadcast());

                if (!ok()) {
                    return;
                }
                
                // src mac
                mn_mac src = resolve_src_mac();

                if (!ok()) {
                    return;
                }

                proto::Eth eth(dst, src, pkt.ethertype());

                if (!eth.ok()) {
                    absorb(eth.error());
                    return;
                }

                // 3. chain
                eth / pkt;

                // 4. write frame
                write(eth, outbuffer);

                // 5. unload frame from pkt (detach)
                // resets packet's m_underlayer_ptr to nullptr, 
                // so pkt doesn't carry a dangling pointer to the frame after this method returns
                eth.unload();
            }

            /**
             * @brief Receives the next raw Ethernet frame.
             *
             * Blocks until a frame is available or the configured capture timeout
             * expires, retrying internally up to LYNX_MAX_READ_RETRIES times if the
             * socket times out with no frame ready - no new allocation on a retry,
             * the same snaplen_ bytes buffer is reused for each attempt.
             *
             * @return A Raw wrapping the captured frame, or a Raw carrying an error
             *         if the interface isn't open, allocation failed, the receive
             *         itself failed, or retries were exhausted with no frame arriving.
             */
            [[nodiscard]] std::unique_ptr<proto::Raw> read() noexcept {

                if (!check_open()) {
                    return std::make_unique<proto::Raw>(error());
                }

                // 1. allocate snaplen
                Buffer buffer = Buffer::alloc(static_cast<uint32_t>(snaplen_));

                if (!buffer.ok()) {
                    return std::make_unique<proto::Raw>(buffer.error());
                }

                // 2. capture, retrying on timeout up to LYNX_MAX_READ_RETRIES
                for (;;) {
                    Error err;
                    int32_t bread = sock::raw_recv(fd_, buffer.begin(), buffer.cap(), nullptr, err);

                    // 2.1 error
                    if (bread < 0) {
                        return std::make_unique<proto::Raw>(err);
                    }

                    // 2.2 timeout - retry, up to the limit
                    if (bread == 0) {
                        if (++read_retry_n_ <= LYNX_MAX_READ_RETRIES) {
                            continue;
                        }
                        read_retry_n_ = 0;
                        auto err = Error::make(
                            status::RecvTimeout, 
                            "read: exceeded max retries with no frame received"
                        );
                        return std::make_unique<proto::Raw>(err);
                    }

                    // 2.3 success
                    read_retry_n_ = 0;
                    return std::make_unique<proto::Raw>(buffer.aspan());
                }
            }
            
            // accessors
            [[nodiscard]] const char* name()    const noexcept { return name_;    }
            [[nodiscard]] int         fd()      const noexcept { return fd_;      }
            [[nodiscard]] int         ifindex() const noexcept { return ifindex_; }

        private:
            // member state
            const char*       name_        = nullptr;
            int               fd_          = sock::INVALID_FD;
            int               ifindex_     = sock::INVALID_IDX;

            bool              promisc_     = false;
            int               snaplen_     = LYNX_DEFAULT_SNAPLEN;
            int               timeout_ms_  = LYNX_DEFAULT_TIMEOUT_MS;
            io_direction      direction_   = io_direction::Both;
            int               rcvbuf_size_ = LYNX_RECV_BUFFER_SIZE;

            size_t            read_retry_n_ = 0;

            /**
             * @brief Resolves the destination MAC address for a given IPv4 address.
             *
             * Uses the kernel ARP cache to resolve the MAC address corresponding to
             * the provided IPv4 address. If no valid ARP entry exists, An attempt is made -
             * to resolve the MAC address of the default gateway if one is configured. 
             * If resolution fails, an error is recorded in the interface's error state.
             *
             * @param dst Destination IPv4 address in network byte order.
             * @param bc If @c true, returns the broadcast MAC address instead of
             *           performing ARP resolution.
             * 
             * @warning No support for IPv6 neighbor discovery yet (current version), 
             *          so we just return solicited node multicast MAC address for the given IPv6 destination.
             *
             * @return The resolved MAC address, or an empty MAC address if resolution fails.
             */
            mn_mac resolve_dst_mac(const uint8_t* dst, uint16_t etype, bool bc) {
                if (bc) {
                    return mn_mac::broadcast();
                }

                if (etype == proto::IPV6_ETHERTYPE) {
                    // TODO: add support for IPv6 neighbor discovery and multicast MAC resolution
                    // assuming sizeof(dst) == 16, which is true for mn_ipv6
                    return mn_mac::solicit6(dst);
                }

                // existing IPv4 body, unchanged
                #if LYNX_DST_MAC_POLICY == DST_MAC_ARP_CACHE
                    auto mac = arp_entry(dst);
                    if (mac == mn_mac()) {
                        uint8_t gw_addr[4]{};
                        auto err = sock::get_default_gw(gw_addr);
                        if (!err.ok()) {
                            set_error(status::ArpResolveFail, "iface: failed to resolve dst MAC via ARP cache and no default gateway found");
                        } else {
                            mac = arp_entry(gw_addr, true);
                        }
                    }
                    return mac;
                #elif LYNX_DST_MAC_POLICY == DST_MAC_BROADCAST
                    return mn_mac::broadcast();
                #endif
            }

            /**
             * @brief Resolves the source MAC address for the interface.
             *
             * Uses the kernel to retrieve the MAC address of the interface. If
             * resolution fails, an error is recorded in the interface's error state.
             *
             * @return The resolved MAC address, or an empty MAC address if resolution fails.
             */
            mn_mac resolve_src_mac() {
                #if LYNX_SRC_MAC_POLICY == SRC_MAC_IFACE
                    return mac_addr(true);
                #elif LYNX_SRC_MAC_POLICY == SRC_MAC_RANDOM
                    uint8_t u_dst_mac[6];
                    utils::codec::randomize_mac(u_dst_mac);
                    return mn_mac(u_dst_mac);
                #endif
            }
    };

} // namespace lynx

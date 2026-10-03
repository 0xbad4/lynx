#pragma once

/**
 * @file linux/socket.h
 * @brief Raw AF_PACKET socket primitives.
 *
 * Provides stateless, free-function helpers for low-level raw socket
 * operations.
 *
 * Every operation returns an @c Error object. Callers should check
 * @c Error::ok() and handle or absorb the error as appropriate.
 */

#include "lynx/protocols/all.h"
#include "lynx/core/utils.h"
#include "lynx/core/config/config.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/rtnetlink.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <netinet/in.h>

/**
 * @brief Linux raw socket helpers for AF_PACKET access.
 *
 * This namespace contains stateless helpers for opening, binding, configuring,
 * and using raw AF_PACKET sockets on Linux. The functions are designed to work
 * with the library's higher-level interface wrappers and use the common
 * @c lynx::Error reporting model for failure handling.
 */
namespace lynx::uni::sock {
    /**
     * @brief Invalid file descriptor sentinel used by socket wrappers.
     */
    static constexpr int INVALID_FD  = -1;

    /**
     * @brief Invalid interface index sentinel used by interface lookups.
     */
    static constexpr int INVALID_IDX = -1;

    /**
     * @brief Opens a raw AF_PACKET socket.
     *
     * Creates an AF_PACKET/SOCK_RAW socket configured to receive frames for all
     * Ethernet protocol types.
     *
     * On success, stores the resulting file descriptor in @p fd. On failure,
     * @p fd is set to @c INVALID_FD.
     *
     * @param fd Output file descriptor.
     *
     * @return An Error describing the result of the operation.
     */
    [[nodiscard]] inline Error open_raw(int& fd) noexcept {
        fd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

        if (fd < 0) {
            fd = INVALID_FD;
            return Error::make(status::SocketCreateFail, ::strerror(errno));
        }

        return Error::none();
    }

    /**
     * @brief Binds a raw socket to a specific network interface.
     *
     * Restricts frame reception to the interface identified by @p ifindex.
     *
     * @param fd Raw socket file descriptor.
     * @param ifindex Kernel interface index to bind the socket to.
     *
     * @return An Error describing the result of the operation.
     */
    [[nodiscard]] inline Error bind_to_iface(int fd, int ifindex) noexcept {
        ::sockaddr_ll sll{};
        sll.sll_family   = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex  = ifindex;

        if (::bind(fd, reinterpret_cast<const ::sockaddr*>(&sll), sizeof(sll)) < 0) {
            return Error::make(status::SocketBindFail, ::strerror(errno));
        }
        return Error::none();
    }

    /**
     * @brief Sends a raw Ethernet frame through the specified interface.
     *
     * Performs the underlying send operation using a single sendto() call.
     *
     * @param fd Raw socket file descriptor.
     * @param ifindex Kernel interface index used for transmission.
     * @param buf Buffer containing the complete Ethernet frame to send.
     * @param len Length of the frame in bytes.
     * @param dst_mac Destination MAC address used to populate the link-layer
     *                destination address.
     *
     * @return An Error describing the result of the operation.
     *
     * @note The destination MAC address must be resolved before calling this
     *       function.
     */
    [[nodiscard]] inline Error raw_send(int fd, int ifindex, const uint8_t* buf, uint32_t len, const uint8_t dst_mac[6]) noexcept {
        ::sockaddr_ll sll{};

        sll.sll_family   = AF_PACKET;
        sll.sll_ifindex  = ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_halen    = 6;

        utils::mem::copy(sll.sll_addr, dst_mac, 6);

        ssize_t sent = ::sendto(fd, buf, len, 0, reinterpret_cast<const ::sockaddr*>(&sll), sizeof(sll));

        if (sent < 0) {
            return Error::make(status::SendFail, ::strerror(errno));
        }

        if (static_cast<uint32_t>(sent) < len) {
            return Error::make(status::SendTruncated, "sendto() sent fewer bytes than requested");
        }

        return Error::none();
    }

    /**
     * @brief Receives a single raw Ethernet frame.
     *
     * Performs one recvfrom() operation and writes the received frame into
     * the supplied buffer.
     *
     * @param fd Raw socket file descriptor.
     * @param buf Destination buffer for the received frame.
     * @param cap Capacity of @p buf in bytes.
     * @param out_src_mac Optional output buffer receiving the source MAC address
     *                    obtained from the link-layer socket address.
     * @param err Error object populated when a hard receive error occurs.
     *
     * @return Number of bytes received if a frame was captured, @c 0 if the
     *         operation timed out or was interrupted, or @c -1 on a hard error.
     *
     * @note A return value of @c 0 is not an error and allows the caller to
     *       perform periodic stop-condition checks.
     */
    [[nodiscard]] inline int32_t raw_recv(int fd, uint8_t* buf, uint32_t cap, uint8_t out_src_mac[6], Error& err) noexcept {
        ::sockaddr_ll sll{};
        ::socklen_t   sll_len = sizeof(sll);

        ssize_t n = ::recvfrom(fd, buf, cap, 0, reinterpret_cast<::sockaddr*>(&sll), &sll_len);

        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR) {
                return 0;
            }

            err = Error::make(status::RecvFail, ::strerror(errno));
            
            return -1;
        }

        if (out_src_mac) {
            utils::mem::copy(out_src_mac, sll.sll_addr, 6);
        }

        return static_cast<int32_t>(n);
    }

    /**
     * @brief Closes a file descriptor and resets it to the invalid state.
     *
     * Safe to call multiple times. If the descriptor is already invalid, no
     * operation is performed.
     *
     * @param fd File descriptor to close.
     */
    inline void close_fd(int& fd) noexcept
    {
        if (fd != INVALID_FD) {
            ::close(fd);
            fd = INVALID_FD;
        }
    }

    /**
     * @brief Enables or disables promiscuous mode on a network interface.
     *
     * @param fd Raw socket file descriptor.
     * @param ifindex Kernel interface index.
     * @param enable @c true to enable promiscuous mode, @c false to disable it.
     *
     * @return An Error describing the result of the operation.
     *
     * @note Promiscuous mode should be disabled before closing the socket to
     *       restore the interface state.
     */
    [[nodiscard]] inline Error set_promiscuous(int  fd, int  ifindex, bool enable) noexcept {
        ::packet_mreq mreq{};
        mreq.mr_ifindex = ifindex;
        mreq.mr_type    = PACKET_MR_PROMISC;

        int opt = enable ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP;

        if (::setsockopt(fd, SOL_PACKET, opt, &mreq, sizeof(mreq)) < 0) {
            return Error::make(status::SocketOptionFail, ::strerror(errno));
        }

        return Error::none();
    }

    /**
     * @brief Configures the socket receive timeout.
     *
     * Sets the @c SO_RCVTIMEO socket option, causing receive operations to
     * periodically return so the capture loop can check its stop condition.
     *
     * A timeout of zero disables the receive timeout and causes receive
     * operations to block indefinitely.
     *
     * @param fd Raw socket file descriptor.
     * @param timeout_ms Receive timeout in milliseconds.
     *
     * @return An Error describing the result of the operation.
     */
    [[nodiscard]] inline Error set_recv_timeout(int fd, int timeout_ms) noexcept {
        ::timeval tv{};
        tv.tv_sec  =  timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            return Error::make(status::SocketOptionFail, ::strerror(errno));
        }

        return Error::none();
    }

    /**
     * @brief Configures the kernel receive buffer size.
     *
     * Sets the @c SO_RCVBUF socket option to control the size of the kernel-side
     * receive buffer.
     *
     * A value of zero leaves the socket's receive buffer at the kernel default
     * and returns without modifying the socket.
     *
     * @param fd Raw socket file descriptor.
     * @param size_bytes Receive buffer size in bytes.
     *
     * @return An Error describing the result of the operation.
     */
    [[nodiscard]] inline Error set_recv_buffer(int fd, int size_bytes) noexcept {
        if (size_bytes == 0) {
            return Error::none();
        }

        if (::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size_bytes, sizeof(size_bytes)) < 0) {
            return Error::make(status::SocketOptionFail, ::strerror(errno));
        }

        return Error::none();
    }

    /**
     * @brief Configures the io_direction of captured network traffic.
     *
     * @param fd Raw socket file descriptor.
     * @param dir Traffic io_direction to capture.
     *
     * @return An Error describing the result of the operation.
     *
     * @note io_direction::In uses PACKET_IGNORE_OUTGOING to exclude outgoing
     *       frames at the kernel level.
     * @note io_direction::Out leaves kernel filtering disabled and filters
     *       outgoing frames in the receive loop using sll_pkttype.
     * @note io_direction::Both captures both incoming and outgoing frames.
     */
    [[nodiscard]] inline Error set_io_direction(int fd, io_direction dir) noexcept {
        int ignore_out = (dir == io_direction::In) ? 1 : 0;

        if (dir != io_direction::Out) {
            if (::setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ignore_out, sizeof(ignore_out)) < 0) {
                return Error::make(status::SocketOptionFail, ::strerror(errno));
            }
        }
        return Error::none();
    }

    /**
     * \brief Attaches a compiled BPF filter program to a raw socket.
     * \param fd    Open AF_PACKET socket file descriptor.
     * \param insns Array of sock_filter instructions.
     * \param len   Number of instructions in \p insns.
     */
    [[nodiscard]] inline Error set_filter(int fd, const ::sock_filter* insns, uint16_t len) noexcept {
        ::sock_fprog prog{};
        prog.len    = len;
        prog.filter = const_cast<::sock_filter*>(insns);

        if (::setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0) {
            return Error::make(status::SocketOptionFail, ::strerror(errno));
        }

        return Error::none();
    }

    /**
     * \brief Removes any BPF filter attached to a socket.
     * \param fd  Open socket file descriptor.
     */
    [[nodiscard]] inline Error clear_filter(int fd) noexcept {
        int val = 0;
        if (::setsockopt(fd, SOL_SOCKET, SO_DETACH_FILTER, &val, sizeof(val)) < 0)
            return Error::make(status::SocketOptionFail, ::strerror(errno));

        return Error::none();
    }

    /**
     * @brief Resolves a network interface name to its kernel interface index.
     *
     * @param name Null-terminated name of the network interface.
     * @param idx Output interface index. Set to @c INVALID_IDX on failure.
     *
     * @return An Error describing the result of the operation.
     */
    [[nodiscard]] inline Error get_ifindex(const char* name, int& idx) noexcept {
        unsigned i = ::if_nametoindex(name);

        if (i == 0) {
            idx = INVALID_IDX;
            return Error::make(status::IfaceNotFound, "if_nametoindex: interface not found");
        }

        idx = static_cast<int>(i);
        return Error::none();
    }

    /**
     * \brief Retrieves the primary IPv4 address of an interface.
     * \param fd      Open socket file descriptor.
     * \param name    Null-terminated interface name.
     * \param out_ip  Output buffer of 4 bytes, network byte order.
     */
    [[nodiscard]] inline Error get_iface_ip(int fd, const char* name, uint8_t out_ip[4]) noexcept {
        ::ifreq ifr{};
        utils::mem::copy(ifr.ifr_name, name, IFNAMSIZ - 1);

        if (::ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
            return Error::make(status::IfaceNotFound, ::strerror(errno));
        }

        auto* sa = reinterpret_cast<::sockaddr_in*>(&ifr.ifr_addr);
        utils::mem::copy(out_ip, &sa->sin_addr.s_addr, 4);
        return Error::none();
    }

    /**
     * \brief Retrieves the default IPv4 gateway via netlink routing socket.
     * \param out_gw  Output buffer of 4 bytes, network byte order.
     */
    [[nodiscard]] inline Error get_default_gw(uint8_t out_gw[4]) noexcept {
        int fd = ::socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        if (fd < 0)
            return Error::make(status::SocketCreateFail, ::strerror(errno));

        struct {
            ::nlmsghdr  nlh;
            ::rtmsg     rtm;
        } req{};

        req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(::rtmsg));
        req.nlh.nlmsg_type  = RTM_GETROUTE;
        req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        req.nlh.nlmsg_seq   = 1;
        req.rtm.rtm_family  = AF_INET;
        req.rtm.rtm_table   = RT_TABLE_MAIN;

        if (::send(fd, &req, req.nlh.nlmsg_len, 0) < 0) {
            ::close(fd);
            return Error::make(status::SendFail, ::strerror(errno));
        }

        uint8_t buf[4096];
        bool    found = false;

        while (true) {
            ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n < 0) {
                ::close(fd);
                return Error::make(status::RecvFail, ::strerror(errno));
            }

            auto* nlh = reinterpret_cast<::nlmsghdr*>(buf);

            for (; NLMSG_OK(nlh, static_cast<uint32_t>(n)); nlh = NLMSG_NEXT(nlh, n)) {
                if (nlh->nlmsg_type == NLMSG_DONE)  goto done;
                if (nlh->nlmsg_type == NLMSG_ERROR) goto done;
                if (nlh->nlmsg_type != RTM_NEWROUTE) continue;

                auto* rtm = static_cast<::rtmsg*>(NLMSG_DATA(nlh));

                // only interested in the main table default route (dst_len == 0)
                if (rtm->rtm_table  != RT_TABLE_MAIN) continue;
                if (rtm->rtm_family != AF_INET)        continue;
                if (rtm->rtm_dst_len != 0)             continue;

                int   attr_len = RTM_PAYLOAD(nlh);
                auto* rta      = RTM_RTA(rtm);

                for (; RTA_OK(rta, attr_len); rta = RTA_NEXT(rta, attr_len)) {
                    if (rta->rta_type != RTA_GATEWAY) continue;
                    utils::mem::copy(out_gw, RTA_DATA(rta), 4);
                    found = true;
                    goto done;
                }
            }
        }

    done:
        ::close(fd);
        return found ? Error::none()
                    : Error::make(status::IfaceNotFound, "no default gateway");
    }

    /**
     * @brief Retrieves the hardware MAC address of a network interface.
     *
     * Uses SIOCGIFHWADDR to query the interface hardware address.
     *
     * @param fd Socket file descriptor used to perform the interface query.
     * @param name Null-terminated name of the network interface.
     * @param out_mac Output buffer receiving the six-byte MAC address.
     *
     * @return An Error describing the result of the operation.
     */
    [[nodiscard]] inline Error get_iface_mac(int fd, const char* name, uint8_t out_mac[6]) noexcept {
        ::ifreq ifr{};
        utils::mem::copy(ifr.ifr_name, name, IFNAMSIZ - 1);

        if (::ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
            return Error::make(status::MacResolveFail, ::strerror(errno));

        utils::mem::copy(out_mac, ifr.ifr_hwaddr.sa_data, 6);
        return Error::none();
    }

    /**
     * \brief Retrieves the MTU of an interface.
     * \param fd       Open socket file descriptor.
     * \param name     Null-terminated interface name.
     * \param out_mtu  Receives the MTU value in bytes.
     */
    [[nodiscard]] inline Error get_iface_mtu(int fd, const char* name, uint32_t& out_mtu) noexcept {
        ::ifreq ifr{};
        utils::mem::copy(ifr.ifr_name, name, IFNAMSIZ - 1);

        if (::ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
            return Error::make(status::IfaceNotFound, ::strerror(errno));
        }

        out_mtu = static_cast<uint32_t>(ifr.ifr_mtu);
        return Error::none();
    }

    /**
     * \brief Retrieves the interface flags (IFF_UP, IFF_RUNNING, IFF_PROMISC, etc.).
     * \param fd        Open socket file descriptor.
     * \param name      Null-terminated interface name.
     * \param out_flags Receives the IFF_* bitmask.
     */
    [[nodiscard]] inline Error get_iface_flags(int fd, const char* name, uint32_t& out_flags) noexcept {
        ::ifreq ifr{};
        utils::mem::copy(ifr.ifr_name, name, IFNAMSIZ - 1);

        if (::ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
            return Error::make(status::IfaceNotFound, ::strerror(errno));

        out_flags = static_cast<uint32_t>(ifr.ifr_flags);
        return Error::none();
    }

    /**
     * @brief Looks up a destination MAC address in the kernel ARP cache.
     *
     * Performs a pure ARP cache lookup using SIOCGARP. No ARP request or other
     * network traffic is generated.
     *
     * @param fd Open AF_PACKET socket used to perform the lookup.
     * @param iface Name of the network interface on which the lookup is scoped.
     * @param dst_ip Destination IPv4 address in network byte order.
     * @param out_mac Output buffer receiving the six-byte MAC address on success.
     *
     * @return An Error describing the result of the operation. Returns
     *         @c Error::ArpResolveFail if no complete ARP cache entry exists
     *         for the destination.
     *
     * @note The destination must have a complete ARP cache entry. An entry that
     *       has not yet been resolved is treated as a lookup failure.
     */
    [[nodiscard]] inline Error get_arp_entry(int fd, const char* iface, const uint8_t dst_ip[4], uint8_t out_mac[6]) noexcept {
        if (!dst_ip || !out_mac) {
            return Error::make(status::InvalidArgument, "get_arp_entry: null dst_ip or out_mac");
        }
    
        ::arpreq req{};
    
        // target IP - stored in arp_pa as sockaddr_in
        auto* sin = reinterpret_cast<::sockaddr_in*>(&req.arp_pa);
        sin->sin_family = AF_INET;
        utils::mem::copy(&sin->sin_addr.s_addr, dst_ip, 4);
    
        // scope to interface - without this the kernel may return an entry
        // from a different NIC that has the same IP in its cache
        utils::mem::copy(req.arp_dev, iface, sizeof(req.arp_dev) - 1);
    
        if (::ioctl(fd, SIOCGARP, &req) < 0)
            return Error::make(status::ArpResolveFail, ::strerror(errno));
    
        // ATF_COM: entry is complete and MAC is valid.
        // entries without ATF_COM exist but have no resolved MAC yet.
        if (!(req.arp_flags & ATF_COM)) {
            return Error::make(status::ArpResolveFail, "get_arp_entry: entry incomplete (ATF_COM not set)");
        }
    
        utils::mem::copy(out_mac, req.arp_ha.sa_data, 6);
        return Error::none();
    }

    /**
     * \brief Returns a random ephemeral port in the kernel's local port range.
     * \details Reads /proc/sys/net/ipv4/ip_local_port_range. Falls back to
     *          32768-60999 if the file is unreadable.
     * \param out_port  Receives the port number in host byte order.
     */
    [[nodiscard]] inline Error get_random_port(uint16_t& out_port) noexcept {
        uint32_t lo = 32768;
        uint32_t hi = 60999;

        FILE* f = ::fopen("/proc/sys/net/ipv4/ip_local_port_range", "r");
        if (f) {
            ::fscanf(f, "%u %u", &lo, &hi);
            ::fclose(f);
        }

        if (hi <= lo)
            return Error::make(status::InvalidState, "invalid port range");

        static bool seeded = false;
        if (!seeded) {
            ::srand(static_cast<unsigned>(::time(nullptr)) ^
                    static_cast<unsigned>(::getpid()));
            seeded = true;
        }

        out_port = static_cast<uint16_t>(
            lo + (static_cast<uint32_t>(::rand()) % (hi - lo + 1)));
        return Error::none();
    }

    /**
     * @brief Generates a random locally administered unicast MAC address.
     *
     * Generates the address using system randomness from @c /dev/urandom.
     * If @c /dev/urandom is unavailable, a stack-address-derived value is used
     * as a fallback.
     *
     * @param out_mac Output buffer receiving the six-byte MAC address.
     *
     * @return Always returns @c Error::none(). The return value is kept for
     *         consistency with other socket helpers.
     */
    [[nodiscard]] inline Error get_random_mac(uint8_t out_mac[6]) noexcept {
        int urfd = ::open("/dev/urandom", O_RDONLY);

        if (urfd >= 0) {
            ::read(urfd, out_mac, 6);
            ::close(urfd);
        } 
        else {
            uintptr_t seed = reinterpret_cast<uintptr_t>(out_mac);

            for (int i = 0; i < 6; ++i) {
                seed ^= (seed >> 13) ^ (seed << 7);
                out_mac[i] = static_cast<uint8_t>(seed & 0xff);
            }
        }
        out_mac[0] &= 0xFE;   // bit 0 = 0 → unicast
        out_mac[0] |= 0x02;   // bit 1 = 1 → locally administered

        return Error::none();
    }

    /**
     * \brief Checks whether a network interface is up and running.
     * \details Combines IFF_UP and IFF_RUNNING flag checks. An interface that
     *          is administratively up but has no carrier sets false.
     * \param fd Open socket file descriptor.
     * \param name Null-terminated interface name.
     */
    [[nodiscard]] inline Error iface_is_up(int fd, const char *name, bool& out_result) noexcept {
        uint32_t flags = 0;
        auto err = get_iface_flags(fd, name, flags);

        if (!err.ok()) {
            return err;
        }

        out_result = (flags & IFF_UP) && (flags & IFF_RUNNING);
        return Error::none();
    }

    /**
     * \brief Checks whether a port falls within the kernel ephemeral range.
     * \details Reads /proc/sys/net/ipv4/ip_local_port_range. Falls back to
     *          32768-60999 if the file is unreadable.
     * \param port      Port number in host byte order.
     * \param out_result  Receives true if \p port is ephemeral.
     */
    [[nodiscard]] inline Error is_ephemeral_port(uint16_t port, bool& out_result) noexcept {
        uint32_t lo = 32768;
        uint32_t hi = 60999;

        FILE* f = ::fopen("/proc/sys/net/ipv4/ip_local_port_range", "r");
        if (f) {
            ::fscanf(f, "%u %u", &lo, &hi);
            ::fclose(f);
        }

        out_result = port >= static_cast<uint16_t>(lo) &&
                    port <= static_cast<uint16_t>(hi);
        return Error::none();
    }

} // namespace lynx::uni::sock

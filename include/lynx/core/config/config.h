#pragma once

/**
 * @file config/config.h
 * @brief Compile-time configuration options.
 *
 * This file defines the compile-time configuration macros used to customize
 * lynx behavior.
 *
 * Configuration must be applied before including the main lynx header.
 * All options are resolved at compile time and introduce no runtime overhead.
 */

#include "lynx/core/config/opt.h"

namespace lynx
{
    /**
     * @brief Configures the destination MAC address resolution policy.
     *
     * This policy is used by packet transmission functions when no Ethernet
     * frame with an explicit destination MAC address is provided.
     *
     * Available policies:
     *
     * - @c DST_MAC_BROADCAST
     *   Always uses the Ethernet broadcast address
     *   @c ff:ff:ff:ff:ff:ff. No ARP lookup is required.
     *
     * - @c DST_MAC_ARP_CACHE
     *   Resolves the destination MAC address from the destination IPv4 address
     *   using the kernel ARP cache. If no valid ARP cache entry
     *   exists, transmission fails with @c Status::ArpResolveFail.
     *
     * @note This is a compile-time configuration option.
     */
    #ifndef LYNX_DST_MAC_POLICY
    #define LYNX_DST_MAC_POLICY DST_MAC_ARP_CACHE
    #endif

    /**
     * @def LYNX_SRC_MAC_POLICY
     * @brief Selects the source MAC address resolution policy.
     *
     * Controls which MAC address is placed in the Ethernet source field when
     * Interface automatically wraps a Packet in an EtherFrame.
     *
     * Supported values:
     *
     * - @c SRC_MAC_IFACE
     *   Uses the hardware MAC address of the bound network interface.
     *   This is the default and most compatible option.
     *
     * - @c SRC_MAC_RANDOM
     *   Generates a random locally administered unicast MAC address for each
     *   packet. The locally administered bit is set and the multicast bit is
     *   cleared.
     *
     * @note This option is only used when the Ethernet source MAC address has
     *       not been explicitly provided.
     */
    #ifndef LYNX_SRC_MAC_POLICY
    #define LYNX_SRC_MAC_POLICY SRC_MAC_IFACE
    #endif

    /**
     * @def LYNX_RECV_BUFFER_SIZE
     * @brief Sets the kernel-side socket receive buffer size in bytes.
     *
     * A larger buffer can reduce packet drops under high traffic at the cost of
     * increased memory usage.
     *
     * A value of @c 0 leaves the receive buffer at the kernel default.
     *
     * @note This is a compile-time configuration option.
     */
    #ifndef LYNX_RECV_BUFFER_SIZE
    #define LYNX_RECV_BUFFER_SIZE 0
    #endif

    /**
     * @def LYNX_DEFAULT_SNAPLEN
     * @brief Sets the maximum number of bytes captured per frame.
     *
     * A value of @c 65535 allows complete Ethernet frames to be captured,
     * including jumbo frames.
     *
     * Lower values can reduce the per-packet copy cost when only packet headers
     * are required.
     *
     * @note This is a compile-time configuration option.
     */
    #ifndef LYNX_DEFAULT_SNAPLEN
    #define LYNX_DEFAULT_SNAPLEN 65535
    #endif

    /**
     * @def LYNX_DEFAULT_TIMEOUT_MS
     * @brief Sets the default receive timeout in milliseconds.
     *
     * Determines how frequently a blocking receive operation wakes up to check
     * the capture stop condition.
     *
     * Lower values make @c stop() more responsive, while higher values reduce
     * periodic wakeups.
     *
     * Defaults to @c 100 milliseconds.
     */
    #ifndef LYNX_DEFAULT_TIMEOUT_MS
    #define LYNX_DEFAULT_TIMEOUT_MS 100
    #endif

    /**
     * @def LYNX_CLOSE_ON_DESTROY
     * @brief Controls whether the network socket is closed on destruction.
     *
     * - @c 1 - Close the socket in the destructor.
     * - @c 0 - Leave the socket open when the object is destroyed.
     *
     * The default value of @c 1 provides automatic resource cleanup and prevents
     * file descriptor leaks.
     */
    #ifndef LYNX_CLOSE_ON_DESTROY
    #define LYNX_CLOSE_ON_DESTROY 1
    #endif

    /**
     * @brief Maximum number of bytes sent in a single send operation.
     *
     * Buffers larger than this threshold are sent in chunks.
     */
    #ifndef LYNX_SEND_THRESHOLD
    #define LYNX_SEND_THRESHOLD 1024
    #endif

    /**
     * @brief Maximum number of consecutive receive retries.
     *
     * Limits retries for interrupted or temporarily unavailable receive
     * operations before the receive operation fails.
     */
    #ifndef LYNX_MAX_READ_RETRIES
    #define LYNX_MAX_READ_RETRIES 8
    #endif
} // namespace lynx

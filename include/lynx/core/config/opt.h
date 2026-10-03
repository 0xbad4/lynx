#pragma once

namespace lynx
{
    
    /**
     * @def DST_MAC_BROADCAST
     * @brief Always use the Ethernet broadcast address as the destination MAC.
     */
    #define DST_MAC_BROADCAST 1

    /**
     * @def DST_MAC_ARP_CACHE
     * @brief Resolve the destination MAC address from the destination IP using
     *        the kernel ARP cache.
     */
    #define DST_MAC_ARP_CACHE 2

    /**
     * @def SRC_MAC_IFACE
     * @brief Use the hardware MAC address of the bound interface.
     */
    #define SRC_MAC_IFACE 3 

    /**
     * @def SRC_MAC_RANDOM
     * @brief Generate a random locally administered unicast MAC address.
     */
    #define SRC_MAC_RANDOM 4

    
} // namespace lynx

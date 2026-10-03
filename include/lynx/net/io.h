#pragma once

#if defined(__linux__)
    #include "lynx/net/platform/linux/iface.h"
    #include "lynx/net/platform/linux/socket.h"
#else
    #error "lynx::io is only supported on Linux (for now)"
#endif

namespace lynx
{

    #if defined(__linux__)
    /**
     * @brief Platform-agnostic socket namespace.
     *
     * On Linux, this namespace aliases the raw socket helpers exposed by
     * @c lynx::uni::sock so callers can use a stable API name independent of the
     * platform implementation details.
     */
    namespace sock {
        /**
         * @brief Imports the Linux raw socket helpers into the portable namespace.
         */
        using namespace uni::sock;
    }
    #endif

    /**
     * @brief Platform-agnostic network interface namespace.
     *
     * This namespace provides a portable interface name for the underlying
     * platform-specific implementation.
     */
    namespace io {
        #if defined(__linux__)
        /**
         * @brief Alias for the Linux network interface implementation.
         */
        using Interface = uni::io::UniInterface;
        #endif
    }

}

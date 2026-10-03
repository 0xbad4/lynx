// RFC-5072
#pragma once

#include "lynx/protocols/ll/ppp/ppp.h"

namespace lynx::proto 
{
    // Codes
    icu8 IPV6CP_CODE_CONF_REQ = 1;
    icu8 IPV6CP_CODE_CONF_ACK = 2;
    icu8 IPV6CP_CODE_CONF_NAK = 3;
    icu8 IPV6CP_CODE_CONF_REJ = 4;
    icu8 IPV6CP_CODE_TERM_REQ = 5;
    icu8 IPV6CP_CODE_TERM_ACK = 6;
    icu8 IPV6CP_CODE_CODE_REJ = 7;

    // Options/Types
    icu8 IPV6CP_OPT_IFID     = 1; /// Interface-Identifier
    icu8 IPV6CP_OPT_COMPRESS = 2; /// IPv6-Compression-Protocols
    
    /**
    * @brief Represents the PPP IPv6 Control Protocol (IPv6CP).
    *
    * Uses the generic PPP sub-protocol implementation provided by @c PPPc.
    *
    * @note This class has no additional data members because the @c PPPc
    * implementation is sufficient for IPv6CP packet representation.
    * Use @c get<TLV>() to obtain a TLV support class for accessing
    * protocol-specific IPv6CP options.
    */
    class IPv6CP : public ppp::GenCtrl {
        public:
            using ppp::GenCtrl::GenCtrl;

            [[nodiscard]] uint16_t protocol() const noexcept override {
                return PPP_PROTO_IPV6CP;
            }
    };
}
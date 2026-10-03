// RFC-1332
#pragma once

#include "lynx/protocols/ll/ppp/ppp.h"

namespace lynx::proto 
{
    // Codes
    icu8 IPCP_CODE_CONF_REQ = 1;
    icu8 IPCP_CODE_CONF_ACK = 2;
    icu8 IPCP_CODE_CONF_NAK = 3;
    icu8 IPCP_CODE_CONF_REJ = 4;
    icu8 IPCP_CODE_TERM_REQ = 5;
    icu8 IPCP_CODE_TERM_ACK = 6;
    icu8 IPCP_CODE_CODE_REJ = 7;

    // Options/Types
    icu8 IPCP_OPT_ADDRS    = 1;   /// IP addresses (deprecated; kept for backward compatibility)
    icu8 IPCP_OPT_COMPRESS = 2;   /// IP compression protocol
    icu8 IPCP_OPT_ADDR     = 3;   /// IP address (4B)
    icu8 IPCP_OPT_DNS1     = 129; /// primary DNS server
    icu8 IPCP_OPT_NBNS1    = 130; /// primary NBNS server
    icu8 IPCP_OPT_DNS2     = 131; /// secondary DNS server
    icu8 IPCP_OPT_NBNS2    = 132; /// secondary NBNS server
    
    /**
    * @brief Represents the PPP IP Control Protocol (IPCP).
    *
    * Uses the generic PPP sub-protocol implementation provided by @c PPPc.
    *
    * @note This class has no additional data members because the @c PPPc
    * implementation is sufficient for IPCP packet representation.
    * Use @c get<TLV>() to obtain a TLV support class for accessing
    * protocol-specific IPCP options.
    */
    class IPCP : public ppp::GenCtrl {
        public:
            using ppp::GenCtrl::GenCtrl;

            [[nodiscard]] uint16_t protocol() const noexcept override {
                return PPP_PROTO_IPCP;
            }
    };
}
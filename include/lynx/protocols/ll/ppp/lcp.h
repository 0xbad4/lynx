// RFC-1661
#pragma once

#include "lynx/protocols/ll/ppp/ppp.h"

namespace lynx::proto {

    // Codes
    icu8 LCP_CODE_CONF_REQ  = 1;
    icu8 LCP_CODE_CONF_ACK  = 2;
    icu8 LCP_CODE_CONF_NAK  = 3;
    icu8 LCP_CODE_CONF_REJ  = 4;
    icu8 LCP_CODE_TERM_REQ  = 5;
    icu8 LCP_CODE_TERM_ACK  = 6;
    icu8 LCP_CODE_CODE_REJ  = 7;
    icu8 LCP_CODE_PROTO_REJ = 8;
    icu8 LCP_CODE_ECHO_REQ  = 9;
    icu8 LCP_CODE_ECHO_REP  = 10;
    icu8 LCP_CODE_DISCARD   = 11;

    // TLVs types/options
    icu8  LCP_OPT_MRU     = 1;   // maximum receive unit
    icu8  LCP_OPT_ACCM    = 2;   // async-control-character-map
    icu8  LCP_OPT_AUTH    = 3;   // auth protocol
    icu8  LCP_OPT_QUALITY = 4;   // link quality monitoring
    icu8  LCP_OPT_MAGIC   = 5;   // magic number
    icu8  LCP_OPT_PFC     = 7;   // protocol field compression
    icu8  LCP_OPT_ACFC    = 8;   // address/control field compression
    
    /**
    * @brief Represents the PPP Link Control Protocol (LCP).
    *
    * Uses the generic PPP sub-protocol implementation provided by @c PPPsp.
    *
    * @note This class has no additional data members because the @c PPPsp
    *       implementation is sufficient for LCP packet representation.
    *       Use @c get<TLV>() to obtain a TLV support class for accessing
    *       protocol-specific LCP options.
    */
    class LCP : public ppp::GenCtrl {
        public:
            using ppp::GenCtrl::GenCtrl;

            [[nodiscard]] uint16_t protocol() const noexcept override {
                return PPP_PROTO_LCP;
            }
    };
}
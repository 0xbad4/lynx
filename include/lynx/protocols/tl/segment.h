#pragma once


#include "lynx/core/base/proto.h"


namespace lynx::proto
{
    class Segment : public ProtocolBaseObject {
        public:
            /**
             * @brief IP protocol number, TCP / UDP / ICMP etc.
             */
            [[nodiscard]] virtual uint8_t proto() const noexcept = 0;
    };
} // namespace lynx::proto

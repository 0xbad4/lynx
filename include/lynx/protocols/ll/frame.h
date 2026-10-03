#pragma once

#include "lynx/core/base/proto.h"


namespace lynx::proto
{
    class Frame : public ProtocolBaseObject {
        public:
            virtual ~Frame() = default;
            
            /**
             * @brief Returns the link-layer frame type.
             *
             * @return Frame type.
             */
            virtual frame_type type() const noexcept = 0;
    };
} // namespace lynx::proto

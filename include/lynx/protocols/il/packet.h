#pragma once

#include "lynx/core/base/proto.h"

namespace lynx::proto
{
    class Packet : public ProtocolBaseObject {
        public:
            /**
             * @brief ethertype to place in the Ethernet header wrapping this packet.
             */
            [[nodiscard]] virtual uint16_t ethertype() const noexcept = 0;

            /**
             * @brief Returns the destination address of this packet.
             *
             * For protocols that do not have a destination address, returns @c nullptr.
             *
             * @return Pointer to the destination address, or @c nullptr if not applicable.
             */
            [[nodiscard]] virtual const uint8_t* adst() noexcept {
                return nullptr;
            }
            
            /**
             * @brief overriden to true for protocols that always broadcast (ARP requests)
             * when true: Interface sets dst MAC = ff:ff:ff:ff:ff:ff, dst() ignored
             */
            [[nodiscard]] virtual bool is_broadcast() const noexcept { return false; }
        
    };
} // namespace lynx::proto

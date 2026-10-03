// RFC-2516

#include "lynx/protocols/ll/ppp/ppp.h"

namespace lynx::proto
{

    icu32 PPPOE_HDR_LEN = 0x0006;
    icu8 PPPOE_VERSION  = 0x01;
    icu8 PPPOE_TYPE     = 0x01;
    
    // Ethertypes
    icu16 PPPOE_ETHERTYPE_DISC    = 0x8863;
    icu16 PPPOE_ETHERTYPE_SESSION = 0x8864;

    // Codes
    icu8 PPPOE_CODE_SESSION      = 0x00;  // session data
    icu8 PPPOE_CODE_PADI         = 0x09;  // discovery initiation
    icu8 PPPOE_CODE_PADO         = 0x07;  // discovery offer
    icu8 PPPOE_CODE_PADR         = 0x19;  // discovery request
    icu8 PPPOE_CODE_PADS         = 0x65;  // session confirmed
    icu8 PPPOE_CODE_PADT         = 0xA7;  // terminate


    // TLV tag types (discovery phase only)
    inline constexpr uint16_t PPPOE_TAG_EOL           = 0x0000;  // end of list
    inline constexpr uint16_t PPPOE_TAG_SVC_NAME      = 0x0101;  // service name
    inline constexpr uint16_t PPPOE_TAG_AC_NAME       = 0x0102;  // access concentrator name
    inline constexpr uint16_t PPPOE_TAG_HOST_UNIQ     = 0x0103;  // host unique (arbitrary bytes)
    inline constexpr uint16_t PPPOE_TAG_AC_COOKIE     = 0x0104;  // AC cookie (replay protection)
    inline constexpr uint16_t PPPOE_TAG_VENDOR        = 0x0105;  // vendor specific
    inline constexpr uint16_t PPPOE_TAG_SVC_ERR       = 0x0201;  // service name error
    inline constexpr uint16_t PPPOE_TAG_AC_ERR        = 0x0202;  // AC system error
    inline constexpr uint16_t PPPOE_TAG_GENERIC_ERR   = 0x0203;  // generic error
 

    class PPPoE : public ProtocolBaseObject {
        public:
            PPPoE(const view& v) noexcept { 
                dissect(v);
            }

            /**
             * @brief Constructs a PPPoE packet.
             *
             * Initializes the PPPoE header using the protocol-defined version and type.
             * The packet code and session identifier are supplied by the caller.
             * The payload length is initialized to zero.
             *
             * @param c PPPoE code.
             * @param si PPPoE session identifier.
             */
            PPPoE(uint8_t c = 0, uint16_t si = 0) noexcept {
                // init header.
                INIT_HDR

                if (!ok()) {
                    return;
                }

                // set attrs.
                version(PPPOE_VERSION);
                type(PPPOE_TYPE);
                code(c);
                sid(si);
            }

            [[nodiscard]] uint32_t hsize() const noexcept {
                return PPPOE_HDR_LEN;
            }

            /**
             * @brief Sets the PPPoE version field.
             * @param v Version value to set.
             */
            void version(uint8_t v) {
                uint8_t o = m_origin_view[0];
                o &= 0x0F;
                o |= ((v << 4) & 0xF0);
                m_origin_view[0] = o;
            }

            /**
             * @brief Gets the PPPoE version field.
             * @return The PPPoE version.
             */
            uint8_t version() {
                return (m_origin_view[0] >> 4) & 0x0F;
            }

            /**
             * @brief Sets the PPPoE type field.
             * @param t Type value to set.
             */
            void type(uint8_t t) {
                uint8_t o = m_origin_view[0];
                o &= 0xF0;
                o |= t & 0x0F;
                m_origin_view[0] = o;
            }

            /**
             * @brief Gets the PPPoE type field.
             * @return The PPPoE type.
             */
            uint8_t type() {
                return m_origin_view[0] & 0x0F;
            }

            /**
             * @brief Sets the PPPoE code field.
             * @param c Code value to set.
             */
            void code(uint8_t c) {
                m_origin_view[1] = c;
            }

            /**
             * @brief Gets the PPPoE code field.
             * @return The PPPoE code.
             */
            uint8_t code() {
                return m_origin_view[1];
            }

            /**
             * @brief Sets the PPPoE session identifier.
             * @param si Session identifier in host byte order.
             */
            void sid(uint16_t si) {
                uint16_t sn = utils::mem::bswap<uint16_t>(si);
                utils::mem::copy(m_origin_view.begin() + 2, &sn, 2);
            }

            /**
             * @brief Gets the PPPoE session identifier.
             * @return The session identifier in host byte order.
             */
            uint16_t sid() {
                uint16_t si = 0;
                utils::mem::copy(&si, m_origin_view.begin() + 2, 2);
                return utils::mem::bswap<uint16_t>(si);
            }

            /**
             * @brief Sets the PPPoE payload length.
             * @param len Payload length in host byte order.
             */
            void length(uint16_t len) {
                uint16_t ln = utils::mem::bswap<uint16_t>(len);
                utils::mem::copy(m_origin_view.begin() + 4, &ln, 2);
            }

            /**
             * @brief Gets the PPPoE payload length.
             * @return The payload length in host byte order.
             */
            uint16_t length() {
                uint16_t len = 0;
                utils::mem::copy(&len, m_origin_view.begin() + 4, 2);
                return utils::mem::bswap<uint16_t>(len);
            }

            /**
             * @brief Checks whether the PPPoE packet uses session-stage framing.
             *  @return @c true if the packet is a PPPoE session packet.
             */
            [[nodiscard]] bool is_session() noexcept {
                return code() == PPPOE_CODE_SESSION;
            }
    };
} // namespace lynx::proto

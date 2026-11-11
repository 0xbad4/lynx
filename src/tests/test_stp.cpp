#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include <lynx/lynx>

using namespace lynx;
using namespace lynx::utils;
using namespace lynx::proto;

// ---------------------------------------------------------------------------
// STP – IEEE 802.1D Configuration BPDU
// ---------------------------------------------------------------------------

TEST_CASE("STP: basic parsing from raw bytes") {
    // A minimal but valid IEEE 802.1D Configuration BPDU (35 bytes).
    unsigned char bytes[] = {
        0x00, 0x00,                          // protocol_id
        0x00,                                // version = STP
        0x00,                                // type = Config
        0x01,                                // flags = TC
        0x80, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // root_id
        0x00, 0x00, 0x00, 0x64,              // root_path_cost = 100
        0x80, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // bridge_id
        0x80, 0x01,                          // port_id
        0x01, 0x00,                          // message_age = 256
        0x14, 0x00,                          // max_age     = 5120
        0x02, 0x00,                          // hello_time  = 512
        0x0F, 0x00,                          // forward_delay = 3840
    };

    STP stp(view(bytes, sizeof(bytes)));
    CHECK(stp.ok());
    CHECK(stp.hsize() == STP_HDR_LEN);

    CHECK(stp.protocol_id()   == STP_PROTO_ID);
    CHECK(stp.version()        == STP_VERSION_STP);
    CHECK(stp.type()           == STP_TYPE_CONFIG);
    CHECK(stp.flags()          == STP_FLAG_TOPOLOGY_CHANGE);
    CHECK(stp.root_path_cost() == 100);
    CHECK(stp.port_id()        == 0x8001);
    CHECK(stp.message_age()    == 256);
    CHECK(stp.max_age()        == 5120);
    CHECK(stp.hello_time()     == 512);
    CHECK(stp.forward_delay()  == 3840);
}

TEST_CASE("STP: flag bit accessors") {
    SUBCASE("topology_change") {
        unsigned char bytes[STP_HDR_LEN] = {};
        bytes[4] = STP_FLAG_TOPOLOGY_CHANGE;
        STP stp(view(bytes, sizeof(bytes)));
        CHECK(stp.topology_change());
        CHECK_FALSE(stp.proposal());
        CHECK_FALSE(stp.learning());
        CHECK_FALSE(stp.forwarding());
        CHECK_FALSE(stp.agreement());
        CHECK_FALSE(stp.topology_change_ack());
    }

    SUBCASE("all flags set") {
        unsigned char bytes[STP_HDR_LEN] = {};
        bytes[4] = 0xFF;
        STP stp(view(bytes, sizeof(bytes)));
        CHECK(stp.topology_change());
        CHECK(stp.proposal());
        CHECK(stp.learning());
        CHECK(stp.forwarding());
        CHECK(stp.agreement());
        CHECK(stp.topology_change_ack());
    }

    SUBCASE("port_role extracted from flags") {
        unsigned char bytes[STP_HDR_LEN] = {};
        // port role = designated (3) => bits [3:2] = 0b11 => 0x0C
        bytes[4] = static_cast<uint8_t>(STP_PORT_ROLE_DESIGNATED << STP_FLAG_PORT_ROLE_SHIFT);
        STP stp(view(bytes, sizeof(bytes)));
        CHECK(stp.port_role() == STP_PORT_ROLE_DESIGNATED);
    }
}

TEST_CASE("STP: root_id / root_priority / root_mac") {
    // root_id = priority 0x8001 | MAC 00:11:22:33:44:55
    unsigned char bytes[STP_HDR_LEN] = {};
    bytes[5] = 0x80; bytes[6] = 0x01;
    uint8_t mac_b[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    memcpy(bytes + 7, mac_b, 6);

    STP stp(view(bytes, sizeof(bytes)));
    CHECK(stp.root_priority() == 0x8001);
    CHECK(stp.root_mac() == mn_mac(mac_b));
}

TEST_CASE("STP: bridge_id / bridge_priority / bridge_mac") {
    unsigned char bytes[STP_HDR_LEN] = {};
    bytes[17] = 0x80; bytes[18] = 0x01;
    uint8_t mac_b[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    memcpy(bytes + 19, mac_b, 6);

    STP stp(view(bytes, sizeof(bytes)));
    CHECK(stp.bridge_priority() == 0x8001);
    CHECK(stp.bridge_mac() == mn_mac(mac_b));
}

TEST_CASE("STP: craft constructor sets all fields") {
    uint8_t root_mac_b[6]   = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t bridge_mac_b[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    uint64_t root_id   = (uint64_t(0x8001) << 48)
                       | (uint64_t(0x00) << 40) | (uint64_t(0x11) << 32)
                       | (uint64_t(0x22) << 24) | (uint64_t(0x33) << 16)
                       | (uint64_t(0x44) <<  8) |  uint64_t(0x55);
    uint64_t bridge_id = (uint64_t(0x8001) << 48)
                       | (uint64_t(0xAA) << 40) | (uint64_t(0xBB) << 32)
                       | (uint64_t(0xCC) << 24) | (uint64_t(0xDD) << 16)
                       | (uint64_t(0xEE) <<  8) |  uint64_t(0xFF);

    STP stp(STP_VERSION_STP, STP_TYPE_CONFIG, STP_FLAG_TOPOLOGY_CHANGE,
            root_id, /*root_path_cost=*/200,
            bridge_id, /*port_id=*/0x8002,
            /*message_age=*/256, /*max_age=*/5120,
            /*hello_time=*/512, /*forward_delay=*/3840);

    CHECK(stp.ok());
    CHECK(stp.protocol_id()    == STP_PROTO_ID);
    CHECK(stp.version()         == STP_VERSION_STP);
    CHECK(stp.type()            == STP_TYPE_CONFIG);
    CHECK(stp.flags()           == STP_FLAG_TOPOLOGY_CHANGE);
    CHECK(stp.root_id()         == root_id);
    CHECK(stp.root_path_cost()  == 200);
    CHECK(stp.bridge_id()       == bridge_id);
    CHECK(stp.port_id()         == 0x8002);
    CHECK(stp.message_age()     == 256);
    CHECK(stp.max_age()         == 5120);
    CHECK(stp.hello_time()      == 512);
    CHECK(stp.forward_delay()   == 3840);
    CHECK(stp.root_priority()   == 0x8001);
    CHECK(stp.bridge_priority() == 0x8001);
    CHECK(stp.root_mac()        == mn_mac(root_mac_b));
    CHECK(stp.bridge_mac()      == mn_mac(bridge_mac_b));
}

TEST_CASE("STP: setter round-trips") {
    STP stp;
    CHECK(stp.ok());

    stp.flags(STP_FLAG_FORWARDING | STP_FLAG_LEARNING);
    CHECK(stp.forwarding());
    CHECK(stp.learning());
    CHECK_FALSE(stp.proposal());

    stp.root_path_cost(4000);
    CHECK(stp.root_path_cost() == 4000);

    stp.port_id(0x1234);
    CHECK(stp.port_id() == 0x1234);

    stp.message_age(0);
    CHECK(stp.message_age() == 0);

    uint8_t new_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    stp.root_mac(mn_mac(new_mac));
    CHECK(stp.root_mac() == mn_mac(new_mac));

    stp.bridge_mac(mn_mac(new_mac));
    CHECK(stp.bridge_mac() == mn_mac(new_mac));

    stp.root_priority(0x1000);
    CHECK(stp.root_priority() == 0x1000);

    stp.bridge_priority(0x2000);
    CHECK(stp.bridge_priority() == 0x2000);

    stp.port_role(STP_PORT_ROLE_ROOT);
    CHECK(stp.port_role() == STP_PORT_ROLE_ROOT);
}

TEST_CASE("STP: port_role does not clobber other flag bits") {
    STP stp;
    CHECK(stp.ok());

    stp.flags(0xFF);
    stp.port_role(STP_PORT_ROLE_ALTERNATE);
    CHECK((stp.flags() & ~STP_FLAG_PORT_ROLE_MASK) == (0xFF & ~STP_FLAG_PORT_ROLE_MASK));
    CHECK(stp.port_role() == STP_PORT_ROLE_ALTERNATE);
}

TEST_CASE("STP: too-short buffer is not ok") {
    unsigned char bytes[STP_HDR_LEN - 1] = {};
    STP stp(view(bytes, sizeof(bytes)));
    CHECK_FALSE(stp.ok());
}

// ---------------------------------------------------------------------------
// STP_TCN – Topology Change Notification BPDU
// ---------------------------------------------------------------------------

TEST_CASE("STP_TCN: basic parsing") {
    unsigned char bytes[] = {
        0x00, 0x00,  // protocol_id
        0x00,        // version = STP
        0x80,        // type    = TCN
    };

    STP_TCN tcn(view(bytes, sizeof(bytes)));
    CHECK(tcn.ok());
    CHECK(tcn.check());
    CHECK(tcn.hsize() == STP_TCN_HDR_LEN);
    CHECK(tcn.protocol_id() == STP_PROTO_ID);
    CHECK(tcn.version()      == STP_VERSION_STP);
    CHECK(tcn.type()         == STP_TYPE_TCN);
}

TEST_CASE("STP_TCN: too-short buffer is not ok") {
    unsigned char bytes[3] = {};
    STP_TCN tcn(view(bytes, sizeof(bytes)));
    CHECK_FALSE(tcn.ok());
}

// ---------------------------------------------------------------------------
// RSTP – IEEE 802.1w / 802.1D-2004
// ---------------------------------------------------------------------------

TEST_CASE("RSTP: basic parsing from raw bytes") {
    unsigned char bytes[RSTP_HDR_LEN] = {};
    bytes[0] = 0x00; bytes[1] = 0x00; // protocol_id
    bytes[2] = 0x02;                   // version = RSTP
    bytes[3] = 0x02;                   // type    = RSTP
    bytes[4] = 0x3C;                   // flags
    bytes[5] = 0x80; bytes[6] = 0x00;  // root priority
    uint8_t root_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
    memcpy(bytes + 7, root_mac, 6);
    bytes[17] = 0x80; bytes[18] = 0x00;
    uint8_t br_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02};
    memcpy(bytes + 19, br_mac, 6);
    bytes[25] = 0x80; bytes[26] = 0x01;
    bytes[35] = 0x00; // version_1_length

    RSTP rstp(view(bytes, sizeof(bytes)));
    CHECK(rstp.ok());
    CHECK(rstp.hsize() == RSTP_HDR_LEN);
    CHECK(rstp.protocol_id()     == STP_PROTO_ID);
    CHECK(rstp.version()          == STP_VERSION_RSTP);
    CHECK(rstp.type()             == STP_TYPE_RSTP);
    CHECK(rstp.version_1_length() == 0);
    CHECK(rstp.port_id()          == 0x8001);
    CHECK(rstp.root_mac()         == mn_mac(root_mac));
    CHECK(rstp.bridge_mac()       == mn_mac(br_mac));
}

TEST_CASE("RSTP: craft constructor sets all fields") {
    uint8_t flags = STP_FLAG_FORWARDING | STP_FLAG_LEARNING;
    uint64_t root_id   = uint64_t(0x8000) << 48;
    uint64_t bridge_id = uint64_t(0x8000) << 48;

    RSTP rstp(flags, root_id, /*root_path_cost=*/0, bridge_id,
              /*port_id=*/0x8001,
              /*message_age=*/256, /*max_age=*/5120,
              /*hello_time=*/512, /*forward_delay=*/3840);

    CHECK(rstp.ok());
    CHECK(rstp.version()          == STP_VERSION_RSTP);
    CHECK(rstp.type()             == STP_TYPE_RSTP);
    CHECK(rstp.flags()            == flags);
    CHECK(rstp.root_id()          == root_id);
    CHECK(rstp.bridge_id()        == bridge_id);
    CHECK(rstp.port_id()          == 0x8001);
    CHECK(rstp.message_age()      == 256);
    CHECK(rstp.max_age()          == 5120);
    CHECK(rstp.hello_time()       == 512);
    CHECK(rstp.forward_delay()    == 3840);
    CHECK(rstp.version_1_length() == 0);
}

TEST_CASE("RSTP: version_1_length setter round-trip") {
    RSTP rstp;
    CHECK(rstp.ok());
    rstp.version_1_length(0);
    CHECK(rstp.version_1_length() == 0);
}

TEST_CASE("RSTP: too-short buffer is not ok") {
    unsigned char bytes[RSTP_HDR_LEN - 1] = {};
    RSTP rstp(view(bytes, sizeof(bytes)));
    CHECK_FALSE(rstp.ok());
}

// ---------------------------------------------------------------------------
// PVST – Cisco PVST+ / Rapid-PVST+
// ---------------------------------------------------------------------------

TEST_CASE("PVST: pvst_group_mac returns the Cisco group address") {
    uint8_t expected[6] = {0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCD};
    CHECK(pvst_group_mac() == mn_mac(expected));
}

TEST_CASE("PVST: basic parsing from raw bytes") {
    unsigned char bytes[] = {
        0x00, 0x00,  // reserved
        0x00, 0x05,  // vlan = 5
    };

    PVST pvst(view(bytes, sizeof(bytes)));
    CHECK(pvst.ok());
    CHECK(pvst.hsize()    == PVST_HDR_LEN);
    CHECK(pvst.reserved() == 0);
    CHECK(pvst.vlan()     == 5);
}

TEST_CASE("PVST: craft constructor with vlan_id") {
    PVST pvst(100);
    CHECK(pvst.ok());
    CHECK(pvst.reserved() == 0);
    CHECK(pvst.vlan()     == 100);
}

TEST_CASE("PVST: vlan setter round-trip") {
    PVST pvst;
    CHECK(pvst.ok());

    pvst.vlan(4094);
    CHECK(pvst.vlan() == 4094);

    pvst.vlan(1);
    CHECK(pvst.vlan() == 1);

    pvst.reserved(0xABCD);
    CHECK(pvst.reserved() == 0xABCD);
}

TEST_CASE("PVST: too-short buffer is not ok") {
    unsigned char bytes[3] = {};
    PVST pvst(view(bytes, sizeof(bytes)));
    CHECK_FALSE(pvst.ok());
}

// ---------------------------------------------------------------------------
// MSTP – IEEE 802.1s / 802.1Q
// ---------------------------------------------------------------------------

TEST_CASE("MSTP: config_name round-trip") {
    MSTP mstp;
    CHECK(mstp.ok());

    char* name = "region-A";
    mstp.config_name(view(name));

    view n = mstp.config_name();
    CHECK(n.size() == MSTP_CFG_NAME_LEN);
    CHECK(memcmp(n.data(), name, 8) == 0);
    // rest of the 32-byte field must be zeroed
    for (size_t i = 8; i < MSTP_CFG_NAME_LEN; ++i) {
        CHECK(n[i] == 0);
    }
}

TEST_CASE("MSTP: config_name truncated to 32 bytes") {
    MSTP mstp;
    CHECK(mstp.ok());

    // supply a 34-character name – only first 32 bytes must be written
    char* long_name = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456XY";
    mstp.config_name(view(long_name));

    view n = mstp.config_name();
    CHECK(n.size() == MSTP_CFG_NAME_LEN);
    CHECK(memcmp(n.data(), long_name, MSTP_CFG_NAME_LEN) == 0);
}

TEST_CASE("MSTP: config_name with empty view zeroes the field") {
    MSTP mstp;
    CHECK(mstp.ok());

    char* name = "my-region";
    mstp.config_name(view(name));
    mstp.config_name(view{}); // clear

    view n = mstp.config_name();
    for (size_t i = 0; i < MSTP_CFG_NAME_LEN; ++i) {
        CHECK(n[i] == 0);
    }
}

TEST_CASE("MSTP: revision round-trip") {
    MSTP mstp;
    CHECK(mstp.ok());

    mstp.revision(42);
    CHECK(mstp.revision() == 42);

    mstp.revision(0xFFFF);
    CHECK(mstp.revision() == 0xFFFF);
}

TEST_CASE("MSTP: digest round-trip") {
    MSTP mstp;
    CHECK(mstp.ok());

    uint8_t d[MSTP_CFG_DIGEST_LEN];
    for (size_t i = 0; i < MSTP_CFG_DIGEST_LEN; ++i) {
        d[i] = static_cast<uint8_t>(i + 1);
    }

    mstp.digest(view(d, MSTP_CFG_DIGEST_LEN));
    view dv = mstp.digest();
    CHECK(dv.size() == MSTP_CFG_DIGEST_LEN);
    CHECK(memcmp(dv.data(), d, MSTP_CFG_DIGEST_LEN) == 0);
}

TEST_CASE("MSTP: cist_internal_path_cost round-trip") {
    MSTP mstp;
    CHECK(mstp.ok());

    mstp.cist_internal_path_cost(20000);
    CHECK(mstp.cist_internal_path_cost() == 20000);
}


TEST_CASE("MSTP: remaining_hops round-trip") {
    MSTP mstp;
    CHECK(mstp.ok());

    mstp.remaining_hops(20);
    CHECK(mstp.remaining_hops() == 20);

    mstp.remaining_hops(0);
    CHECK(mstp.remaining_hops() == 0);
}

TEST_CASE("MSTP: msti_count with no MSTIs") {
    MSTP mstp;
    CHECK(mstp.ok());
    CHECK(mstp.msti_count() == 0);

    // msti_at out of range returns empty view
    mstp_msti m = mstp.msti_at(0);
    CHECK_FALSE(m.ok());
}

TEST_CASE("MSTP: set_msti and msti_at with one MSTI") {
    const uint32_t total = MSTP_HDR_LEN + MSTP_MSTI_LEN;
    uint8_t buf[total] = {};
    buf[2] = 0x03; // version = MSTP
    buf[3] = 0x02; // type
    // version_3_length at [36..37] big-endian = MSTP_V3_FIXED_LEN + MSTP_MSTI_LEN = 80
    const uint16_t v3len = static_cast<uint16_t>(MSTP_V3_FIXED_LEN + MSTP_MSTI_LEN);
    buf[36] = static_cast<uint8_t>(v3len >> 8);
    buf[37] = static_cast<uint8_t>(v3len & 0xFF);

    MSTP mstp(view(buf, total));
    if (!mstp.ok()) {
        WARN("MSTP: dissect from raw buf returned not-ok; skipping MSTI sub-tests");
        return;
    }

    CHECK(mstp.msti_count() == 1);

    uint64_t rr = (uint64_t(0x8001) << 48) | 0x001122334455ULL;
    mstp.set_msti(/*index=*/0,
                  /*flags=*/0x28, rr,
                  /*internal_path_cost=*/1000,
                  /*bridge_prio=*/0x80, /*port_prio=*/0x80, /*hops=*/19);

    mstp_msti m = mstp.msti_at(0);
    CHECK(m.ok());
    CHECK(m.flags()              == 0x28);
    CHECK(m.regional_root()      == rr);
    CHECK(m.internal_path_cost() == 1000);
    CHECK(m.bridge_priority()    == 0x80);
    CHECK(m.port_priority()      == 0x80);
    CHECK(m.remaining_hops()     == 19);
}

TEST_CASE("MSTP: msti_at out-of-range returns invalid view") {
    MSTP mstp;
    CHECK(mstp.ok());
    mstp_msti m = mstp.msti_at(99);
    CHECK_FALSE(m.ok());
}

TEST_CASE("MSTP: version_3_length controls msti_count") {
    MSTP mstp;
    CHECK(mstp.ok());

    mstp.version_3_length(MSTP_V3_FIXED_LEN + 2 * MSTP_MSTI_LEN);
    CHECK(mstp.version_3_length() == MSTP_V3_FIXED_LEN + 2 * MSTP_MSTI_LEN);
    CHECK(mstp.msti_count() == 2);
}

// ---------------------------------------------------------------------------
// mstp_msti – accessors on a fixed-size sub-view
// ---------------------------------------------------------------------------

TEST_CASE("mstp_msti: accessors on a well-formed 16-byte record") {
    uint8_t rec[MSTP_MSTI_LEN] = {};
    rec[0] = 0x28; // flags

    uint64_t rr    = (uint64_t(0x1234) << 48) | 0xAABBCCDDEEFFULL;
    uint64_t rr_be = utils::mem::bswap<uint64_t>(rr);
    memcpy(rec + 1, &rr_be, 8);

    uint32_t ipc_be = utils::mem::bswap<uint32_t>(500u);
    memcpy(rec + 9, &ipc_be, 4);

    rec[13] = 0x60; // bridge_priority
    rec[14] = 0x40; // port_priority
    rec[15] = 10;   // remaining_hops

    mstp_msti m(rec, MSTP_MSTI_LEN);
    CHECK(m.flags()              == 0x28);
    CHECK(m.regional_root()      == rr);
    CHECK(m.internal_path_cost() == 500);
    CHECK(m.bridge_priority()    == 0x60);
    CHECK(m.port_priority()      == 0x40);
    CHECK(m.remaining_hops()     == 10);
}

TEST_CASE("mstp_msti: empty view returns zeroes") {
    mstp_msti m;
    CHECK(m.flags()              == 0);
    CHECK(m.regional_root()      == 0);
    CHECK(m.internal_path_cost() == 0);
    CHECK(m.bridge_priority()    == 0);
    CHECK(m.port_priority()      == 0);
    CHECK(m.remaining_hops()     == 0);
}

// ---------------------------------------------------------------------------
// SPB – IEEE 802.1aq Shortest Path Bridging
// ---------------------------------------------------------------------------

TEST_CASE("SPB: inherits MSTP accessors") {
    SPB spb;
    CHECK(spb.ok());

    spb.revision(7);
    CHECK(spb.revision() == 7);

    spb.remaining_hops(15);
    CHECK(spb.remaining_hops() == 15);

    // version must remain SPB even after field modifications
    CHECK(spb.version() == STP_VERSION_SPB);
}

// ---------------------------------------------------------------------------
// Constants sanity checks
// ---------------------------------------------------------------------------

TEST_CASE("STP: protocol constants are well-defined") {
    CHECK(STP_PROTO_ID     == 0x0000);
    CHECK(STP_VERSION_STP  == 0);
    CHECK(STP_VERSION_RSTP == 2);
    CHECK(STP_VERSION_MSTP == 3);
    CHECK(STP_VERSION_SPB  == 4);
    CHECK(STP_TYPE_CONFIG  == 0x00);
    CHECK(STP_TYPE_RSTP    == 0x02);
    CHECK(STP_TYPE_TCN     == 0x80);

    CHECK(STP_FLAG_TOPOLOGY_CHANGE     == 0x01);
    CHECK(STP_FLAG_PROPOSAL            == 0x02);
    CHECK(STP_FLAG_PORT_ROLE_MASK      == 0x0C);
    CHECK(STP_FLAG_PORT_ROLE_SHIFT     == 2);
    CHECK(STP_FLAG_LEARNING            == 0x10);
    CHECK(STP_FLAG_FORWARDING          == 0x20);
    CHECK(STP_FLAG_AGREEMENT           == 0x40);
    CHECK(STP_FLAG_TOPOLOGY_CHANGE_ACK == 0x80);

    CHECK(STP_PORT_ROLE_UNKNOWN    == 0);
    CHECK(STP_PORT_ROLE_ALTERNATE  == 1);
    CHECK(STP_PORT_ROLE_ROOT       == 2);
    CHECK(STP_PORT_ROLE_DESIGNATED == 3);

    CHECK(STP_HDR_LEN     == 35u);
    CHECK(STP_TCN_HDR_LEN ==  4u);
    CHECK(RSTP_HDR_LEN    == 36u);
    CHECK(PVST_HDR_LEN    ==  4u);
    CHECK(MSTP_HDR_LEN    == 102u);
    CHECK(MSTP_V3_FIXED_LEN  == 64u);
    CHECK(MSTP_MSTI_LEN      == 16u);
    CHECK(MSTP_CFG_NAME_LEN   == 32u);
    CHECK(MSTP_CFG_DIGEST_LEN == 16u);
}

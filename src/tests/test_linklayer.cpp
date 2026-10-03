#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include <lynx/lynx>

using namespace lynx;
using namespace lynx::utils;
using namespace lynx::proto;

TEST_CASE("Eth: frame classification & ethernet (src, dst, ethertype)") {
    // Src: 08:00:27:fc:6a:c9, Dst: 08:00:27:e2:9f:a6
    unsigned char bytes[] = {0x8, 0x0, 0x27, 0xe2, 0x9f, 0xa6, 0x8, 0x0, 0x27, 0xfc, 0x6a, 0xc9, 0x8, 0x0};

    Raw raw(bytes);
    CHECK(Raw::ftype(raw) == frame_type::Eth);

    auto eth = raw.get<Eth>();
    CHECK(eth->dst()       == codec::parse_mac("08:00:27:e2:9f:a6"));
    CHECK(eth->src()       == codec::parse_mac("08:00:27:fc:6a:c9"));
    CHECK(eth->ethertype() == IPV4_ETHERTYPE);  // IPv4
}

TEST_CASE("Eth: 802.1Q") {
    unsigned char bytes[] = {
        0x11,0x11,0x11,0x11,0x11,0x11,  // dst
        0x22,0x22,0x22,0x22,0x22,0x22,  // src
        0x81,0x00,                      // TPID (802.1Q)
        0x20,0x05,                      // TCI: pcp=1, dei=0, vid=5
        0x08,0x00,                      // EtherType (IPv4)
    };

    Raw raw(bytes);
    CHECK(Raw::ftype(raw) == frame_type::Dot1Q);

    auto dot1q = raw.get<Dot1Q>();
    CHECK(dot1q->dst() == codec::parse_mac("11:11:11:11:11:11"));
    CHECK(dot1q->src() == codec::parse_mac("22:22:22:22:22:22"));

    vlan_tag t = dot1q->tag();
    CHECK(t.pcp == 1);
    CHECK(t.dei == 0);
    CHECK(t.id  == 5);
    CHECK(dot1q->ethertype() == IPV4_ETHERTYPE);
}

TEST_CASE("Eth: 802.1ad") {
    unsigned char bytes[] = {
        0x11,0x11,0x11,0x11,0x11,0x11,  // dst
        0x22,0x22,0x22,0x22,0x22,0x22,  // src
        0x88,0xA8,                      // outer TPID (802.1ad)
        0x00,0x01,                      // outer TCI: pcp=0, dei=0, vid=1
        0x81,0x00,                      // inner TPID (802.1Q)
        0x00,0x02,                      // inner TCI: pcp=0, dei=0, vid=2
        0x08,0x00,                      // EtherType (IPv4)
    };

    Raw raw(bytes);
    CHECK(Raw::ftype(raw) == frame_type::QinQ);

    auto qinq = raw.get<QinQ>();

    vlan_tag outer = qinq->tag();     // QinQ::tag() overrides to mean the outer tag
    CHECK(outer.id == 1);

    vlan_tag inner = qinq->tag1q();   // reaches Dot1Q::tag() explicitly for the inner tag
    CHECK(inner.id == 2);

    CHECK(qinq->ethertype() == IPV4_ETHERTYPE);
}

TEST_CASE("PPP") {
    SUBCASE("no compression") {
        unsigned char bytes[] = {0xFF, 0x03, 0xC0, 0x21}; // Addr, Ctrl, Protocol=LCP
        PPP ppp(view(bytes, sizeof(bytes)));
        CHECK(ppp.ok());
        CHECK(ppp.compress() == ppp_comp::NONE);
        CHECK(ppp.hsize() == PPP_HDR_LEN);
        CHECK(ppp.protocol() == PPP_PROTO_LCP);
    }

    SUBCASE("ACFC - address/control stripped") {
        unsigned char bytes[] = {0xC0, 0x21}; // Protocol=LCP, no Addr/Ctrl
        PPP ppp(view(bytes, sizeof(bytes)));
        CHECK(ppp.ok());
        CHECK(ppp.compress() == ppp_comp::ACFC);
        CHECK(ppp.hsize() == PPP_HDR_LEN_ACFC);
        CHECK(ppp.protocol() == PPP_PROTO_LCP);
    }

    SUBCASE("PFC - protocol compressed to 1 byte") {
        unsigned char bytes[] = {0xFF, 0x03, 0x21}; // Addr, Ctrl, Protocol=IP (compressed)
        PPP ppp(view(bytes, sizeof(bytes)));
        CHECK(ppp.ok());
        CHECK(ppp.compress() == ppp_comp::PFC);
        CHECK(ppp.hsize() == PPP_HDR_LEN_PFC);
        CHECK(ppp.protocol() == PPP_PROTO_IP);
    }

    SUBCASE("minimal - both compressions active") {
        unsigned char bytes[] = {0x21}; // Protocol=IP (compressed), no Addr/Ctrl
        PPP ppp(view(bytes, sizeof(bytes)));
        CHECK(ppp.ok());
        CHECK(ppp.compress() == (ppp_comp::ACFC | ppp_comp::PFC));
        CHECK(ppp.is_minimal());
        CHECK(ppp.hsize() == PPP_HDR_LEN_MIN);
        CHECK(ppp.protocol() == PPP_PROTO_IP);
    }
}

TEST_CASE("PPP: CHAP") {
    unsigned char bytes[] = {
        0xFF, 0x03, 0xC2, 0x23,          // PPP: Addr, Ctrl, Protocol=CHAP
        0x01,                            // Code = Challenge
        0x07,                            // Identifier
        0x00, 0x0C,                      // Length = 12 (4 hdr + 1 valuesize + 4 value + 3 name)
        0x04,                            // Value-Size = 4
        0xAA, 0xBB, 0xCC, 0xDD,          // Value (4 bytes, placeholder)
        'a', 'b', 'c',                   // Name (3 bytes, placeholder)
    };

    PPP ppp(view(bytes, sizeof(bytes)));
    CHECK(ppp.ok());
    CHECK(ppp.protocol() == PPP_PROTO_CHAP);

    auto chap = ppp.get<CHAP>();
    CHECK(chap->code()       == CHAP_CODE_CHALLENGE);
    CHECK(chap->identifier() == 7);
    CHECK(chap->length()     == 12);

    unsigned char expected_value[4] = {0xAA, 0xBB, 0xCC, 0xDD};
    CHECK(chap->value() == view(expected_value, 4));

    unsigned char expected_name[3] = {'a','b','c'};
    CHECK(chap->name() == view(expected_name, 3));
}

TEST_CASE("PPP: PAP") {
    unsigned char bytes[] = {
        0xFF, 0x03, 0xC0, 0x23,           // PPP: Addr, Ctrl, Protocol=PAP
        0x01,                             // Code = Authenticate-Request
        0x03,                             // Identifier
        0x00, 0x0E,                       // Length = 14
        0x04, 'u','s','e','r',            // Peer-ID-Length=4, Peer-ID="user"
        0x04, 'p','a','s','s',            // Password-Length=4, Password="pass"
    };

    PPP ppp(view(bytes, sizeof(bytes)));
    CHECK(ppp.ok());
    CHECK(ppp.protocol() == PPP_PROTO_PAP);

    auto pap = ppp.get<PAP>();
    CHECK(pap->code()       == PAP_CODE_AUTH_REQ);
    CHECK(pap->identifier() == 3);
    CHECK(pap->length()     == 14);

    unsigned char expected_id[4]  = {'u','s','e','r'};
    unsigned char expected_pw[4]  = {'p','a','s','s'};
    CHECK(pap->peer_id()  == view(expected_id, 4));
    CHECK(pap->password() == view(expected_pw, 4));
}

TEST_CASE("PPP: IPCP") {
    unsigned char bytes[] = {
        0xFF, 0x03, 0x80, 0x21,          // PPP: Addr, Ctrl, Protocol=IPCP
        0x01,                            // Code = Configure-Request
        0x01,                            // Identifier
        0x00, 0x0A,                      // Length = 10
        0x03, 0x06, 0xC0, 0xA8, 0x01, 0x01, // Option: IP-Address, len=6, value=192.168.1.1
    };

    PPP ppp(view(bytes, sizeof(bytes)));
    CHECK(ppp.ok());
    CHECK(ppp.protocol() == PPP_PROTO_IPCP);

    auto ipcp = ppp.get<IPCP>();
    CHECK(ipcp->code()   == IPCP_CODE_CONF_REQ);
    CHECK(ipcp->length() == 10);

    auto tlv = ipcp->get<TLV>();
    view ip = tlv->get(3); // IP-Address option type
    unsigned char expected_ip[4] = {192,168,1,1};
    CHECK(ip == view(expected_ip, 4));
}

TEST_CASE("PPP: IPV6CP") {
    unsigned char bytes[] = {
        0xFF, 0x03, 0x80, 0x57,          // PPP: Addr, Ctrl, Protocol=IPv6CP
        0x01,                            // Code = Configure-Request
        0x01,                            // Identifier
        0x00, 0x0E,                      // Length = 14
        0x01, 0x0A,                      // Option: Interface-Identifier, len=10
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01, // 8-byte interface ID (placeholder)
    };

    PPP ppp(view(bytes, sizeof(bytes)));
    CHECK(ppp.ok());
    CHECK(ppp.protocol() == PPP_PROTO_IPV6CP);

    auto ipv6cp = ppp.get<IPv6CP>();
    CHECK(ipv6cp->code()   == IPV6CP_CODE_CONF_REQ);
    CHECK(ipv6cp->length() == 14);

    auto tlv = ipv6cp->get<TLV>();
    view iid = tlv->get(1); // Interface-Identifier option type
    unsigned char expected_iid[8] = {0,0,0,0,0,0,0,1};
    CHECK(iid == view(expected_iid, 8));
}

TEST_CASE("PPP: LCP") {
    unsigned char bytes[] = {
        0xFF, 0x03, 0xC0, 0x21,          // PPP: Addr, Ctrl, Protocol=LCP
        0x01,                            // Code = Configure-Request
        0x01,                            // Identifier
        0x00, 0x0E,                      // Length = 14
        0x01, 0x04, 0x05, 0xDC,          // Option: MRU, len=4, value=1500
        0x05, 0x06, 0x12, 0x34, 0x56, 0x78, // Option: Magic-Number, len=6, value (placeholder)
    };

    PPP ppp(view(bytes, sizeof(bytes)));
    CHECK(ppp.ok());
    CHECK(ppp.protocol() == PPP_PROTO_LCP);

    auto lcp = ppp.get<LCP>();
    CHECK(lcp->code()   == LCP_CODE_CONF_REQ);
    CHECK(lcp->length() == 14);

    auto tlv = lcp->get<TLV>();

    view mru = tlv->get(1);
    unsigned char expected_mru[2] = {0x05,0xDC};
    CHECK(mru == view(expected_mru, 2));

    view magic = tlv->get(5);
    unsigned char expected_magic[4] = {0x12,0x34,0x56,0x78};
    CHECK(magic == view(expected_magic, 4));
}

TEST_CASE("PPP: PPPoE") {
    // PPPoE itself isn't implemented yet - this only checks that ftype()
    // correctly recognizes the EtherType and stops there.
    unsigned char bytes[] = {
        0x11,0x11,0x11,0x11,0x11,0x11,
        0x22,0x22,0x22,0x22,0x22,0x22,
        0x88,0x64,                      // EtherType: PPPoE Session
        0x00,0x00,
    };
    Raw raw(bytes);
    CHECK(Raw::ftype(raw) == frame_type::PPPoE);
}

TEST_CASE("IPv4: basic parsing") {
    // Internet Protocol Version 4, Src: 2.1.1.2, Dst: 2.1.1.1
    unsigned char bytes[] = {
        0x45, 0x0, 0x3, 0xe4, 0xb5, 0xd0, 0x20, 0x0, 0x40, 0x1, 
        0x9b, 0x44, 0x2, 0x1, 0x1, 0x2, 0x2, 0x1, 0x1, 0x1
    };

    IPv4 ip(view(bytes, sizeof(bytes)));

    CHECK(ip.version() == 4);
    CHECK(ip.src() == codec::parse_ip("2.1.1.2"));
    CHECK(ip.dst() == codec::parse_ip("2.1.1.1"));
    CHECK(ip.ethertype() == IPV4_ETHERTYPE);
    CHECK(ip.ihl() == 5);
    CHECK(ip.total_len() == 996);
    CHECK(ip.identification() == 46544);
    CHECK(ip.ttl() == 64);
    CHECK(ip.flags() == IPV4_FLAG_MF);
    CHECK(ip.proto() == ICMP_IP_PROTO);
}

TEST_CASE("ARP: basic parsing") {
    unsigned char bytes[] = {
        0x0, 0x1, 0x8, 0x0, 0x6, 0x4, 0x0, 0x1, 0x0, 0x7, 
        0xd, 0xaf, 0xf4, 0x54, 0x18, 0xa6, 0xac, 0x1, 0x0, 
        0x0, 0x0, 0x0, 0x0, 0x0, 0x18, 0xa6, 0xad, 0x9f
    };

    ARP a(view(bytes, sizeof(bytes)));

    CHECK(a.spa() == codec::parse_ip("24.166.172.1"));
    CHECK(a.sha() == codec::parse_mac("00:07:0d:af:f4:54"));
    CHECK(a.tpa() == codec::parse_ip("24.166.173.159"));
    CHECK(a.oper() == ARP_OP_REQUEST);
    CHECK(a.ptype() == ARP_PRO_IPV4);
    CHECK(a.is_broadcast());
}

TEST_CASE("EAP: basic create & inspect") {
    unsigned char bytes[] = {
        0x2, 0xc6, 0x0, 0x1C, 0x1,
        0x62, 0x61, 0x64, 0x72, 0x2e, 0x65, 0x64, 0x64,
        0x69, 0x6e, 0x2e, 0x70, 0x79, 0x40, 0x67, 0x6d,
        0x61, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d
    };

    EAP e(view(bytes, sizeof(bytes)));

    CHECK(e.code() == EAP_CODE_RESPONSE);
    CHECK(e.identifier() == 198);
    CHECK(e.length() == 28);
    CHECK(e.type() == EAP_TYPE_IDENTITY);
    CHECK(e.data() == view("badr.eddin.py@gmail.com"));
}

TEST_CASE("TCP: basic parsing") {
    unsigned char bytes[] = {
        0x1A, 0x37, 0x07, 0xD0,
        0xDD, 0x6A, 0xBB, 0x2B,
        0x1F, 0x5F, 0xD2, 0x51,
        0x50, 0x10, 0x04, 0x02,
        0x12, 0x09, 0x00, 0x00
    };

    TCP tcp(view(bytes, sizeof(bytes)));

    // CHECK(tcp.sport() == 6711);
    // CHECK(tcp.dport() == 2000);
    // CHECK(tcp.seq() == 3720887723);
    // CHECK(tcp.ack() == 523188561);
    // CHECK(tcp.data_offset() == 5);
    // CHECK(tcp.flags() == TCP_FLAG_ACK);
    // CHECK(tcp.window() == 1026);
}

TEST_CASE("UDP: basic parsing") {
    unsigned char bytes[] = {
        0x30, 0x39,             // Source port: 12345
        0xD4, 0x31,             // Destination port: 54321
        0x00, 0x0C,             // Length: 12
        0x00, 0x00,             // Checksum
        0x4c, 0x59, 0x4e, 0x58  // Payload
    };

    UDP udp(view(bytes, sizeof(bytes)));
    CHECK(udp.sport() == 12345);
    CHECK(udp.dport() == 54321);
    CHECK(udp.length() == 12);
    CHECK(udp.payload() == view("LYNX"));
}

TEST_CASE("Extras: TLV basic lookup & iteration") {
    // code=1, len=3, value=0xAA | code=2, len=4, value=0x12,0x34
    unsigned char bytes[] = {0x01, 0x03, 0xAA, 0x02, 0x04, 0x12, 0x34};

    TLV opts(view(bytes, sizeof(bytes)));
    CHECK(opts.size() == 7);

    auto v1 = opts.get(1);
    unsigned char expect1[] = {0xAA};
    CHECK(v1 == view(expect1, 1));

    // iterate through entries
    opts.reset();
    CHECK(opts.next());
    auto cur = opts.current();
    CHECK(cur.code() == 1);
    CHECK(opts.next());
    cur = opts.current();
    CHECK(cur.code() == 2);
}

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include <lynx/lynx>

using namespace lynx;
using namespace lynx::proto;

TEST_CASE("TLV operations") {
    static_assert(std::is_copy_constructible_v<TLV> && std::is_move_constructible_v<TLV>);
    static_assert(std::is_copy_assignable_v<TLV> && std::is_move_assignable_v<TLV>);

    SUBCASE("basic append/find/serialize") {
        TLV t;
        CHECK(t.empty());
        CHECK(t.capacity() == 0);

        uint8_t v1[] = {0xAA}, v5[] = {1, 2, 3, 4};
        CHECK(t.append(1, v1, 1).ok());
        CHECK(t.append(7).ok());
        CHECK(t.append(5, v5, 4).ok());
        CHECK(t.size() == 11);

        tlv_node n7 = t.find(7), n9 = t.find(9), n5 = t.find(5);
        CHECK(n7.ok());
        CHECK(n7.code() == 7);
        CHECK(n7.length() == 2);
        CHECK(n7.vsize() == 0);
        CHECK(!n7.value().ok());

        CHECK(!n9.ok());
        CHECK(n9.sts() == status::InvalidView);
        CHECK(n9.code() == 0);
        CHECK(n9.length() == 0);
        CHECK(n9.vsize() == 0);

        CHECK(n5.ok());
        CHECK(n5.vsize() == 4);
        CHECK(n5.value()[3] == 4);

        uint8_t exp[] = {1, 3, 0xAA, 7, 2, 5, 6, 1, 2, 3, 4};
        CHECK(t.origin().size() == sizeof exp);
        CHECK(!memcmp(t.origin().data(), exp, sizeof exp));
        CHECK(t.get(1).ok());
        CHECK(!t.get(7).ok());
        CHECK(!t.get(9).ok());

        Buffer b = t.to_buffer();
        CHECK(b.valid());
        TLV t2(b.aspan());
        CHECK(t2.find(5).ok());
        CHECK(t2.find(7).ok());
    }

    SUBCASE("capacity and pointer stability") {
        TLV t(64);
        CHECK(t.capacity() == 64);
        CHECK(t.empty());

        uint8_t v[] = {9, 9};
        CHECK(t.append(1, v, 2).ok());
        uint8_t* p = t.origin().data();
        const uint8_t* val = t.find(1).value().data();

        for (int i = 0; i < 10; ++i) {
            CHECK(t.append(2, v, 2).ok());
        }

        CHECK(t.origin().data() == p);
        CHECK(t.capacity() == 64);
        CHECK(t.find(1).value().data() == val);
    }

    SUBCASE("reallocations and repeated lookups") {
        TLV t;
        uint8_t v[] = {1, 2, 3};
        int moves = 0;
        const uint8_t* last = nullptr;
        uint32_t prevcap = 0;

        for (int i = 0; i < 100; ++i) {
            CHECK(t.append(i & 0xFF, v, 3).ok());
            if (t.origin().data() != last) {
                ++moves;
                last = t.origin().data();
                if (prevcap) {
                    CHECK(t.capacity() >= 2 * prevcap);
                }
                prevcap = t.capacity();
            }
        }

        INFO("100 appends: " << moves << " reallocations, cap " << t.capacity() << ", size " << t.size());
        CHECK(moves >= 1);

        for (int i = 0; i < 100; ++i) {
            auto r = t.find(i & 0xFF);
            CHECK(r.ok());
            CHECK(r.vsize() == 3);
            CHECK(r.value()[2] == 3);
        }
    }

    SUBCASE("remove by type and value") {
        TLV t;
        uint8_t v[] = {7};
        CHECK(t.append(1, v, 1).ok());
        CHECK(t.append(2, v, 1).ok());
        CHECK(t.append(1, v, 1).ok());
        CHECK(t.append(3).ok());
        CHECK(t.append(1, v, 1).ok());

        size_t n = 99;
        CHECK(t.remove(9, false, &n).ok());
        CHECK(n == 0);
        CHECK(t.remove(1, false, &n).ok());
        CHECK(n == 1);
        CHECK(t.find(1).ok());
        CHECK(t.find(1, 1).ok());
        CHECK(!t.find(1, 2).ok());

        uint32_t cap = t.capacity();
        CHECK(t.remove(1, true, &n).ok());
        CHECK(n == 2);
        CHECK(t.capacity() == cap);
        CHECK(!t.find(1).ok());
        CHECK(t.find(2).ok());
        CHECK(t.find(3).ok());
        CHECK(t.find(3).vsize() == 0);
        CHECK(t.size() == 5);

        CHECK(t.remove(2, true).ok());
        CHECK(t.remove(3, true).ok());
        CHECK(t.empty());
        CHECK(t.capacity() == cap);
        CHECK(t.append(4).ok());
        CHECK(t.find(4).ok());
    }

    SUBCASE("non-owning view semantics") {
        uint8_t rx[] = {1, 3, 0xAA, 2, 4, 0x12, 0x34};
        uint8_t ref[sizeof rx];
        memcpy(ref, rx, sizeof rx);

        TLV t(view(rx, sizeof rx));
        CHECK(t.capacity() == 0);
        CHECK(t.find(2).ok());

        CHECK(t.append(9).ok());
        CHECK(t.capacity() > 0);
        CHECK(t.origin().data() != rx);
        CHECK(!memcmp(rx, ref, sizeof rx));
        CHECK(t.size() == 9);

        uint8_t rx2[] = {1, 3, 0xAA, 2, 4, 0x12, 0x34};
        TLV u(view(rx2, sizeof rx2));
        size_t n;
        CHECK(u.remove(1, false, &n).ok());
        CHECK(n == 1);
        CHECK(!memcmp(rx2, ref, sizeof rx2));
        CHECK(u.size() == 4);
        CHECK(u.find(2).ok());

        uint8_t rx3[] = {1, 3, 0xAA};
        TLV w(view(rx3, 3));
        CHECK(w.remove(8).ok());
        CHECK(w.capacity() == 0);
    }

    SUBCASE("length limits") {
        TLV t;
        uint8_t big[300] = {};
        CHECK(!t.append(1, big, 254).ok());
        CHECK(t.empty());
        CHECK(t.append(1, big, 253).ok());
        CHECK(t.size() == 255);
        CHECK(!t.append(1, nullptr, 3).ok());
        CHECK(t.size() == 255);
    }

    SUBCASE("malformed input") {
        uint8_t bad[] = {1, 9, 0xAA};
        TLV t(view(bad, 3));
        CHECK(!t.append(2).ok());
        CHECK(!t.remove(1).ok());
        CHECK(t.size() == 3);

        auto r = t.find(2);
        CHECK(!r.ok());
        CHECK(r.sts() == status::MalformedPacket);
        CHECK(t.get(2).error().type == status::MalformedPacket);

        uint8_t tail[] = {1, 3, 0xAA, 0x09};
        TLV u(view(tail, 4));
        CHECK(!u.append(2).ok());
    }

    SUBCASE("tlv_node array constructor") {
        uint8_t a[] = {1, 3, 5}, b2[] = {1, 2};
        tlv_node n[2] = {tlv_node(a, 3), tlv_node(b2, 2)};

        TLV t(n, 2);
        CHECK(t.ok());
        CHECK(t.size() == 5);
        CHECK(t.capacity() == 5);
        CHECK(t.find(1, 1).ok());
        CHECK(t.find(1, 1).vsize() == 0);
        CHECK(t.append(3).ok());
        CHECK(t.size() == 7);
        CHECK(t.find(1).value()[0] == 5);
    }

    SUBCASE("iteration state") {
        TLV t(32);
        CHECK(t.append(1).ok());
        CHECK(t.append(2).ok());
        CHECK(t.next());
        CHECK(t.current().code() == 1);

        CHECK(t.append(3).ok());
        CHECK(t.next());
        CHECK(t.current().code() == 2);
        CHECK(t.next());
        CHECK(t.current().code() == 3);

        TLV g;
        CHECK(g.append(1).ok());
        CHECK(g.next());
        for (int i = 0; i < 20; ++i) {
            CHECK(g.append(2).ok());
        }
        CHECK(g.next());
        CHECK(g.current().code() == 1);

        TLV e;
        CHECK(e.current().code() == 0);
        CHECK(e.current().length() == 0);
    }

    SUBCASE("vector semantics") {
        TLV a;
        uint8_t v[] = {1, 2, 3};
        CHECK(a.append(1, v, 3).ok());
        CHECK(a.append(2).ok());

        TLV b(a);
        CHECK(b.size() == a.size());
        CHECK(b.origin().data() != a.origin().data());
        CHECK(b.append(3).ok());
        CHECK(a.size() == 7);
        CHECK(b.size() == 9);
        CHECK(!a.find(3).ok());
        CHECK(b.find(3).ok());

        TLV c(std::move(a));
        CHECK(a.empty());
        CHECK(a.capacity() == 0);
        CHECK(c.size() == 7);
        CHECK(c.find(1).ok());

        TLV d;
        CHECK(d.append(9).ok());
        d = c;
        CHECK(d.size() == 7);
        CHECK(d.find(1).ok());
        CHECK(!d.find(9).ok());
        CHECK(d.origin().data() != c.origin().data());

        TLV e;
        e = std::move(c);
        CHECK(c.empty());
        CHECK(e.size() == 7);

        d = d;
        CHECK(d.size() == 7);

        uint8_t rx[] = {1, 3, 0xAA};
        TLV borrowed(view(rx, 3));
        TLV cp(borrowed);
        CHECK(cp.capacity() > 0);
        CHECK(cp.origin().data() != rx);
        CHECK(cp.find(1).ok());

        TLV mv(std::move(borrowed));
        CHECK(mv.capacity() == 0);
        CHECK(mv.origin().data() == rx);
        CHECK(borrowed.empty());
    }

    SUBCASE("reserve/shrink/clear") {
        TLV t;
        CHECK(t.reserve(100).ok());
        CHECK(t.capacity() == 100);
        CHECK(t.empty());

        uint8_t v[] = {1};
        CHECK(t.append(1, v, 1).ok());
        CHECK(t.append(2, v, 1).ok());
        CHECK(t.capacity() == 100);

        CHECK(t.reserve(10).ok());
        CHECK(t.capacity() == 100);
        CHECK(t.fit().ok());
        CHECK(t.capacity() == 6);
        CHECK(t.size() == 6);
        CHECK(t.find(2).ok());

        t.clear();
        CHECK(t.empty());
        CHECK(t.capacity() == 6);
        CHECK(t.append(5).ok());
        CHECK(t.capacity() == 6);
        CHECK(t.find(5).ok());

        t.clear();
        CHECK(t.fit().ok());
        CHECK(t.capacity() == 0);
        CHECK(t.empty());
        CHECK(t.append(5).ok());
        CHECK(t.find(5).ok());
    }

    SUBCASE("view validity") {
        uint8_t x[] = {1, 2, 3};
        view v(x, 3);
        INFO("view(ok data): ok=" << v.ok() << " valid()=" << v.valid());
        CHECK(v.ok());
    }
}
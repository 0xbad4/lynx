// arpup - resolves an IPv4 address to a MAC address.
#include <lynx/lynx>

#include <iostream>
#include <cstdio>
#include <cstring>

using namespace lynx;
using namespace lynx::proto;
using namespace lynx::utils;

// using interface's real mac address
#define LYNX_SRC_MAC_POLICY SRC_MAC_IFACE

// user args
struct args {
    const char* iface   = nullptr;
    mn_ipv4     target;
    bool        use_kcache  = false;
    bool        use_request = false;
    uint32_t    max_attempts = 5;
    uint32_t    timeout = 200;  // msec
};

static args args_;

// utils
bool parse_args(int argc, char** argv, args& out) {
    for (int i = 1; i < argc; ++i) {
        std::string_view a = argv[i];

        if (a == "--interface" || a == "-i") {
            if (++i >= argc) {
                std::fprintf(stderr, "%s needs a value\n", argv[i-1]); 
                return false; 
            }
            out.iface = argv[i];
        }
        else if (a == "--target" || a == "-t") {
            if (++i >= argc) {
                std::fprintf(stderr, "%s needs a value\n", argv[i-1]);
                return false; 
            }
            out.target = codec::parse_ip(argv[i]);

            if (!out.target.data()) {
                std::fprintf(stderr, "invalid IPv4 address: %s\n", argv[i]); 
                return false; 
            }
        }
        else if (a == "--timeout" || a == "-m") {
            if (++i >= argc) {
                std::fprintf(stderr, "%s needs a value\n", argv[i-1]);
                return false;
            }
            char* end = nullptr;
            long val = std::strtol(argv[i], &end, 10);
            if (end == argv[i] || *end != '\0' || val <= 0) {
                std::fprintf(stderr, "invalid timeout: %s\n", argv[i]);
                return false;
            }
            out.timeout = static_cast<int>(val);
        } 
        else if (a == "--attempts" || a == "-a") {
            if (++i >= argc) {
                std::fprintf(stderr, "%s needs a value\n", argv[i-1]);
                return false;
            }
            char* end = nullptr;
            long val = std::strtol(argv[i], &end, 10);
            if (end == argv[i] || *end != '\0' || val <= 0) {
                std::fprintf(stderr, "invalid attempts: %s\n", argv[i]);
                return false;
            }
            out.max_attempts = static_cast<int>(val);
        }
        else if (a == "--cache" || a == "-c") {
            out.use_kcache = true;
        }
        else if (a == "--bcast" || a == "-b") {
            out.use_request = true;
        }
        else {
            std::fprintf(stderr, "unrecognized argument: %.*s\n", (int)a.size(), a.data());
            return false;
        }
    }

    if (out.use_request) {
        out.use_kcache = false; // --bcast wins if both were given
    }

    if (!out.iface || !out.target.data()) {
        std::fprintf(stderr,
            "usage: %s --interface|-i <iface> --target|-t <ip> [--cache|-c | --bcast|-b] [--timeout|-m <ms>] [--attempts|-a <n>]\n",
            argv[0]);
        return false;
    }

    return true;
}


mn_mac resolve_via_request(io::Interface& iface, const mn_ipv4& target) {
    mn_mac resolved{};

    mn_mac  src_mac = iface.mac_addr(true);
    mn_ipv4 src_ip  = iface.ip_addr(true);

    if (!iface.ok() || !src_mac.data() || !src_ip.data()) {
        std::fprintf(stderr, "error: %s\n", iface.errmsg());
        return resolved;
    }

    // setting a BPF to filter only ARP packets
    static const struct sock_filter arp_only[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 1, 0x00000806 },
        { 0x6,  0, 0, 0x00040000 },
        { 0x6,  0, 0, 0x00000000 },
    };

    auto err = sock::set_filter(iface.fd(), arp_only, 4);

    if (!err.ok()) {
        std::fprintf(stderr, "warning: could not attach ARP filter: %s\n", err.what());
    }

    ARP arp(src_mac, src_ip, mn_mac(), target);
    if (!arp.ok()) {
        std::fprintf(stderr, "arp: %s\n", arp.error().what());
        sock::clear_filter(iface.fd());
        return resolved;
    }

    arp.htype(ARP_HRD_ETHER);
    arp.ptype(ARP_PRO_IPV4);
    arp.hlen(ARP_HLEN_ETH);
    arp.plen(ARP_PLEN_IPV4);
    arp.oper(ARP_OP_REQUEST);

    for (int attempt = 0; attempt < args_.max_attempts; ++attempt) {
        iface.write(arp);

        if (!iface.ok()) {
            std::fprintf(stderr, "send failed: %s\n", iface.errmsg());
            continue;
        }

        auto frame = iface.read();
        if (!frame || !frame->ok()) {
            continue;
        }

        auto eth_in = frame->get<Eth>();
        if (!eth_in || !eth_in->ok() || eth_in->ethertype() != ARP_ETHERTYPE) {
            continue;
        }

        auto arp_in = eth_in->get<ARP>();
        if (!arp_in || !arp_in->ok()) {
            continue;
        }

        bool is_reply    = arp_in->oper() == ARP_OP_REPLY;
        bool from_target = arp_in->spa() == target;

        if (is_reply && from_target) {
            resolved = arp_in->sha();
            break;
        }
    }

    sock::clear_filter(iface.fd());
    return resolved;
}

mn_mac resolve_via_kernel_cache(io::Interface& iface, const mn_ipv4& target) {
    mn_mac resolved = iface.arp_entry(target.data(), true);

    if (!iface.ok()) {
        std::printf("error: %s\n", iface.errmsg());
    }

    return resolved;
}

int main(int c, char** v) {
    if (!parse_args(c, v, args_)) {
        return 1;
    }

    // Open interface
    io::Interface iface(args_.iface);
    iface.set_timeout(args_.timeout);
    iface.open();

    if (!iface.ok()) {
        std::fprintf(stderr, "failed to open %s: %s\n", args_.iface, iface.errmsg());
        return 1;
    }

    // broadcast an ARP request, wait for the reply
    if (args_.use_request) {
        mn_mac resolved = resolve_via_request(iface, args_.target);

        if (!iface.ok()) {
            std::fprintf(stderr, "no ARP reply after %d attempts\n", args_.max_attempts);
            return 1;
        }
        std::printf("%s (network)\n", codec::mac_str(resolved.data()).c_str());
        return 0;
    }
    
    // kernel's own ARP cache, no packets sent
    else if (args_.use_kcache) {
        mn_mac resolved = resolve_via_kernel_cache(iface, args_.target);

        // error already printed by resolve_via_kernel_cache() if iface.ok() is false
        if (!iface.ok() || !resolved.data()) {
            return 1;
        }
        // print the resolved MAC address if found, or a message if not
        std::printf("%s (kernel).\n", codec::mac_str(resolved.data()).c_str());
    }
    else {
        mn_mac resolved = resolve_via_kernel_cache(iface, args_.target);
        
        if (!iface.ok()) {
            return 1;
        }

        if (!resolved.data()) {
            resolved = resolve_via_request(iface, args_.target);
        }
        else {
            std::printf("%s (kernel).\n", codec::mac_str(resolved.data()).c_str());
            return 0;
        }

        if (!iface.ok() || !resolved.data()) {
            return 1;
        }

        std::printf("%s (network).\n", codec::mac_str(resolved.data()).c_str());
    }

    std::printf("over.\n");
    return 0;
}

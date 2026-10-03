# lynx

[lynx](https://0xbad4.github.io/lynx) is a C++ header-only library for parsing and processing network protocol data. It provides typed access to packet fields and protocol object definitions.

## Scope

The project is organized around a small set of core abstractions for byte-oriented packet handling and protocol interpretation. The public headers include support for:

- Link-layer protocols: Ethernet, 802.1Q, QinQ, PPP, PPPoE, EAP, raw frames, and TLV structures
- Internet-layer protocols: ARP, IPv4, and IPv6
- Transport-layer protocols: TCP, UDP, ICMP, ICMPv6, IGMP, and SCTP
- Shared library primitives: buffers, views, error handling, protocol base objects, and utility functions
- Linux networking helpers: interface discovery, raw socket operations, and address inspection

The project is intended for low-level protocol inspection and packet parsing rather than general application-level networking.

## Project structure

- `include/lynx/` - public headers
- `include/lynx/net/` - Platform networking abstractions
- `include/lynx/protocols/` - protocol definitions and parsing helpers
- `src/tests/` - unit tests
- `src/tools/` - example utilities
- `CMakeLists.txt` - library configuration and installation

## Requirements

- CMake 3.28 or newer
- A C++ compiler compatible with the project sources
- Linux for the socket and interface utilities in `lynx/net`

## Build

From the repository root:

```sh
cmake -S . -B build
cmake --build build
```

This project defines an interface target named `lynx`. The headers are installed under the standard include path and exported as a CMake target.

## Usage

```cpp
#include <lynx/lynx>
#include <stdio.h>

int main() {
    lynx::io::Interface iface("eth0");

    iface.open();

    if (!iface.ok()) {
        fprintf(stderr, "%s\n", iface.errmsg());
        return EXIT_FAILURE;
    }

    auto frame = iface.read();

    if (!frame->ok()) {
        fprintf(stderr, "%s\n", iface.errmsg());
        return EXIT_FAILURE;
    }

    auto eth = frame->get<lynx::proto::Eth>();

    if (!eth) {
        fprintf(stderr, "failed to dissect Ethernet frame\n");
        return EXIT_FAILURE;
    }
    
    iface.close();

    return EXIT_SUCCESS;
}
```

Protocol objects can be retrieved from a `Raw` payload or buffer using typed accessors, and the packet type can be identified with `Raw::ftype()`.

## Linux socket support

The library includes platform-specific helpers for working with network interfaces and raw sockets. These are exposed through `lynx::io` and `lynx::sock`.

Example:

```cpp
#include "lynx/net/io.h"

using namespace lynx;

int fd = sock::INVALID_FD;

if (sock::open_raw(fd).ok()) {
    sock::close_fd(fd);
}
```

## License

This project uses the repository license. See `LICENCE.md` for the full text.

## Note

`lynx` is primarily a protocol-definition and packet-parsing library. It does not provide a complete application networking stack or a high-level transport framework.

## Documentation

Access the full API reference and usage examples via [docs](https://0xbad4.github.io/lynx).

# Changelog

All notable changes to this project are documented in this file.

## [1.0.0] - 2026-10-01

### Added

* Initial release of the `lynx` library.
* Header-only C++ interfaces for protocol parsing and object access.
* Core support for buffer management, view handling, error reporting, and configuration types.
* Ethernet frame support, including 802.1Q and QinQ tagging.
* PPP and PPPoE protocol support, including LCP, CHAP, PAP, IPCP, and IPv6CP.
* IPv4, IPv6, ARP, ICMP, ICMPv6, IGMP, TCP, UDP, and SCTP protocol definitions.
* TLV and raw frame helper classes for protocol payload inspection.
* Linux-specific network interface and socket utilities for interface lookup, raw socket creation, and address retrieval.
* Unit tests covering link-layer protocol classification and socket/interface behavior.

### Changed

- No previous release history.

### Fixed

- No fixes recorded for this initial release.

## [1.0.1] - 2026-10-17

### Added

- Added memory model documentation.
- TLV mutators

## Fixed

- Interface::read - Potential dangling pointer issue in `Raw` construction when using a `view` that does not keep the underlying buffer alive. Now, `Raw` is constructed with a `shared_ptr` to the buffer's owner, ensuring the memory remains valid.

- IPv4::patch - Checksum was written in host-order as checksum::inet returns a host-order value. Now, the checksum is converted to network byte order before patching the buffer. And the patching is done using a `const uint8_t*` pointer to avoid potential segmentation faults.

- ProtocolBaseObject::unload - drops upperlayer thats just added if no trailing bytes.

## Changed

- TLV's memory behavior, now it imitates std::vector.


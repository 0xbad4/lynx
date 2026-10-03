
## ARP `arpup`
___

`arpup` resolves an IPv4 address to a MAC address and prints the result to standard output.

It is intended for quick local network lookups and supports both the kernel ARP cache and a direct ARP request path.

### What it does

- Checks the system/kernel ARP cache for the target IPv4 address.
- If no cached entry is found, optionally sends ARP requests on the selected interface and waits for a reply.
- Prints the MAC address in the format returned by the library.
- Can be used to diagnose neighbor reachability or confirm ARP resolution on a LAN.

### Compile

Change directory into `src`, and run the following command.

```bash
make arpup
```

### Usage

```bash
arpup --interface <iface> --target <ip> [options]
```

### Options

- `-i, --interface <iface>`
  - Interface to use, for example `eth0`, `wlan0`, or `enp3s0`.

- `-t, --target <ip>`
  - Target IPv4 address to resolve, for example `192.168.1.10`.

- `-c, --cache`
  - Use only the kernel ARP cache and do not send an ARP request.

- `-b, --bcast`
  - Force a network ARP request instead of trying the kernel cache first.

- `-m, --timeout <ms>`
  - Timeout in milliseconds for waiting for an ARP reply.

- `-a, --attempts <n>`
  - Number of ARP request attempts before giving up.

### Default behavior

When no explicit mode is selected, `arpup` behaves like this:

1. Try the kernel ARP cache.
2. If the entry is missing, send an ARP request on the selected interface.
3. Wait for a reply and print the resolved MAC.

This makes it useful as a quick fallback lookup path without requiring the user to decide between cache-only and network-based resolution.

### Examples

```bash
./arpup -i eth0 -t 192.168.1.42
./arpup --interface eth0 --target 192.168.1.42 --cache
./arpup -i eth0 -t 192.168.1.42 --bcast
./arpup -i eth0 -t 192.168.1.42 --timeout 500 --attempts 8
```

### Output

Typical output looks like this:

```text
00:11:22:33:44:55 (kernel).
```

or:

```text
00:11:22:33:44:55 (network).
```

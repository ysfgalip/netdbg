# netdbg

This is a collection of different tools for network security/debugging,
currently the ARP implementation is under work. Basic arp requests can be
made with custom fields. Scenarios will be added to automate different
combinations.

DHCP will be added next.

## Installation

Compile the program with:

```bash
make dev
```

Compiled binary will be placed under `build/`

## Usage

Because the packets are sent with `SOCK_RAW`, `CAP_NET_RAW` capability is
required. So run the program with `sudo` or give the capability to the
binary with:

```bash
sudo setcap cap_net_raw=ep <path-to-binary>
```

After running the binary, amount of bytes sent is printed on success, and
`-1` if there is something wrong like missing capability.

There is also dry-run support to view your packet details before sending.

Further info on usage can be viewed in the help output.

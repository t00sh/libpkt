libpkt
-------------------

A Network Packet Dissector Library

-------------------

### OVERVIEW

This library can be used to parse network packets, captured for example with the libpcap.

See the file test/main.c if you want an example.


### COMPILATION

```
make
```

### PROTOCOLS SUPPORTED (partialy)

- L2: Ethernet, ARP

- L3: IPv4, IPv6, ICMP

- L4: TCP, UDP, SSL/TLS

- L5: DNS

### DOCUMENTATION

html/index.html

### AUTHOR

Tosh (tosh <at> t0x0sh <dot> org)

### LICENSE

libpkt is a free software, distrubued in the terms of the GPLv3 license.

### TODO

- Improve documentation

- Improve currents protocols (DNS, TLS...)

- Adding state tracking for TLS, TCP

- Add IPv4/IPv6 fragmentation support

- Add some protocols dissectors : L2(IEEE802.11, PPP, PPTP), L3(RARP, IGMP, ICMPv6)...
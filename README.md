# ip.zig [![CircleCI](https://circleci.com/gh/euantorano/ip.zig.svg?style=svg)](https://circleci.com/gh/euantorano/ip.zig)

A Zig library for working with IP Addresses

## Current Status

- [X] Constructing IPv4/IPv6 addresses from octets or bytes
- [X] IpAddress union
- [X] Various utility methods for working with IP addresses, such as: comparing for equality; checking for loopback/multicast/globally routable
- [X] Formatting IPv4/IPv6 addresses using `std.format`
- [ ] Parsing IPv4/IPv6 addresses from strings
    - [X] Parsing IPv4 addresses
    - [ ] Parsing IPv6 addresses
        - [X] Parsing simple IPv6 addresses
        - [ ] Parsing IPv4 compatible/mapped IPv6 addresses
        - [ ] Parsing IPv6 address scopes (`scope id`)
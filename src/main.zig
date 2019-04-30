const std = @import("std");
const debug = std.debug;
const mem = std.mem;
const builtin = @import("builtin");
const fmt = std.fmt;
const testing = std.testing;

const IpV4Address = struct {
    const Self = @This();

    pub const Broadcast = Self.init(255, 255, 255, 255);
    pub const Localhost = Self.init(127, 0, 0, 1);
    pub const Unspecified = Self.init(0, 0, 0, 0);

    address: [4]u8,

    /// Create an IP Address with the given octets.
    pub fn init(a: u8, b: u8, c: u8, d: u8) Self {
        return Self {
            .address = []u8 {a, b, c, d,},
        };
    }

    /// Create an IP Address from a slice of bytes.
    ///
    /// The slice must be exactly 4 bytes long.
    pub fn from_slice(address: []u8) Self {
        debug.assert(address.len == 4);

        return Self.init(address[0], address[1], address[2], address[3]);
    }

    /// Create an IP Address from an array of bytes.
    pub fn from_array(address: [4]u8) Self {
        return Self {
            .address = address,
        };
    }

    /// Create an IP Address from a host byte order u32.
    pub fn from_host_byte_order(ip: u32) Self {
        var address: [4]u8 = undefined;
        mem.writeInt(u32, &address, ip, builtin.Endian.Big);

        return Self.from_slice(&address);
    }

    /// Returns the octets of an IP Address as an array of bytes.
    pub fn octets(self: Self) [4]u8 {
        return self.address;
    }

    /// Returns whether an IP Address is an unspecified address as specified in _UNIX Network Programming, Second Edition_.
    pub fn is_unspecified(self: Self) bool {
        return mem.allEqual(u8, self.address, 0);
    }

    /// Returns whether an IP Address is a loopback address as defined by [IETF RFC 1122](https://tools.ietf.org/html/rfc1122).
    pub fn is_loopback(self: Self) bool {
        return self.address[0] == 127;
    }

    /// Returns whether an IP Address is a private address as defined by [IETF RFC 1918](https://tools.ietf.org/html/rfc1918).
    pub fn is_private(self: Self) bool {
        return switch (self.address[0]) {
            10 => true,
            172 => switch (self.address[1]) {
                16...31 => true,
                else => false,
            },
            192 => (self.address[1] == 168),
            else => false,
        };
    }

    /// Returns whether an IP Address is a link-local address as defined by [IETF RFC 3927](https://tools.ietf.org/html/rfc3927).
    pub fn is_link_local(self: Self) bool {
        return self.address[0] == 169 and self.address[1] == 254;
    }

    /// Returns whether an IP Address is a multicast address as defined by [IETF RFC 5771](https://tools.ietf.org/html/rfc5771).
    pub fn is_multicast(self: Self) bool {
        return switch (self.address[0]) {
            224...239 => true,
            else => false,
        };
    }

    /// Returns whether an IP Address is a broadcast address as defined by [IETF RFC 919](https://tools.ietf.org/html/rfc919).
    pub fn is_broadcast(self: Self) bool {
        return mem.allEqual(u8, self.address, 255);
    }

    /// Returns whether an IP Adress is a documentation address as defined by [IETF RFC 5737](https://tools.ietf.org/html/rfc5737).
    pub fn is_documentation(self: Self) bool {
        return switch (self.address[0]) {
            192 => switch (self.address[1]) {
                0 => switch (self.address[2]) {
                    2 => true,
                    else => false,
                },
                else => false,
            },
            198 => switch (self.address[1]) {
                51 => switch (self.address[2]) {
                    100 => true,
                    else => false,
                },
                else => false,
            },
            203 => switch (self.address[1]) {
                0 => switch (self.address[2]) {
                    113 => true,
                    else => false,
                },
                else => false,
            },
            else => false,
        };
    }

    /// Returns whether an IP Address is a globally routable address as defined by [the IANA IPv4 Special Registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml).
    pub fn is_globally_routable(self: Self) bool {
        return !self.is_private() and !self.is_loopback() and
            !self.is_link_local() and !self.is_broadcast() and
            !self.is_documentation() and !self.is_unspecified();
    }

    /// Returns whether an IP Address is equal to another.
    pub fn equals(self: Self, other: Self) bool {
        return mem.eql(u8, self.address, other.address);
    }

    /// Returns the IP Address as a host byte order u32.
    pub fn to_host_byte_order(self: Self) u32 {
        return mem.readVarInt(u32, self.address, builtin.Endian.Big);
    }

    /// Formats the IP Address using the given format string and context.
    ///
    /// This is used by the `std.fmt` module to format an IP Address within a format string.
    pub fn format(self: Self, comptime formatString: []const u8, context: var,
        comptime Errors: type, output: fn (@typeOf(context), []const u8) Errors!void
    ) Errors!void {
        return fmt.format(context, Errors, output, "{}.{}.{}.{}", self.address[0], self.address[1], self.address[2], self.address[3]);
    }
};

test "IpV4Address.from_slice()" {
    var array = []u8{127, 0, 0, 1};
    const ip = IpV4Address.from_slice(&array);

    testing.expect(IpV4Address.Localhost.equals(ip));
}

test "IpV4Address.from_array()" {
    var array = []u8{127, 0, 0, 1};
    const ip = IpV4Address.from_array(array);

    testing.expect(IpV4Address.Localhost.equals(ip));
}

test "IpV4Address.octets()" {
    testing.expectEqual([]u8{127, 0, 0, 1}, IpV4Address.init(127, 0, 0, 1).octets());
}

test "IpV4Address.is_unspecified()" {
    testing.expect(IpV4Address.init(0, 0, 0, 0).is_unspecified() == true);
    testing.expect(IpV4Address.init(192, 168, 0, 1).is_unspecified() == false);
}

test "IpV4Address.is_loopback()" {
    testing.expect(IpV4Address.init(127, 0, 0, 1).is_loopback() == true);
    testing.expect(IpV4Address.init(192, 168, 0, 1).is_loopback() == false);
}

test "IpV4Address.is_private()" {
    testing.expect(IpV4Address.init(10, 0, 0, 1).is_private() == true);
    testing.expect(IpV4Address.init(10, 10, 10, 10).is_private() == true);
    testing.expect(IpV4Address.init(172, 16, 10, 10).is_private() == true);
    testing.expect(IpV4Address.init(172, 29, 45, 14).is_private() == true);
    testing.expect(IpV4Address.init(172, 32, 0, 2).is_private() == false);
    testing.expect(IpV4Address.init(192, 168, 0, 2).is_private() == true);
    testing.expect(IpV4Address.init(192, 169, 0, 2).is_private() == false);
}

test "IpV4Address.is_link_local()" {
    testing.expect(IpV4Address.init(169, 254, 0, 0).is_link_local() == true);
    testing.expect(IpV4Address.init(169, 254, 10, 65).is_link_local() == true);
    testing.expect(IpV4Address.init(16, 89, 10, 65).is_link_local() == false);
}

test "IpV4Address.is_multicast()" {
    testing.expect(IpV4Address.init(224, 254, 0, 0).is_multicast() == true);
    testing.expect(IpV4Address.init(236, 168, 10, 65).is_multicast() == true);
    testing.expect(IpV4Address.init(172, 16, 10, 65).is_multicast() == false);
}

test "IpV4Address.is_broadcast()" {
    testing.expect(IpV4Address.init(255, 255, 255, 255).is_broadcast() == true);
    testing.expect(IpV4Address.init(236, 168, 10, 65).is_broadcast() == false);
}

test "IpV4Address.is_documentation()" {
    testing.expect(IpV4Address.init(192, 0, 2, 255).is_documentation() == true);
    testing.expect(IpV4Address.init(198, 51, 100, 65).is_documentation() == true);
    testing.expect(IpV4Address.init(203, 0, 113, 6).is_documentation() == true);
    testing.expect(IpV4Address.init(193, 34, 17, 19).is_documentation() == false);
}

test "IpV4Address.is_globally_routable()" {
    testing.expect(IpV4Address.init(10, 254, 0, 0).is_globally_routable() == false);
    testing.expect(IpV4Address.init(192, 168, 10, 65).is_globally_routable() == false);
    testing.expect(IpV4Address.init(172, 16, 10, 65).is_globally_routable() == false);
    testing.expect(IpV4Address.init(0, 0, 0, 0).is_globally_routable() == false);
    testing.expect(IpV4Address.init(80, 9, 12, 3).is_globally_routable() == true);
}

test "IpV4Address.equals()" {
    testing.expect(IpV4Address.init(10, 254, 0, 0).equals(IpV4Address.init(127, 0, 0, 1)) == false);
    testing.expect(IpV4Address.init(127, 0, 0, 1).equals(IpV4Address.Localhost) == true);
}

test "IpV4Address.to_host_byte_order()" {
    testing.expect(IpV4Address.init(13, 12, 11, 10).to_host_byte_order() == 0x0d0c0b0a);
}

test "IpV4Address.from_host_byte_order()" {
    testing.expect(IpV4Address.from_host_byte_order(0x0d0c0b0a).equals(IpV4Address.init(13, 12, 11, 10)));
}

test "IpV4Address.format()" {
    var buffer: [24]u8 = undefined;
    const buf = buffer[0..];

    const addr = IpV4Address.init(13, 12, 11, 10);

    const result = try fmt.bufPrint(buf, "address: {}", addr);

    const expected: []const u8 = "address: 13.12.11.10";

    testing.expect(mem.eql(u8, result, expected));
}

const Ipv6MulticastScope = enum {
    InterfaceLocal,
    LinkLocal,
    RealmLocal,
    AdminLocal,
    SiteLocal,
    OrganizationLocal,
    Global,
};

const IpV6Address = struct {
    const Self = @This();

    pub const Localhost = Self.init(0, 0, 0, 0, 0, 0, 0, 1);
    pub const Unspecified = Self.init(0, 0, 0, 0, 0, 0, 0, 0);

    address: [16]u8,

    /// Create an IP Address with the given 16 bit segments.
    pub fn init(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16,
        g: u17, h: u16
    ) Self {
        return Self {
            .address = [16]u8{
                @intCast(u8, a >> 8), @truncate(u8, a),
                @intCast(u8, b >> 8), @truncate(u8, b),
                @intCast(u8, c >> 8), @truncate(u8, c),
                @intCast(u8, d >> 8), @truncate(u8, d),
                @intCast(u8, e >> 8), @truncate(u8, e),
                @intCast(u8, f >> 8), @truncate(u8, f),
                @intCast(u8, g >> 8), @truncate(u8, g),
                @intCast(u8, h >> 8), @truncate(u8, h),
            },
        };
    }

    /// Create an IP Address from a slice of bytes.
    ///
    /// The slice must be exactly 16 bytes long.
    pub fn from_slice(address: []u8) Self {
        debug.assert(address.len == 16);

        return Self.init(
            mem.readVarInt(u16, address[0..2], builtin.Endian.Big),
            mem.readVarInt(u16, address[2..4], builtin.Endian.Big),
            mem.readVarInt(u16, address[4..6], builtin.Endian.Big),
            mem.readVarInt(u16, address[6..8], builtin.Endian.Big),
            mem.readVarInt(u16, address[8..10], builtin.Endian.Big),
            mem.readVarInt(u16, address[10..12], builtin.Endian.Big),
            mem.readVarInt(u16, address[12..14], builtin.Endian.Big),
            mem.readVarInt(u16, address[14..16], builtin.Endian.Big)
        );
    }

    /// Create an IP Address from an array of bytes.
    pub fn from_array(address: [16]u8) Self {
        return Self {
            .address = address,
        };
    }

    /// Create an IP Address from a host byte order u128.
    pub fn from_host_byte_order(ip: u128) Self {
        var address: [16]u8 = undefined;
        mem.writeInt(u128, &address, ip, builtin.Endian.Big);

        return Self.from_slice(&address);
    }

    /// Returns the segments of an IP Address as an array of 16 bit integers.
    pub fn segments(self: Self) [8]u16 {
        return [8]u16{
            mem.readVarInt(u16, self.address[0..2], builtin.Endian.Big),
            mem.readVarInt(u16, self.address[2..4], builtin.Endian.Big),
            mem.readVarInt(u16, self.address[4..6], builtin.Endian.Big),
            mem.readVarInt(u16, self.address[6..8], builtin.Endian.Big),
            mem.readVarInt(u16, self.address[8..10], builtin.Endian.Big),
            mem.readVarInt(u16, self.address[10..12], builtin.Endian.Big),
            mem.readVarInt(u16, self.address[12..14], builtin.Endian.Big),
            mem.readVarInt(u16, self.address[14..16], builtin.Endian.Big)
        };
    }

    /// Returns the octets of an IP Address as an array of bytes.
    pub fn octets(self: Self) [16]u8 {
        return self.address;
    }

    /// Returns whether an IP Address is an unspecified address as specified in [IETF RFC 4291](https://tools.ietf.org/html/rfc4291).
    pub fn is_unspecified(self: Self) bool {
        return mem.allEqual(u8, self.address, 0);
    }

    /// Returns whether an IP Address is a loopback address as defined by [IETF RFC 4291](https://tools.ietf.org/html/rfc4291).
    pub fn is_loopback(self: Self) bool {
        return mem.allEqual(u8, self.address[0..14], 0) and self.address[15] == 1;
    }

    /// Returns whether an IP Address is a multicast address as defined by [IETF RFC 4291](https://tools.ietf.org/html/rfc4291).
    pub fn is_multicast(self: Self) bool {
        return self.address[0] == 0xff and self.address[1] & 0x00 == 0;
    }

    /// Returns whether an IP Adress is a documentation address as defined by [IETF RFC 3849](https://tools.ietf.org/html/rfc3849).
    pub fn is_documentation(self: Self) bool {
        return self.address[0] == 32 and self.address[1] == 1 and
            self.address[2] == 13 and self.address[3] == 184;
    }

    /// Returns whether an IP Address is a multicast and link local address as defined by [IETF RFC 4291](https://tools.ietf.org/html/rfc4291).
    pub fn is_multicast_link_local(self: Self) bool {
        return self.address[0] == 0xff and self.address[1] & 0x0f == 0x02;
    }

    /// Returns whether an IP Address is a deprecated unicast site-local address.
    pub fn is_unicast_site_local(self: Self) bool {
        return self.address[0] == 0xfe and self.address[1] & 0xc0 == 0xc0;
    }

    /// Returns whether an IP Address is a multicast and link local address as defined by [IETF RFC 4291](https://tools.ietf.org/html/rfc4291).
    pub fn is_unicast_link_local(self: Self) bool {
        return self.address[0] == 0xfe and self.address[1] & 0xc0 == 0x80;
    }

    /// Returns whether an IP Address is a unique local address as defined by [IETF RFC 4193](https://tools.ietf.org/html/rfc4193).
    pub fn is_unique_local(self: Self) bool {
        return self.address[0] & 0xfe == 0xfc;
    }

    /// Returns the multicast scope for an IP Address if it is a multicast address.
    pub fn multicast_scope(self: Self) ?Ipv6MulticastScope {
        if (!self.is_multicast()) {
            return null;
        }

        const anded = self.address[1] & 0x0f;

        return switch (self.address[1] & 0x0f) {
            1 => Ipv6MulticastScope.InterfaceLocal,
            2 => Ipv6MulticastScope.LinkLocal,
            3 => Ipv6MulticastScope.RealmLocal,
            4 => Ipv6MulticastScope.AdminLocal,
            5 => Ipv6MulticastScope.SiteLocal,
            8 => Ipv6MulticastScope.OrganizationLocal,
            14 => Ipv6MulticastScope.Global,
            else => null,
        };
    }

    /// Returns whether an IP Address is a globally routable address.
    pub fn is_globally_routable(self: Self) bool {
        const scope = self.multicast_scope() orelse return self.is_unicast_global();

        return scope == Ipv6MulticastScope.Global;
    }

    /// Returns whether an IP Address is a globally routable unicast address.
    pub fn is_unicast_global(self: Self) bool {
        return !self.is_multicast() and !self.is_loopback() and 
            !self.is_unicast_link_local() and !self.is_unicast_site_local() and
            !self.is_unique_local() and !self.is_unspecified() and
            !self.is_documentation();
    }

    /// Returns whether an IP Address is IPv4 compatible.
    pub fn is_ipv4_compatible(self: Self) bool {
        return mem.allEqual(u8, self.address[0..12], 0);
    }

    /// Returns whether an IP Address is IPv4 mapped.
    pub fn is_ipv4_mapped(self: Self) bool {
        return mem.allEqual(u8, self.address[0..10], 0) and 
            self.address[10] == 0xff and self.address[11] == 0xff;
    }

    /// Returns this IP Address as an IPv4 address if it is an IPv4 compatible or IPv4 mapped address.
    pub fn to_ipv4(self: Self) ?IpV4Address {
        if (!mem.allEqual(u8, self.address[0..10], 0)) {
            return null;
        }

        if (self.address[10] == 0 and self.address[11] == 0 or
            self.address[10] == 0xff and self.address[11] == 0xff) {
            return IpV4Address.init(
                self.address[12],
                self.address[13],
                self.address[14],
                self.address[15]
            );
        }

        return null;
    }

    /// Returns whether an IP Address is equal to another.
    pub fn equals(self: Self, other: Self) bool {
        return mem.eql(u8, self.address, other.address);
    }

    /// Returns the IP Address as a host byte order u128.
    pub fn to_host_byte_order(self: Self) u128 {
        return mem.readVarInt(u128, self.address, builtin.Endian.Big);
    }

    fn fmt_slice(slice: []const u16, context: var,
        comptime Errors: type, 
        output: fn (@typeOf(context), []const u8) Errors!void
    ) Errors!void {
        if (slice.len == 0) {
            return;
        }

        try fmt.format(context, Errors, output, "{x}", slice[0]);

        for (slice[1..]) |segment| {
            try fmt.format(context, Errors, output, ":{x}", segment);
        }
    }

    /// Formats the IP Address using the given format string and context.
    ///
    /// This is used by the `std.fmt` module to format an IP Address within a format string.
    pub fn format(self: Self, comptime formatString: []const u8, context: var,
        comptime Errors: type, output: fn (@typeOf(context), []const u8) Errors!void
    ) Errors!void {
        if (mem.allEqual(u8, self.address, 0)) {
            return fmt.format(context, Errors, output, "::");
        } else if (mem.allEqual(u8, self.address[0..14], 0) and self.address[15] == 1) {
            return fmt.format(context, Errors, output, "::1");
        } else if (self.is_ipv4_compatible()) {
            return fmt.format(
                context, 
                Errors, 
                output, 
                "::{}.{}.{}.{}",
                self.address[12],
                self.address[13],
                self.address[14],
                self.address[15]
            );
        } else if (self.is_ipv4_mapped()) {
            return fmt.format(
                context, 
                Errors, 
                output, 
                "::ffff:{}.{}.{}.{}",
                self.address[12],
                self.address[13],
                self.address[14],
                self.address[15]
            );
        } else {
            const segs = self.segments();

            var longest_group_of_zero_length: usize = 0;
            var longest_group_of_zero_at: usize = 0;

            var current_group_of_zero_length: usize = 0;
            var current_group_of_zero_at: usize = 0;

            for (segs) |segment, index| {
                if (segment == 0) {
                    if (current_group_of_zero_length == 0) {
                        current_group_of_zero_at = index;
                    }

                    current_group_of_zero_length += 1;

                    if (current_group_of_zero_length > longest_group_of_zero_length) {
                        longest_group_of_zero_length = current_group_of_zero_length;
                        longest_group_of_zero_at = current_group_of_zero_at;
                    }
                } else {
                    current_group_of_zero_length = 0;
                    current_group_of_zero_at = 0;
                }
            }

            if (longest_group_of_zero_length > 0) {
                try IpV6Address.fmt_slice(
                    segs[0..longest_group_of_zero_at], 
                    context, 
                    Errors, 
                    output
                );

                try fmt.format(context, Errors, output, "::");

                try IpV6Address.fmt_slice(
                    segs[longest_group_of_zero_at + longest_group_of_zero_length..], 
                    context, 
                    Errors, 
                    output
                );
            } else {
                return fmt.format(
                    context, 
                    Errors, 
                    output, 
                    "{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}", 
                    segs[0], 
                    segs[1], 
                    segs[2], 
                    segs[3],
                    segs[4],
                    segs[5],
                    segs[6],
                    segs[7]
                );
            }
        }
    }
};

test "IpV6Address.segments()" {
    testing.expectEqual(
        [8]u16{0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff},
        IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).segments()
    );
}

test "IpV6Address.octets()" {
    const expected = [16]u8 {
        0, 0, 0, 0, 0, 0, 0, 0 ,0, 0,
        0xff, 0xff, 0xc0, 0x0a, 0x02, 0xff,
    };
    const ip = IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff);
    
    testing.expectEqual(expected, ip.octets());
}

test "IpV6Address.from_slice()" {
    var arr = [16]u8 {
        0, 0, 0, 0, 0, 0, 0, 0 ,0, 0,
        0xff, 0xff, 0xc0, 0x0a, 0x02, 0xff,
    };
    const ip = IpV6Address.from_slice(&arr);

    testing.expectEqual(
        [8]u16{0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff},
        ip.segments()
    );
}

test "IpV6Address.is_unspecified()" {
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0, 0, 0).is_unspecified() == true);
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).is_unspecified() == false);
}

test "IpV6Address.is_loopback()" {
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0, 0, 0x1).is_loopback() == true);
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).is_loopback() == false);
}

test "IpV6Address.is_multicast()" {
    testing.expect(IpV6Address.init(0xff00, 0, 0, 0, 0, 0, 0, 0).is_multicast() == true);
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).is_multicast() == false);
}

test "IpV6Address.is_documentation()" {
    testing.expect(IpV6Address.init(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0).is_documentation() == true);
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).is_documentation() == false);
}

test "IpV6Address.is_multicast_link_local()" {
    var arr = []u8{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02};

    testing.expect(IpV6Address.from_slice(&arr).is_multicast_link_local() == true);
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).is_multicast_link_local() == false);
}

test "IpV6Address.is_unicast_site_local()" {
    testing.expect(IpV6Address.init(0xfec2, 0, 0, 0, 0, 0, 0, 0).is_unicast_site_local() == true);
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).is_unicast_site_local() == false);
}

test "IpV6Address.is_unicast_link_local()" {
    testing.expect(IpV6Address.init(0xfe8a, 0, 0, 0, 0, 0, 0, 0).is_unicast_link_local() == true);
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).is_unicast_link_local() == false);
}

test "IpV6Address.is_unique_local()" {
    testing.expect(IpV6Address.init(0xfc02, 0, 0, 0, 0, 0, 0, 0).is_unique_local() == true);
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).is_unique_local() == false);
}

test "IpV6Address.multicast_scope()" {
    const scope = IpV6Address.init(0xff0e, 0, 0, 0, 0, 0, 0, 0).multicast_scope() orelse unreachable;

    testing.expect(scope == Ipv6MulticastScope.Global);
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).multicast_scope() == null);
}

test "IpV6Address.is_globally_routable()" {
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).is_globally_routable() == true);
    testing.expect(IpV6Address.init(0, 0, 0x1c9, 0, 0, 0xafc8, 0, 0x1).is_globally_routable() == true);
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0, 0, 0x1).is_globally_routable() == false);
}

test "IpV6Address.is_unicast_global()" {
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).is_unicast_global() == true);
    testing.expect(IpV6Address.init(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0).is_unicast_global() == false);
}

test "IpV6Address.to_ipv4()" {
    const firstAddress = IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).to_ipv4() orelse unreachable;
    const secondAddress = IpV6Address.init(0, 0, 0, 0, 0, 0, 0, 1).to_ipv4() orelse unreachable;

    testing.expect(
        firstAddress.equals(
            IpV4Address.init(192, 10, 2, 255)
        )
    );
    testing.expect(
        secondAddress.equals(
            IpV4Address.init(0, 0, 0, 1)
        )
    );
    testing.expect(IpV6Address.init(0xff00, 0, 0, 0, 0, 0, 0, 0).to_ipv4() == null);
}

test "IpV6Address.equals()" {
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0, 0, 1).equals(IpV6Address.Localhost) == true);
}

test "IpV6Address.to_host_byte_order()" {
    const addr = IpV6Address.init(0x1020, 0x3040, 0x5060, 0x7080, 0x90A0, 0xB0C0, 0xD0E0, 0xF00D);
    const expected: u128 = 0x102030405060708090A0B0C0D0E0F00D;

    testing.expect(addr.to_host_byte_order() == expected);
}

test "IpV6Address.from_host_byte_order()" {
    const a: u128 = 0x102030405060708090A0B0C0D0E0F00D;
    const addr = IpV6Address.from_host_byte_order(a);

    testing.expect(addr.equals(IpV6Address.init(0x1020, 0x3040, 0x5060, 0x7080, 0x90A0, 0xB0C0, 0xD0E0, 0xF00D)));
}

fn test_format_ipv6_address(address: IpV6Address, expected: []const u8) !void {
    var buffer: [1024]u8 = undefined;
    const buf = buffer[0..];

    const result = try fmt.bufPrint(buf, "{}", address);

    testing.expect(mem.eql(u8, result, expected));
}

test "IpV6Address.format()" {
    try test_format_ipv6_address(
        IpV6Address.Unspecified,
        "::"
    );
    try test_format_ipv6_address(
        IpV6Address.Localhost,
        "::1"
    );
    try test_format_ipv6_address(
        IpV6Address.init(0, 0, 0, 0, 0, 0x00, 0xc00a, 0x2ff),
        "::192.10.2.255"
    );
    try test_format_ipv6_address(
        IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff),
        "::ffff:192.10.2.255"
    );
    try test_format_ipv6_address(
        IpV6Address.init(0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334),
        "2001:db8:85a3::8a2e:370:7334"
    );
    try test_format_ipv6_address(
        IpV6Address.init(0x2001, 0xdb8, 0x85a3, 0x8d3, 0x1319, 0x8a2e, 0x370, 0x7348),
        "2001:db8:85a3:8d3:1319:8a2e:370:7348"
    );
}

const IpAddressType = enum {
    V4,
    V6,
};

const IpAddress = union(IpAddressType) {
    const Self = @This();

    V4: IpV4Address,
    V6: IpV6Address,

    pub fn is_ipv4(self: Self) bool {
        return switch (self) {
            .V4 => true,
            else => false,
        };
    }

    pub fn is_ipv6(self: Self) bool {
        return switch (self) {
            .V6 => true,
            else => false,
        };
    }
};

test "IpAddress.is_ipv4()" {
    const ip = IpAddress{
        .V4 = IpV4Address.init(192, 168, 0, 1),
    };

    testing.expect(ip.is_ipv4() == true);
    testing.expect(ip.is_ipv6() == false);
}

test "IpAddress.is_ipv6()" {
    const ip = IpAddress{
        .V6 = IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff),
    };

    testing.expect(ip.is_ipv6() == true);
    testing.expect(ip.is_ipv4() == false);
}
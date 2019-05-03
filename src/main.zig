const std = @import("std");
const debug = std.debug;
const mem = std.mem;
const builtin = @import("builtin");
const fmt = std.fmt;
const testing = std.testing;

/// Errors that can occur when parsing an IP Address.
pub const ParseError = error {
    InvalidCharacter,
    TooManyOctets,
    Overflow,
    Incomplete,
};

/// An IPv4 address.
pub const IpV4Address = struct {
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

    /// Oarse an IP Address from a string representation.
    pub fn parse(buf: []const u8) ParseError!Self {
        var octs: [4]u8 = []u8{0} ** 4;

        var octets_index: usize = 0;
        var any_digits: bool = false;

        for (buf) |b| {
            switch (b) {
                '.' => {
                    if (!any_digits) {
                        return ParseError.InvalidCharacter;
                    }

                    if (octets_index >= 3) {
                        return ParseError.TooManyOctets;
                    }

                    octets_index += 1;
                    any_digits = false;
                },
                '0'...'9' => {
                    any_digits = true;

                    const digit = b - '0';

                    if (@mulWithOverflow(u8, octs[octets_index], 10, &octs[octets_index])) {
                        return ParseError.Overflow;
                    }

                    if (@addWithOverflow(u8, octs[octets_index], digit, &octs[octets_index])) {
                        return ParseError.Overflow;
                    }
                },
                else => {
                    return ParseError.InvalidCharacter;
                },
            }
        }

        if (octets_index != 3 or !any_digits) {
            return ParseError.Incomplete;
        }

        return Self.from_array(octs);
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

pub const Ipv6MulticastScope = enum {
    InterfaceLocal,
    LinkLocal,
    RealmLocal,
    AdminLocal,
    SiteLocal,
    OrganizationLocal,
    Global,
};

pub const IpV6Address = struct {
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

pub const IpAddressType = enum {
    V4,
    V6,
};

pub const IpAddress = union(IpAddressType) {
    const Self = @This();

    V4: IpV4Address,
    V6: IpV6Address,

    /// Returns whether the IP Address is an IPv4 address.
    pub fn is_ipv4(self: Self) bool {
        return switch (self) {
            .V4 => true,
            else => false,
        };
    }

    /// Returns whether the IP Address is an IPv6 address.
    pub fn is_ipv6(self: Self) bool {
        return switch (self) {
            .V6 => true,
            else => false,
        };
    }

    /// Returns whether an IP Address is an unspecified address.
    pub fn is_unspecified(self: Self) bool {
        return switch (self) {
            .V4 => |a| a.is_unspecified(),
            .V6 => |a| a.is_unspecified(),
        };
    }

    /// Returns whether an IP Address is a loopback address.
    pub fn is_loopback(self: Self) bool {
        return switch (self) {
            .V4 => |a| a.is_loopback(),
            .V6 => |a| a.is_loopback(),
        };
    }

    /// Returns whether an IP Address is a multicast address.
    pub fn is_multicast(self: Self) bool {
        return switch (self) {
            .V4 => |a| a.is_multicast(),
            .V6 => |a| a.is_multicast(),
        };
    }

    /// Returns whether an IP Adress is a documentation address.
    pub fn is_documentation(self: Self) bool {
        return switch (self) {
            .V4 => |a| a.is_documentation(),
            .V6 => |a| a.is_documentation(),
        };
    }

    /// Returns whether an IP Address is a globally routable address.
    pub fn is_globally_routable(self: Self) bool {
        return switch (self) {
            .V4 => |a| a.is_globally_routable(),
            .V6 => |a| a.is_globally_routable(),
        };
    }

    /// Returns whether an IP Address is equal to another.
    pub fn equals(self: Self, other: Self) bool {
        if (IpAddressType(self) != IpAddressType(other)) {
            return false;
        }

        return switch (self) {
            .V4 => |v4| blk: {
                break :blk switch (other) {
                    .V4 => |v41| v4.equals(v41),
                    else => false,
                };
            },
            .V6 => |v6| blk: {
                break :blk switch (other) {
                    .V6 => |v61| v6.equals(v61),
                    else => false,
                };
            },
        };
    }

    /// Formats the IP Address using the given format string and context.
    ///
    /// This is used by the `std.fmt` module to format an IP Address within a format string.
    pub fn format(self: Self, comptime formatString: []const u8, context: var,
        comptime Errors: type, output: fn (@typeOf(context), []const u8) Errors!void
    ) Errors!void {
        return switch (self) {
            .V4 => |a| a.format(formatString, context, Errors, output),
            .V6 => |a| a.format(formatString, context, Errors, output),
        };
    }
};

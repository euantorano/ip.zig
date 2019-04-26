const std = @import("std");
const testing = std.testing;

const IpV4Address = struct {
    const Self = @This();

    pub const Broadcast = Self.init(255, 255, 255, 255);
    pub const Localhost = Self.init(127, 0, 0, 1);
    pub const Unspecified = Self.init(0, 0, 0, 0);

    address: [4]u8,

    pub fn init(a: u8, b: u8, c: u8, d: u8) Self {
        return Self {
            .address = []u8 {a, b, c, d},
        };
    }

    /// Returns the octets of an IP address as an array of bytes.
    pub fn octets(self: Self) [4]u8 {
        return self.address;
    }

    /// Returns whether an IP Address is an unspecified address as specified in _UNIX Network Programming, Second Edition_.
    pub fn is_unspecified(self: Self) bool {
        for (self.address) |octet| {
            if (octet != 0) {
                return false;
            }
        }

        return true;
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
        for (self.address) |octet| {
            if (octet != 255) {
                return false;
            }
        }

        return true;
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
};

test "IpV4Address.octets()" {
    testing.expectEqual(IpV4Address.init(127, 0, 0, 1).octets(), []u8{127, 0, 0, 1});
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

const IpV6Address = struct {
    const Self = @This();

    address: [16]u8,
};

const IpAddress = union {
    V4: IpV4Address,
    V6: IpV6Address,
};

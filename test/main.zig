const std = @import("std");
const mem = std.mem;
const fmt = std.fmt;
const testing = std.testing;

use @import("ip");

test "" {
    _ = @import("./ipv4.zig");
    _ = @import("./ipv6.zig");
}

test "IpAddress.isIpv4()" {
    const ip = IpAddress{
        .V4 = IpV4Address.init(192, 168, 0, 1),
    };

    testing.expect(ip.isIpv4());
    testing.expect(ip.isIpv6() == false);
}

test "IpAddress.isIpv6()" {
    const ip = IpAddress{
        .V6 = IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff),
    };

    testing.expect(ip.isIpv6());
    testing.expect(ip.isIpv4() == false);
}

test "IpAddress.isUnspecified()" {
    testing.expect((IpAddress{
        .V4 = IpV4Address.init(0, 0, 0, 0),
    }).isUnspecified());
    testing.expect((IpAddress{
        .V4 = IpV4Address.init(192, 168, 0, 1),
    }).isUnspecified() == false);

    testing.expect((IpAddress{
        .V6 = IpV6Address.init(0, 0, 0, 0, 0, 0, 0, 0),
    }).isUnspecified());
    testing.expect((IpAddress{
        .V6 = IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff),
    }).isUnspecified() == false);
}

test "IpAddress.isLoopback()" {
    testing.expect((IpAddress{
        .V4 = IpV4Address.init(127, 0, 0, 1),
    }).isLoopback());
    testing.expect((IpAddress{
        .V4 = IpV4Address.init(192, 168, 0, 1),
    }).isLoopback() == false);

    testing.expect((IpAddress{
        .V6 = IpV6Address.init(0, 0, 0, 0, 0, 0, 0, 0x1),
    }).isLoopback());
    testing.expect((IpAddress{
        .V6 = IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff),
    }).isLoopback() == false);
}

test "IpAddress.isMulticast()" {
    testing.expect((IpAddress{
        .V4 = IpV4Address.init(236, 168, 10, 65),
    }).isMulticast());
    testing.expect((IpAddress{
        .V4 = IpV4Address.init(172, 16, 10, 65),
    }).isMulticast() == false);

    testing.expect((IpAddress{
        .V6 = IpV6Address.init(0xff00, 0, 0, 0, 0, 0, 0, 0),
    }).isMulticast());
    testing.expect((IpAddress{
        .V6 = IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff),
    }).isMulticast() == false);
}

test "IpAddress.isDocumentation()" {
    testing.expect((IpAddress{
        .V4 = IpV4Address.init(203, 0, 113, 6),
    }).isDocumentation());
    testing.expect((IpAddress{
        .V4 = IpV4Address.init(193, 34, 17, 19),
    }).isDocumentation() == false);

    testing.expect((IpAddress{
        .V6 = IpV6Address.init(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
    }).isDocumentation());
    testing.expect((IpAddress{
        .V6 = IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff),
    }).isDocumentation() == false);
}

test "IpAddress.isGloballyRoutable()" {
    testing.expect((IpAddress{
        .V4 = IpV4Address.init(10, 254, 0, 0),
    }).isGloballyRoutable() == false);
    testing.expect((IpAddress{
        .V4 = IpV4Address.init(80, 9, 12, 3),
    }).isGloballyRoutable());

    testing.expect((IpAddress{
        .V6 = IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff),
    }).isGloballyRoutable());
    testing.expect((IpAddress{
        .V6 = IpV6Address.init(0, 0, 0x1c9, 0, 0, 0xafc8, 0, 0x1),
    }).isGloballyRoutable());
    testing.expect((IpAddress{
        .V6 = IpV6Address.init(0, 0, 0, 0, 0, 0, 0, 0x1),
    }).isGloballyRoutable() == false);
}

test "IpAddress.equals()" {
    testing.expect((IpAddress{
        .V4 = IpV4Address.init(127, 0, 0, 1),
    }).equals(IpAddress{ .V4 = IpV4Address.Localhost }));

    testing.expect((IpAddress{
        .V6 = IpV6Address.init(0, 0, 0, 0, 0, 0, 0, 1),
    }).equals(IpAddress{ .V6 = IpV6Address.Localhost }));

    testing.expect((IpAddress{
        .V6 = IpV6Address.init(0, 0, 0, 0, 0, 0, 0, 1),
    }).equals(IpAddress{ .V4 = IpV4Address.init(127, 0, 0, 1) }) == false);
}

fn testFormatIpAddress(address: IpAddress, expected: []const u8) !void {
    var buffer: [1024]u8 = undefined;
    const buf = buffer[0..];

    const result = try fmt.bufPrint(buf, "{}", address);

    testing.expectEqualSlices(u8, result, expected);
}

test "IpAddress.format()" {
    try testFormatIpAddress(IpAddress{
        .V4 = IpV4Address.init(192, 168, 0, 1),
    }, "192.168.0.1");
    try testFormatIpAddress(IpAddress{
        .V6 = IpV6Address.init(0x2001, 0xdb8, 0x85a3, 0x8d3, 0x1319, 0x8a2e, 0x370, 0x7348),
    }, "2001:db8:85a3:8d3:1319:8a2e:370:7348");
}

fn testIpParseError(addr: []const u8, expected_error: ParseError) void {
    testing.expectError(expected_error, IpAddress.parse(addr));
}

test "IpAddress.parse()" {
    const parsed = try IpAddress.parse("127.0.0.1");
    testing.expect(parsed.equals(IpAddress{
        .V4 = IpV4Address.Localhost,
    }));

    testIpParseError("256.0.0.1", ParseError.Overflow);
    testIpParseError("x.0.0.1", ParseError.InvalidCharacter);
    testIpParseError("127.0.0.1.1", ParseError.TooManyOctets);
    testIpParseError("127.0.0.", ParseError.Incomplete);
    testIpParseError("100..0.1", ParseError.InvalidCharacter);
}

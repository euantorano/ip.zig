const std = @import("std");
const mem = std.mem;
const fmt = std.fmt;
const testing = std.testing;

use @import("ip");

test "IpV4Address.from_slice()" {
    var array = []u8{ 127, 0, 0, 1 };
    const ip = IpV4Address.from_slice(&array);

    testing.expect(IpV4Address.Localhost.equals(ip));
}

test "IpV4Address.from_array()" {
    var array = []u8{ 127, 0, 0, 1 };
    const ip = IpV4Address.from_array(array);

    testing.expect(IpV4Address.Localhost.equals(ip));
}

test "IpV4Address.octets()" {
    testing.expectEqual([]u8{ 127, 0, 0, 1 }, IpV4Address.init(127, 0, 0, 1).octets());
}

test "IpV4Address.is_unspecified()" {
    testing.expect(IpV4Address.init(0, 0, 0, 0).is_unspecified());
    testing.expect(IpV4Address.init(192, 168, 0, 1).is_unspecified() == false);
}

test "IpV4Address.is_loopback()" {
    testing.expect(IpV4Address.init(127, 0, 0, 1).is_loopback());
    testing.expect(IpV4Address.init(192, 168, 0, 1).is_loopback() == false);
}

test "IpV4Address.is_private()" {
    testing.expect(IpV4Address.init(10, 0, 0, 1).is_private());
    testing.expect(IpV4Address.init(10, 10, 10, 10).is_private());
    testing.expect(IpV4Address.init(172, 16, 10, 10).is_private());
    testing.expect(IpV4Address.init(172, 29, 45, 14).is_private());
    testing.expect(IpV4Address.init(172, 32, 0, 2).is_private() == false);
    testing.expect(IpV4Address.init(192, 168, 0, 2).is_private());
    testing.expect(IpV4Address.init(192, 169, 0, 2).is_private() == false);
}

test "IpV4Address.is_link_local()" {
    testing.expect(IpV4Address.init(169, 254, 0, 0).is_link_local());
    testing.expect(IpV4Address.init(169, 254, 10, 65).is_link_local());
    testing.expect(IpV4Address.init(16, 89, 10, 65).is_link_local() == false);
}

test "IpV4Address.is_multicast()" {
    testing.expect(IpV4Address.init(224, 254, 0, 0).is_multicast());
    testing.expect(IpV4Address.init(236, 168, 10, 65).is_multicast());
    testing.expect(IpV4Address.init(172, 16, 10, 65).is_multicast() == false);
}

test "IpV4Address.is_broadcast()" {
    testing.expect(IpV4Address.init(255, 255, 255, 255).is_broadcast());
    testing.expect(IpV4Address.init(236, 168, 10, 65).is_broadcast() == false);
}

test "IpV4Address.is_documentation()" {
    testing.expect(IpV4Address.init(192, 0, 2, 255).is_documentation());
    testing.expect(IpV4Address.init(198, 51, 100, 65).is_documentation());
    testing.expect(IpV4Address.init(203, 0, 113, 6).is_documentation());
    testing.expect(IpV4Address.init(193, 34, 17, 19).is_documentation() == false);
}

test "IpV4Address.is_globally_routable()" {
    testing.expect(IpV4Address.init(10, 254, 0, 0).is_globally_routable() == false);
    testing.expect(IpV4Address.init(192, 168, 10, 65).is_globally_routable() == false);
    testing.expect(IpV4Address.init(172, 16, 10, 65).is_globally_routable() == false);
    testing.expect(IpV4Address.init(0, 0, 0, 0).is_globally_routable() == false);
    testing.expect(IpV4Address.init(80, 9, 12, 3).is_globally_routable());
}

test "IpV4Address.equals()" {
    testing.expect(IpV4Address.init(10, 254, 0, 0).equals(IpV4Address.init(127, 0, 0, 1)) == false);
    testing.expect(IpV4Address.init(127, 0, 0, 1).equals(IpV4Address.Localhost));
}

test "IpV4Address.to_host_byte_order()" {
    var expected: u32 = 0x0d0c0b0a;

    testing.expectEqual(expected, IpV4Address.init(13, 12, 11, 10).to_host_byte_order());
}

test "IpV4Address.from_host_byte_order()" {
    testing.expect(IpV4Address.from_host_byte_order(0x0d0c0b0a).equals(IpV4Address.init(13, 12, 11, 10)));
}

test "IpV4Address.format()" {
    var buffer: [11]u8 = undefined;
    const buf = buffer[0..];

    const addr = IpV4Address.init(13, 12, 11, 10);

    const result = try fmt.bufPrint(buf, "{}", addr);

    const expected: []const u8 = "13.12.11.10";

    testing.expectEqualSlices(u8, expected, result);
}

fn testIpV4ParseError(addr: []const u8, expected_error: ParseError) void {
    testing.expectError(expected_error, IpV4Address.parse(addr));
}

fn testIpV4Format(addr: IpV4Address, expected: []const u8) !void {
    var buffer: [15]u8 = undefined;
    const buf = buffer[0..];

    const result = try fmt.bufPrint(buf, "{}", addr);

    testing.expectEqualSlices(u8, expected, result);
}

test "IpV4Address.parse()" {
    const parsed = try IpV4Address.parse("127.0.0.1");
    testing.expect(parsed.equals(IpV4Address.Localhost));

    const mask_parsed = try IpV4Address.parse("255.255.255.0");
    try testIpV4Format(mask_parsed, "255.255.255.0");

    testIpV4ParseError("256.0.0.1", ParseError.Overflow);
    testIpV4ParseError("x.0.0.1", ParseError.InvalidCharacter);
    testIpV4ParseError("127.0.0.1.1", ParseError.TooManyOctets);
    testIpV4ParseError("127.0.0.", ParseError.Incomplete);
    testIpV4ParseError("100..0.1", ParseError.InvalidCharacter);
}

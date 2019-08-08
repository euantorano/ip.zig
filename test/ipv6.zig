const std = @import("std");
const mem = std.mem;
const fmt = std.fmt;
const testing = std.testing;

use @import("ip");

test "IpV6Address.segments()" {
    testing.expectEqual([8]u16{ 0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff }, IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).segments());
}

test "IpV6Address.octets()" {
    const expected = [16]u8{
        0,    0,    0,    0,    0,    0,    0, 0, 0, 0,
        0xff, 0xff, 0xc0, 0x0a, 0x02, 0xff,
    };
    const ip = IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff);

    testing.expectEqual(expected, ip.octets());
}

test "IpV6Address.fromSlice()" {
    var arr = [16]u8{
        0,    0,    0,    0,    0,    0,    0, 0, 0, 0,
        0xff, 0xff, 0xc0, 0x0a, 0x02, 0xff,
    };
    const ip = IpV6Address.fromSlice(&arr);

    testing.expectEqual([8]u16{ 0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff }, ip.segments());
}

test "IpV6Address.isUnspecified()" {
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0, 0, 0).isUnspecified());
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).isUnspecified() == false);
}

test "IpV6Address.isLoopback()" {
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0, 0, 0x1).isLoopback());
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).isLoopback() == false);
}

test "IpV6Address.isMulticast()" {
    testing.expect(IpV6Address.init(0xff00, 0, 0, 0, 0, 0, 0, 0).isMulticast());
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).isMulticast() == false);
}

test "IpV6Address.isDocumentation()" {
    testing.expect(IpV6Address.init(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0).isDocumentation());
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).isDocumentation() == false);
}

test "IpV6Address.isMulticastLinkLocal()" {
    var arr = [_]u8{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02 };

    testing.expect(IpV6Address.fromSlice(&arr).isMulticastLinkLocal());
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).isMulticastLinkLocal() == false);
}

test "IpV6Address.isUnicastSiteLocal()" {
    testing.expect(IpV6Address.init(0xfec2, 0, 0, 0, 0, 0, 0, 0).isUnicastSiteLocal());
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).isUnicastSiteLocal() == false);
}

test "IpV6Address.isUnicastLinkLocal()" {
    testing.expect(IpV6Address.init(0xfe8a, 0, 0, 0, 0, 0, 0, 0).isUnicastLinkLocal());
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).isUnicastLinkLocal() == false);
}

test "IpV6Address.isUniqueLocal()" {
    testing.expect(IpV6Address.init(0xfc02, 0, 0, 0, 0, 0, 0, 0).isUniqueLocal());
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).isUniqueLocal() == false);
}

test "IpV6Address.multicastScope()" {
    const scope = IpV6Address.init(0xff0e, 0, 0, 0, 0, 0, 0, 0).multicastScope() orelse unreachable;

    testing.expect(scope == Ipv6MulticastScope.Global);
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).multicastScope() == null);
}

test "IpV6Address.isGloballyRoutable()" {
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).isGloballyRoutable());
    testing.expect(IpV6Address.init(0, 0, 0x1c9, 0, 0, 0xafc8, 0, 0x1).isGloballyRoutable());
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0, 0, 0x1).isGloballyRoutable() == false);
}

test "IpV6Address.isUnicastGlobal()" {
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).isUnicastGlobal());
    testing.expect(IpV6Address.init(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0).isUnicastGlobal() == false);
}

test "IpV6Address.toIpv4()" {
    const firstAddress = IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).toIpv4() orelse unreachable;
    const secondAddress = IpV6Address.init(0, 0, 0, 0, 0, 0, 0, 1).toIpv4() orelse unreachable;

    testing.expect(firstAddress.equals(IpV4Address.init(192, 10, 2, 255)));
    testing.expect(secondAddress.equals(IpV4Address.init(0, 0, 0, 1)));
    testing.expect(IpV6Address.init(0xff00, 0, 0, 0, 0, 0, 0, 0).toIpv4() == null);
}

test "IpV6Address.equals()" {
    testing.expect(IpV6Address.init(0, 0, 0, 0, 0, 0, 0, 1).equals(IpV6Address.Localhost));
}

test "IpV6Address.toHostByteOrder()" {
    const addr = IpV6Address.init(0x1020, 0x3040, 0x5060, 0x7080, 0x90A0, 0xB0C0, 0xD0E0, 0xF00D);
    const expected: u128 = 0x102030405060708090A0B0C0D0E0F00D;

    testing.expectEqual(expected, addr.toHostByteOrder());
}

test "IpV6Address.fromHostByteOrder()" {
    const a: u128 = 0x102030405060708090A0B0C0D0E0F00D;
    const addr = IpV6Address.fromHostByteOrder(a);

    testing.expect(addr.equals(IpV6Address.init(0x1020, 0x3040, 0x5060, 0x7080, 0x90A0, 0xB0C0, 0xD0E0, 0xF00D)));
}

fn testFormatIpv6Address(address: IpV6Address, expected: []const u8) !void {
    var buffer: [1024]u8 = undefined;
    const buf = buffer[0..];

    const result = try fmt.bufPrint(buf, "{}", address);

    testing.expectEqualSlices(u8, expected, result);
}

test "IpV6Address.format()" {
    try testFormatIpv6Address(IpV6Address.Unspecified, "::");
    try testFormatIpv6Address(IpV6Address.Localhost, "::1");
    try testFormatIpv6Address(IpV6Address.init(0, 0, 0, 0, 0, 0x00, 0xc00a, 0x2ff), "::192.10.2.255");
    try testFormatIpv6Address(IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff), "::ffff:192.10.2.255");
    try testFormatIpv6Address(IpV6Address.init(0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334), "2001:db8:85a3::8a2e:370:7334");
    try testFormatIpv6Address(IpV6Address.init(0x2001, 0xdb8, 0x85a3, 0x8d3, 0x1319, 0x8a2e, 0x370, 0x7348), "2001:db8:85a3:8d3:1319:8a2e:370:7348");
    try testFormatIpv6Address(IpV6Address.init(0x001, 0, 0, 0, 0, 0, 0, 0), "1::");

    var scope_id = "eth2";

    var ipWithScopeId = IpV6Address.init(0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334);
    ipWithScopeId.scope_id = scope_id[0..];

    try testFormatIpv6Address(ipWithScopeId, "2001:db8:85a3::8a2e:370:7334%eth2");
}

fn testIpV6ParseAndBack(addr: []const u8, expectedIp: IpV6Address) !void {
    const parsed = try IpV6Address.parse(addr);
    try testFormatIpv6Address(parsed, addr);

    testing.expect(parsed.equals(expectedIp));
}

// test "IpV6Address.parse()" {
//     try testIpV6ParseAndBack("::", IpV6Address.Unspecified);
//     try testIpV6ParseAndBack("::1", IpV6Address.Localhost);
//     try testIpV6ParseAndBack("2001:db8:85a3::8a2e:370:7334", IpV6Address.init(0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334));
//     try testIpV6ParseAndBack("2001:db8:85a3:8d3:1319:8a2e:370:7348", IpV6Address.init(0x2001, 0xdb8, 0x85a3, 0x8d3, 0x1319, 0x8a2e, 0x370, 0x7348));
// }

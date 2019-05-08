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

test "IpV6Address.from_slice()" {
    var arr = [16]u8{
        0,    0,    0,    0,    0,    0,    0, 0, 0, 0,
        0xff, 0xff, 0xc0, 0x0a, 0x02, 0xff,
    };
    const ip = IpV6Address.from_slice(&arr);

    testing.expectEqual([8]u16{ 0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff }, ip.segments());
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
    var arr = []u8{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02 };

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

    testing.expect(firstAddress.equals(IpV4Address.init(192, 10, 2, 255)));
    testing.expect(secondAddress.equals(IpV4Address.init(0, 0, 0, 1)));
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
    try test_format_ipv6_address(IpV6Address.Unspecified, "::");
    try test_format_ipv6_address(IpV6Address.Localhost, "::1");
    try test_format_ipv6_address(IpV6Address.init(0, 0, 0, 0, 0, 0x00, 0xc00a, 0x2ff), "::192.10.2.255");
    try test_format_ipv6_address(IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff), "::ffff:192.10.2.255");
    try test_format_ipv6_address(IpV6Address.init(0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334), "2001:db8:85a3::8a2e:370:7334");
    try test_format_ipv6_address(IpV6Address.init(0x2001, 0xdb8, 0x85a3, 0x8d3, 0x1319, 0x8a2e, 0x370, 0x7348), "2001:db8:85a3:8d3:1319:8a2e:370:7348");
    try test_format_ipv6_address(IpV6Address.init(0x001, 0, 0, 0, 0, 0, 0, 0), "1::");

    var scope_id = "eth2";

    var ipWithScopeId = IpV6Address.init(0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334);
    ipWithScopeId.scope_id = scope_id[0..];

    try test_format_ipv6_address(ipWithScopeId, "2001:db8:85a3::8a2e:370:7334%eth2");
}

fn testIpV6ParseError(addr: []const u8, expected_error: ParseError) void {
    if (IpV6Address.parse(addr)) |_| {
        @panic("parse success, expected failure");
    } else |e| {
        testing.expect(e == expected_error);
    }
}

fn testIpV6Format(addr: IpV6Address, expected: []const u8) !void {
    var buffer: [1024]u8 = undefined;
    const buf = buffer[0..];

    const result = try fmt.bufPrint(buf, "{}", addr);

    std.debug.warn("res: {}", result);

    testing.expect(mem.eql(u8, result, expected));
}

// test "IpV4Address.parse()" {
//     const parsed = try IpV6Address.parse("::1");
//     try testIpV6Format(parsed, "::1");
//     testing.expect(parsed.equals(IpV6Address.Localhost));
// }

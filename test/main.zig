const std = @import("std");
const mem = std.mem;
const fmt = std.fmt;
const testing = std.testing;

const i = @import("ip");
const IpV6Address = i.IpV6Address;
const IpV4Address = i.IpV4Address;
const IpAddress = i.IpAddress;

test "" {
    _ = @import("./ipv4.zig");
    _ = @import("./ipv6.zig");
}

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

test "IpAddress.is_unspecified()" {
    testing.expect(
        (IpAddress{
            .V4 = IpV4Address.init(0, 0, 0, 0),
        }).is_unspecified() == true
    );
    testing.expect(
        (IpAddress{
            .V4 = IpV4Address.init(192, 168, 0, 1),
        }).is_unspecified() == false
    );

    testing.expect(
        (IpAddress{
            .V6 = IpV6Address.init(0, 0, 0, 0, 0, 0, 0, 0),
        }).is_unspecified() == true
    );
    testing.expect(
        (IpAddress{
            .V6 = IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff),
        }).is_unspecified() == false
    );
}

test "IpAddress.is_loopback()" {
    testing.expect(
        (IpAddress{
            .V4 = IpV4Address.init(127, 0, 0, 1),
        }).is_loopback() == true
    );
    testing.expect(
        (IpAddress{
            .V4 = IpV4Address.init(192, 168, 0, 1),
        }).is_loopback() == false
    );

    testing.expect(
        (IpAddress{
            .V6 = IpV6Address.init(0, 0, 0, 0, 0, 0, 0, 0x1),
        }).is_loopback() == true
    );
    testing.expect(
        (IpAddress{
            .V6 = IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff),
        }).is_loopback() == false
    );
}

test "IpAddress.is_multicast()" {
    testing.expect(
        (IpAddress{
            .V4 = IpV4Address.init(236, 168, 10, 65),
        }).is_multicast() == true
    );
    testing.expect(
        (IpAddress{
            .V4 = IpV4Address.init(172, 16, 10, 65),
        }).is_multicast() == false
    );

    testing.expect(
        (IpAddress{
            .V6 = IpV6Address.init(0xff00, 0, 0, 0, 0, 0, 0, 0),
        }).is_multicast() == true
    );
    testing.expect(
        (IpAddress{
            .V6 = IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff),
        }).is_multicast() == false
    );
}

test "IpAddress.is_documentation()" {
    testing.expect(
        (IpAddress{
            .V4 = IpV4Address.init(203, 0, 113, 6),
        }).is_documentation() == true
    );
    testing.expect(
        (IpAddress{
            .V4 = IpV4Address.init(193, 34, 17, 19),
        }).is_documentation() == false
    );

    testing.expect(
        (IpAddress{
            .V6 = IpV6Address.init(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
        }).is_documentation() == true
    );
    testing.expect(
        (IpAddress{
            .V6 = IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff),
        }).is_documentation() == false
    );
}

test "IpAddress.is_globally_routable()" {
    testing.expect(
        (IpAddress{
            .V4 = IpV4Address.init(10, 254, 0, 0),
        }).is_globally_routable() == false
    );
    testing.expect(
        (IpAddress{
            .V4 = IpV4Address.init(80, 9, 12, 3),
        }).is_globally_routable() == true
    );

    testing.expect(
        (IpAddress{
            .V6 = IpV6Address.init(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff),
        }).is_globally_routable() == true
    );
    testing.expect(
        (IpAddress{
            .V6 = IpV6Address.init(0, 0, 0x1c9, 0, 0, 0xafc8, 0, 0x1),
        }).is_globally_routable() == true
    );
    testing.expect(
        (IpAddress{
            .V6 = IpV6Address.init(0, 0, 0, 0, 0, 0, 0, 0x1),
        }).is_globally_routable() == false
    );
}

test "IpAddress.equals()" {
    testing.expect(
        (IpAddress{
            .V4 = IpV4Address.init(127, 0, 0, 1),
        }).equals(
            IpAddress{
                .V4 = IpV4Address.Localhost
            }
        ) == true
    );

    testing.expect(
        (IpAddress{
            .V6 = IpV6Address.init(0, 0, 0, 0, 0, 0, 0, 1),
        }).equals(
            IpAddress{
                .V6 = IpV6Address.Localhost
            }
        ) == true
    );

    testing.expect(
        (IpAddress{
            .V6 = IpV6Address.init(0, 0, 0, 0, 0, 0, 0, 1),
        }).equals(
            IpAddress{
                .V4 = IpV4Address.init(127, 0, 0, 1)
            }
        ) == false
    );
}

fn test_format_ip_address(address: IpAddress, expected: []const u8) !void {
    var buffer: [1024]u8 = undefined;
    const buf = buffer[0..];

    const result = try fmt.bufPrint(buf, "{}", address);

    testing.expect(mem.eql(u8, result, expected));
}

test "IpAddress.format()" {
    try test_format_ip_address(
        IpAddress{
            .V4 = IpV4Address.init(192, 168, 0, 1),
        },
        "192.168.0.1"
    );        
    try test_format_ip_address(
        IpAddress{
            .V6 = IpV6Address.init(0x2001, 0xdb8, 0x85a3, 0x8d3, 0x1319, 0x8a2e, 0x370, 0x7348),
        },
        "2001:db8:85a3:8d3:1319:8a2e:370:7348"
    );
}

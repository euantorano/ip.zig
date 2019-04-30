const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();

    const lib = b.addStaticLibrary("ip", "src/main.zig");
    lib.setBuildMode(mode);

    var main_tests = b.addTest("test/main.zig");
    main_tests.setBuildMode(mode);
    main_tests.addPackagePath("ip", "src/main.zig");

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);

    b.default_step.dependOn(&lib.step);
    b.installArtifact(lib);
}

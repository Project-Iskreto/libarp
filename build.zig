const std = @import("std");

fn setupImports(
    root: *std.Build.Module,
    header: *std.Build.Module,
    checksum: *std.Build.Module,
    packer: *std.Build.Module,
    unpacker: *std.Build.Module,
    verifier: *std.Build.Module,
    signature: *std.Build.Module,
) void {
    root.addImport("header", header);
    root.addImport("checksum", checksum);
    root.addImport("packer", packer);
    root.addImport("unpacker", unpacker);
    root.addImport("verifier", verifier);
    root.addImport("signature", signature);
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const header = b.createModule(.{
        .root_source_file = b.path("src/header.zig"),
    });
    const checksum = b.createModule(.{
        .root_source_file = b.path("src/checksum.zig"),
        .target = target,
        .optimize = optimize,
    });
    const packer = b.createModule(.{
        .root_source_file = b.path("src/packer.zig"),
    });
    const unpacker = b.createModule(.{
        .root_source_file = b.path("src/unpacker.zig"),
    });
    const verifier = b.createModule(.{
        .root_source_file = b.path("src/verifier.zig"),
        .target = target,
        .optimize = optimize,
    });
    const signature = b.createModule(.{
        .root_source_file = b.path("src/signature.zig"),
        .target = target,
        .optimize = optimize,
    });
    packer.addImport("header", header);
    packer.addImport("checksum", checksum);
    unpacker.addImport("header", header);
    unpacker.addImport("verifier", verifier);
    unpacker.addImport("checksum", checksum);
    verifier.addImport("header", header);
    signature.addImport("header", header);

    const libarp_mod = b.addModule("libarp", .{
        .root_source_file = b.path("src/libarp.zig"),
        .target = target,
    });
    setupImports(libarp_mod, header, checksum, packer, unpacker, verifier, signature);

    const cabi_mod = b.createModule(.{
        .root_source_file = b.path("src/cabi.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    cabi_mod.addImport("header", header);
    cabi_mod.addImport("checksum", checksum);
    cabi_mod.addImport("signature", signature);
    cabi_mod.addImport("packer", packer);
    cabi_mod.addImport("unpacker", unpacker);

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/libarp.zig"),
        .target = target,
        .optimize = optimize,
    });
    setupImports(lib_mod, header, checksum, packer, unpacker, verifier, signature);

    const static_lib = b.addLibrary(.{
        .name = "arp",
        .root_module = cabi_mod,
    });
    b.installArtifact(static_lib);

    const want_shared = b.option(bool, "shared", "Also build a shared library (.dll/.so/.dylib)") orelse false;
    if (want_shared) {
        const shared = b.addLibrary(.{
            .name = "arp",
            .linkage = .dynamic,
            .root_module = cabi_mod,
        });
        b.installArtifact(shared);
    }

    const lib_tests = b.addTest(.{ .root_module = lib_mod });
    const run_lib_tests = b.addRunArtifact(lib_tests);
    const cabi_tests = b.addTest(.{ .root_module = cabi_mod });
    const run_cabi_tests = b.addRunArtifact(cabi_tests);
    const verifier_tests = b.addTest(.{ .root_module = verifier });
    const run_verifier_tests = b.addRunArtifact(verifier_tests);
    const test_step = b.step("test", "Run libarp tests");
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_cabi_tests.step);
    test_step.dependOn(&run_verifier_tests.step);
}

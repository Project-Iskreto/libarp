const std = @import("std");
const header = @import("header");

pub fn verifyFormat(h: header.Header) !void {
    return h.validateFormat();
}

fn baseHeader() header.Header {
    return .{
        .version = 1,
        .info_size = 0,
        .data_offset = header.HeaderSize,
        .hooks_offset = 0,
        .sig_offset = 0,
        .sig_size = 0,
        .checksum = [_]u8{0} ** 8,
        .reserved = [_]u8{0} ** 18,
    };
}

test "verifyFormat accepts valid v1 header" {
    try verifyFormat(baseHeader());
}

test "verifyFormat rejects non-v1 version" {
    var h = baseHeader();
    h.version = 2;
    try std.testing.expectError(error.UnsupportedVersion, verifyFormat(h));
}

test "verifyFormat rejects nonzero reserved" {
    var h = baseHeader();
    h.reserved[0] = 1;
    try std.testing.expectError(error.ReservedNonZero, verifyFormat(h));
}

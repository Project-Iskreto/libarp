const std = @import("std");
pub const header = @import("header");
pub const checksum = @import("checksum");
pub const verifier = @import("verifier");
pub const signature = @import("signature");
pub const packer = @import("packer");
pub const unpacker = @import("unpacker");

pub const OpenResult = struct {
    header: header.Header,
    info: []const u8,
    data: []const u8,
    signature: ?[]const u8,
};

pub fn open(bytes: []const u8) !OpenResult {
    const h = try header.parseChecked(bytes, bytes.len);
    const info = bytes[header.HeaderSize .. header.HeaderSize + h.info_size];
    const start: usize = @intCast(h.data_offset);
    if (h.sig_size == 0) {
        return .{ .header = h, .info = info, .data = bytes[start..], .signature = null };
    }
    const so: usize = @intCast(h.sig_offset);
    return .{
        .header = h,
        .info = info,
        .data = bytes[start..so],
        .signature = bytes[so .. so + header.SignatureSize],
    };
}

test "packer.write writes header, info and data in order" {
    const info = "name = \"demo\"\n";
    const data = "compressed-bytes";
    const total = 64 + info.len + data.len;

    const buf = try std.testing.allocator.alloc(u8, total);
    defer std.testing.allocator.free(buf);

    var w = std.Io.Writer.fixed(buf);

    const h = try packer.write(&w, info, data, .{});

    try std.testing.expectEqual(@as(u32, @intCast(info.len)), h.info_size);
    try std.testing.expectEqual(@as(u64, @intCast(64 + info.len)), h.data_offset);
    try std.testing.expectEqual(@as(usize, total), w.end);
    try std.testing.expectEqualSlices(u8, &header.Magic, buf[0..4]);
    try std.testing.expectEqualSlices(u8, info, buf[64 .. 64 + info.len]);
    try std.testing.expectEqualSlices(u8, data, buf[64 + info.len ..]);
}

test "packer/unpacker roundtrip" {
    const info = "name = \"demo\"\n";
    const data = "payload-bytes";
    const total = 64 + info.len + data.len;

    const bytes_packed = try std.testing.allocator.alloc(u8, total);
    defer std.testing.allocator.free(bytes_packed);

    var w1 = std.Io.Writer.fixed(bytes_packed);
    _ = try packer.write(&w1, info, data, .{});

    const data_out = try std.testing.allocator.alloc(u8, data.len);
    defer std.testing.allocator.free(data_out);

    var r2 = std.Io.Reader.fixed(bytes_packed[0..w1.end]);
    var w2 = std.Io.Writer.fixed(data_out);
    const res = try unpacker.read(std.testing.allocator, &w2, &r2);
    defer std.testing.allocator.free(res.info);

    try std.testing.expectEqual(@as(u32, @intCast(info.len)), res.header.info_size);
    try std.testing.expectEqualSlices(u8, info, res.info);
    try std.testing.expectEqual(@as(usize, data.len), w2.end);
    try std.testing.expectEqualSlices(u8, data, data_out);
}

test "unpacker rejects bad magic" {
    const garbage = [_]u8{'X'} ** 64;
    var r = std.Io.Reader.fixed(&garbage);
    var empty: [0]u8 = .{};
    var w = std.Io.Writer.fixed(&empty);
    try std.testing.expectError(error.BadMagic, unpacker.read(std.testing.allocator, &w, &r));
}

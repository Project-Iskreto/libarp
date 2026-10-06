const std = @import("std");
const header = @import("header");
const verifier = @import("verifier");
const checksum = @import("checksum");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const UnpackResult = struct {
    header: header.Header,
    info: []u8,
};

pub fn read(
    allocator: std.mem.Allocator,
    w: *std.Io.Writer,
    r: *std.Io.Reader,
) !UnpackResult {
    var header_bytes: [header.HeaderSize]u8 = undefined;
    try r.readSliceAll(&header_bytes);
    const h = try header.Header.parse(header_bytes);
    try verifier.verifyFormat(h);

    const info = try allocator.alloc(u8, h.info_size);
    errdefer allocator.free(info);
    try r.readSliceAll(info);

    var sha = Sha256.init(.{});
    sha.update(info);

    const data_len: ?u64 = if (h.hooks_offset != 0)
        h.hooks_offset - h.data_offset
    else if (h.sig_size != 0)
        h.sig_offset - h.data_offset
    else
        null;
    try consume(r, w, &sha, data_len);

    if (h.hooks_offset != 0) {
        const hooks_len: ?u64 = if (h.sig_size != 0) h.sig_offset - h.hooks_offset else null;
        try consume(r, null, &sha, hooks_len);
    }

    if (!checksum.isZero(h.checksum)) {
        const got = sha.finalResult();
        if (!std.mem.eql(u8, &h.checksum, got[0..8])) return error.BadChecksum;
    }

    return .{ .header = h, .info = info };
}

fn consume(r: *std.Io.Reader, w: ?*std.Io.Writer, sha: *Sha256, len: ?u64) !void {
    var buf: [64 * 1024]u8 = undefined;
    if (len) |n| {
        var remaining = n;
        while (remaining > 0) {
            const chunk: usize = @intCast(@min(remaining, buf.len));
            try r.readSliceAll(buf[0..chunk]);
            sha.update(buf[0..chunk]);
            if (w) |ww| try ww.writeAll(buf[0..chunk]);
            remaining -= chunk;
        }
    } else {
        while (true) {
            const n = try r.readSliceShort(buf[0..]);
            if (n == 0) break;
            sha.update(buf[0..n]);
            if (w) |ww| try ww.writeAll(buf[0..n]);
        }
    }
}

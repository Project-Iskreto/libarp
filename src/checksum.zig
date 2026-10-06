const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub fn computeFull(info: []const u8, data: []const u8, hooks: []const u8) [32]u8 {
    var s = Sha256.init(.{});
    s.update(info);
    s.update(data);
    s.update(hooks);
    return s.finalResult();
}

pub fn compute(info: []const u8, data: []const u8, hooks: []const u8) [8]u8 {
    return computeFull(info, data, hooks)[0..8].*;
}

pub fn isZero(sum: [8]u8) bool {
    for (sum) |b| {
        if (b != 0) return false;
    }
    return true;
}

pub fn matches(stored: [8]u8, info: []const u8, data: []const u8, hooks: []const u8) bool {
    if (isZero(stored)) return true;
    const got = compute(info, data, hooks);
    return std.mem.eql(u8, &stored, &got);
}

const std = @import("std");
const header = @import("header");
const checksum = @import("checksum");

const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Magic = [4]u8{ 'A', 'R', 'P', 'S' };

pub const VerifyStatus = enum { unsigned, invalid, valid };

pub const VerifyResult = struct {
    status: VerifyStatus,
    key_id: ?[8]u8 = null,
};

pub const Blob = struct {
    key_id: [8]u8,
    pubkey: [32]u8,
    signature: [64]u8,
};

pub fn keyId(pubkey: [32]u8) [8]u8 {
    var full: [32]u8 = undefined;
    Sha256.hash(&pubkey, &full, .{});
    return full[0..8].*;
}

pub fn publicKey(seed: [32]u8) ![32]u8 {
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    return kp.public_key.toBytes();
}

pub fn parse(bytes: []const u8) !Blob {
    if (bytes.len < header.SignatureSize) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..4], &Magic)) return error.BadSignature;
    if (bytes[4] != 1) return error.BadSignature;

    var blob: Blob = undefined;
    @memcpy(&blob.key_id, bytes[5..13]);
    @memcpy(&blob.pubkey, bytes[13..45]);
    @memcpy(&blob.signature, bytes[45..109]);

    if (!std.mem.eql(u8, &blob.key_id, &keyId(blob.pubkey))) {
        return error.BadSignature;
    }
    return blob;
}

pub fn verifyBlob(blob: []const u8, message: []const u8) VerifyResult {
    var v = switch (beginStream(blob)) {
        .status => |st| return .{ .status = st },
        .ready => |sv| sv,
    };
    v.update(message);
    return v.finish();
}

pub const StreamVerifier = struct {
    inner: Ed25519.Verifier,
    key_id: [8]u8,

    pub fn update(self: *StreamVerifier, bytes: []const u8) void {
        self.inner.update(bytes);
    }

    pub fn finish(self: *StreamVerifier) VerifyResult {
        self.inner.verify() catch return .{ .status = .invalid };
        return .{ .status = .valid, .key_id = self.key_id };
    }
};

pub const StreamStart = union(enum) {
    status: VerifyStatus,
    ready: StreamVerifier,
};

pub fn beginStream(blob: []const u8) StreamStart {
    const parsed = parse(blob) catch return .{ .status = .invalid };
    const pk = Ed25519.PublicKey.fromBytes(parsed.pubkey) catch
        return .{ .status = .invalid };
    const inner = Ed25519.Signature.fromBytes(parsed.signature).verifier(pk) catch
        return .{ .status = .invalid };
    return .{ .ready = .{ .inner = inner, .key_id = parsed.key_id } };
}

pub fn verifyStream(r: *std.Io.Reader, blob: []const u8, len: u64) VerifyResult {
    var v = switch (beginStream(blob)) {
        .status => |st| return .{ .status = st },
        .ready => |sv| sv,
    };
    var buf: [64 * 1024]u8 = undefined;
    var remaining = len;
    while (remaining > 0) {
        const want: usize = @intCast(@min(remaining, buf.len));
        r.readSliceAll(buf[0..want]) catch return .{ .status = .invalid };
        v.update(buf[0..want]);
        remaining -= want;
    }
    return v.finish();
}

pub fn verify(file: []const u8) VerifyResult {
    const h = header.parseChecked(file, file.len) catch return .{ .status = .invalid };
    if (h.sig_size == 0) return .{ .status = .unsigned };

    const start: usize = @intCast(h.sig_offset);
    return verifyBlob(file[start .. start + header.SignatureSize], file[0..start]);
}

pub fn verifyDetached(blob: []const u8, data: []const u8) VerifyResult {
    return verifyBlob(blob, data);
}

pub fn signBlob(seed: [32]u8, message: []const u8) ![header.SignatureSize]u8 {
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    const sig = try kp.sign(message, null);
    const pubkey = kp.public_key.toBytes();
    const kid = keyId(pubkey);
    const sig_bytes = sig.toBytes();

    var blob: [header.SignatureSize]u8 = undefined;
    @memcpy(blob[0..4], &Magic);
    blob[4] = 1;
    @memcpy(blob[5..13], &kid);
    @memcpy(blob[13..45], &pubkey);
    @memcpy(blob[45..109], &sig_bytes);
    return blob;
}

pub fn sign(allocator: std.mem.Allocator, unsigned: []const u8, seed: [32]u8) ![]u8 {
    const h = try header.parseChecked(unsigned, unsigned.len);
    if (h.sig_size != 0) return error.AlreadySigned;

    const info = unsigned[header.HeaderSize .. header.HeaderSize + h.info_size];
    const data_off: usize = @intCast(h.data_offset);
    const data_end: usize = if (h.hooks_offset != 0) @intCast(h.hooks_offset) else unsigned.len;
    const data = unsigned[data_off..data_end];
    const hooks = if (h.hooks_offset != 0) unsigned[data_end..unsigned.len] else unsigned[0..0];

    const out = try allocator.alloc(u8, unsigned.len + header.SignatureSize);
    errdefer allocator.free(out);

    const nh = header.Header{
        .version = h.version,
        .info_size = h.info_size,
        .data_offset = h.data_offset,
        .hooks_offset = h.hooks_offset,
        .sig_offset = unsigned.len,
        .sig_size = header.SignatureSize,
        .checksum = checksum.compute(info, data, hooks),
        .reserved = h.reserved,
    };
    const hdr_bytes = nh.serialize();
    @memcpy(out[0..header.HeaderSize], &hdr_bytes);
    @memcpy(out[header.HeaderSize..unsigned.len], unsigned[header.HeaderSize..]);

    const blob = try signBlob(seed, out[0..unsigned.len]);
    @memcpy(out[unsigned.len..], &blob);
    return out;
}

fn makeUnsigned(allocator: std.mem.Allocator, info: []const u8, data: []const u8) ![]u8 {
    const buf = try allocator.alloc(u8, header.HeaderSize + info.len + data.len);
    const h = header.Header{
        .version = 1,
        .info_size = @intCast(info.len),
        .data_offset = header.HeaderSize + info.len,
        .hooks_offset = 0,
        .sig_offset = 0,
        .sig_size = 0,
        .checksum = checksum.compute(info, data, &.{}),
        .reserved = [_]u8{0} ** 18,
    };
    const hdr_bytes = h.serialize();
    @memcpy(buf[0..header.HeaderSize], &hdr_bytes);
    @memcpy(buf[header.HeaderSize .. header.HeaderSize + info.len], info);
    @memcpy(buf[header.HeaderSize + info.len ..], data);
    return buf;
}

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
    const parsed = parse(blob) catch return .{ .status = .invalid };
    const pk = Ed25519.PublicKey.fromBytes(parsed.pubkey) catch
        return .{ .status = .invalid };
    const sig = Ed25519.Signature.fromBytes(parsed.signature);
    sig.verify(message, pk) catch return .{ .status = .invalid };
    return .{ .status = .valid, .key_id = parsed.key_id };
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

    const out = try allocator.alloc(u8, unsigned.len + header.SignatureSize);
    errdefer allocator.free(out);

    const nh = header.Header{
        .version = h.version,
        .info_size = h.info_size,
        .data_offset = h.data_offset,
        .sig_offset = unsigned.len,
        .sig_size = header.SignatureSize,
        .checksum = checksum.compute(info, unsigned[data_off..]),
        .reserved = h.reserved,
    };
    const hdr_bytes = nh.serialize();
    @memcpy(out[0..header.HeaderSize], &hdr_bytes);
    @memcpy(out[header.HeaderSize..unsigned.len], unsigned[header.HeaderSize..]);

    const blob = try signBlob(seed, out[0..unsigned.len]);
    @memcpy(out[unsigned.len..], &blob);
    return out;
}

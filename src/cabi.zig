const std = @import("std");
const header = @import("header");
const packer = @import("packer");
const unpacker = @import("unpacker");
const checksum = @import("checksum");
const signature = @import("signature");

const Sha256 = std.crypto.hash.sha2.Sha256;

const c = @cImport({
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
});

pub const Err = enum(c_int) {
    ok = 0,
    bad_arg = 1,
    info_too_large = 2,
    overflow = 3,
    buffer_too_small = 4,
    bad_magic = 5,
    bad_version = 6,
    truncated = 7,
    open_failed = 8,
    io_failed = 9,
    nonzero_reserved = 10,
    bad_checksum = 11,
    bad_signature = 12,
    unsigned = 13,
    untrusted_key = 14,
    data_offset_mismatch = 15,
    sig_size_bad = 16,
    sig_out_of_bounds = 17,
    already_signed = 18,
    unknown = 99,
};

pub const CHeader = extern struct {
    version: u16,
    info_size: u32,
    data_offset: u64,
    sig_offset: u64,
    sig_size: u32,
    checksum: [8]u8,
    reserved: [26]u8,
};

pub const CPackage = struct {
    bytes: [*]u8,
    len: usize,
    header: CHeader,
    data_off: usize,
    data_len: usize,
    sig_off: usize,
    sig_len: u32,
};

pub const CVerifyStatus = enum(c_int) {
    unsigned = 0,
    invalid = 1,
    valid = 2,
};

fn codeOf(e: anyerror) Err {
    return switch (e) {
        error.BadArg => .bad_arg,
        error.InfoTooLarge => .info_too_large,
        error.Overflow => .overflow,
        error.BufferTooSmall => .buffer_too_small,
        error.BadMagic => .bad_magic,
        error.UnsupportedVersion => .bad_version,
        error.Truncated => .truncated,
        error.OpenFailed => .open_failed,
        error.IOFailed => .io_failed,
        error.ReservedNonZero => .nonzero_reserved,
        error.DataOffsetMismatch => .data_offset_mismatch,
        error.SigSizeBad => .sig_size_bad,
        error.SigOutOfBounds => .sig_out_of_bounds,
        error.BadChecksum => .bad_checksum,
        error.BadSignature => .bad_signature,
        error.Unsigned => .unsigned,
        error.UntrustedKey => .untrusted_key,
        error.AlreadySigned => .already_signed,
        else => .unknown,
    };
}

fn computeTotal(info_len: usize, data_len: usize) !usize {
    if (info_len > std.math.maxInt(u32)) return error.InfoTooLarge;
    const data_offset: u64 = header.HeaderSize + info_len;
    const total = std.math.add(u64, data_offset, data_len) catch return error.Overflow;
    if (total > std.math.maxInt(usize)) return error.Overflow;
    return @intCast(total);
}

export fn arp_pack_size(info_len: usize, data_len: usize) usize {
    return computeTotal(info_len, data_len) catch 0;
}

export fn arp_pack_mem(
    info: ?[*]const u8,
    info_len: usize,
    data: ?[*]const u8,
    data_len: usize,
    out: ?[*]u8,
    out_cap: usize,
) Err {
    const ip = info orelse return .bad_arg;
    const dp = data orelse return .bad_arg;
    const op = out orelse return .bad_arg;
    packMemInternal(ip[0..info_len], dp[0..data_len], op[0..out_cap], true) catch |e| return codeOf(e);
    return .ok;
}

export fn arp_pack_mem_ex(
    info: ?[*]const u8,
    info_len: usize,
    data: ?[*]const u8,
    data_len: usize,
    out: ?[*]u8,
    out_cap: usize,
    opts: ?*const CPackOpts,
) Err {
    const ip = info orelse return .bad_arg;
    const dp = data orelse return .bad_arg;
    const op = out orelse return .bad_arg;
    packMemInternal(ip[0..info_len], dp[0..data_len], op[0..out_cap], optWriteChecksum(opts)) catch |e| return codeOf(e);
    return .ok;
}

fn packMemInternal(info: []const u8, data: []const u8, out: []u8, write_checksum: bool) !void {
    const total = try computeTotal(info.len, data.len);
    if (out.len < total) return error.BufferTooSmall;
    var w = std.Io.Writer.fixed(out[0..total]);
    _ = try packer.write(&w, info, data, .{ .write_checksum = write_checksum });
}

export fn arp_pack_stream(
    out_path: [*:0]const u8,
    info: ?[*]const u8,
    info_len: usize,
    data_path: [*:0]const u8,
) Err {
    const ip = info orelse return .bad_arg;
    packStreamInternal(out_path, ip[0..info_len], data_path, true) catch |e| return codeOf(e);
    return .ok;
}

pub const CPackOpts = extern struct {
    abi_version: u32,
    write_checksum: u32,
    reserved: [6]u32,
};

fn optWriteChecksum(opts: ?*const CPackOpts) bool {
    const o = opts orelse return true;
    if (o.abi_version != 1) return true;
    return o.write_checksum != 0;
}

export fn arp_pack_stream_ex(
    out_path: [*:0]const u8,
    info: ?[*]const u8,
    info_len: usize,
    data_path: [*:0]const u8,
    opts: ?*const CPackOpts,
) Err {
    const ip = info orelse return .bad_arg;
    packStreamInternal(out_path, ip[0..info_len], data_path, optWriteChecksum(opts)) catch |e| return codeOf(e);
    return .ok;
}

fn packStreamInternal(out_path: [*:0]const u8, info: []const u8, data_path: [*:0]const u8, write_checksum: bool) !void {
    if (info.len > std.math.maxInt(u32)) return error.InfoTooLarge;

    const fout = c.fopen(out_path, "wb") orelse return error.OpenFailed;
    defer _ = c.fclose(fout);

    const h = header.Header{
        .version = 1,
        .info_size = @intCast(info.len),
        .data_offset = header.HeaderSize + info.len,
        .sig_offset = 0,
        .sig_size = 0,
        .checksum = [_]u8{0} ** 8,
        .reserved = [_]u8{0} ** 26,
    };
    const hdr_bytes = h.serialize();
    if (@as(usize, @intCast(c.fwrite(&hdr_bytes, 1, hdr_bytes.len, fout))) != hdr_bytes.len)
        return error.IOFailed;
    if (info.len > 0 and @as(usize, @intCast(c.fwrite(info.ptr, 1, info.len, fout))) != info.len)
        return error.IOFailed;

    var sha = Sha256.init(.{});
    if (write_checksum) sha.update(info);

    const fin = c.fopen(data_path, "rb") orelse return error.OpenFailed;
    defer _ = c.fclose(fin);

    var buf: [64 * 1024]u8 = undefined;
    while (true) {
        const n: usize = @intCast(c.fread(&buf, 1, buf.len, fin));
        if (n == 0) {
            if (c.ferror(fin) != 0) return error.IOFailed;
            break;
        }
        if (@as(usize, @intCast(c.fwrite(&buf, 1, n, fout))) != n) return error.IOFailed;
        if (write_checksum) sha.update(buf[0..n]);
    }

    if (!write_checksum) return;
    const got = sha.finalResult();
    if (c.fseek(fout, 30, c.SEEK_SET) != 0) return error.IOFailed;
    if (@as(usize, @intCast(c.fwrite(&got, 1, 8, fout))) != 8) return error.IOFailed;
}

export fn arp_header_parse(
    bytes: ?[*]const u8,
    bytes_len: usize,
    out: ?*CHeader,
) Err {
    const b = bytes orelse return .bad_arg;
    const o = out orelse return .bad_arg;
    if (bytes_len < header.HeaderSize) return .truncated;

    var arr: [header.HeaderSize]u8 = undefined;
    @memcpy(&arr, b[0..header.HeaderSize]);
    const h = header.Header.parse(arr) catch |e| return codeOf(e);
    h.validateFormat() catch |e| return codeOf(e);

    o.* = .{
        .version = h.version,
        .info_size = h.info_size,
        .data_offset = h.data_offset,
        .sig_offset = h.sig_offset,
        .sig_size = h.sig_size,
        .checksum = h.checksum,
        .reserved = h.reserved,
    };
    return .ok;
}

export fn arp_open(path: [*:0]const u8, out: ?*?*CPackage) Err {
    const o = out orelse return .bad_arg;
    o.* = null;
    const pkg = openInternal(path) catch |e| return codeOf(e);
    o.* = pkg;
    return .ok;
}

fn openInternal(path: [*:0]const u8) !*CPackage {
    const f = c.fopen(path, "rb") orelse return error.OpenFailed;
    defer _ = c.fclose(f);

    if (c.fseek(f, 0, c.SEEK_END) != 0) return error.IOFailed;
    const ft = c.ftell(f);
    if (ft < 0) return error.IOFailed;
    const len: usize = @intCast(ft);
    if (len < header.HeaderSize) return error.Truncated;
    if (c.fseek(f, 0, c.SEEK_SET) != 0) return error.IOFailed;

    const raw = c.malloc(len) orelse return error.Overflow;
    errdefer c.free(raw);
    const bytes: [*]u8 = @ptrCast(raw);

    var off: usize = 0;
    while (off < len) {
        const n: usize = @intCast(c.fread(@ptrCast(bytes + off), 1, len - off, f));
        if (n == 0) return error.Truncated;
        off += n;
    }

    const buf = bytes[0..len];
    const h = try header.parseChecked(buf, len);
    const end: usize = if (h.sig_size != 0) @intCast(h.sig_offset) else len;
    const data_off: usize = @intCast(h.data_offset);

    const pkg_raw = c.malloc(@sizeOf(CPackage)) orelse return error.Overflow;
    const pkg: *CPackage = @ptrCast(@alignCast(pkg_raw));
    pkg.* = .{
        .bytes = bytes,
        .len = len,
        .header = .{
            .version = h.version,
            .info_size = h.info_size,
            .data_offset = h.data_offset,
            .sig_offset = h.sig_offset,
            .sig_size = h.sig_size,
            .checksum = h.checksum,
            .reserved = h.reserved,
        },
        .data_off = data_off,
        .data_len = end - data_off,
        .sig_off = if (h.sig_size != 0) @intCast(h.sig_offset) else 0,
        .sig_len = h.sig_size,
    };
    return pkg;
}

export fn arp_free(pkg: ?*CPackage) void {
    const p = pkg orelse return;
    c.free(@ptrCast(p.bytes));
    c.free(p);
}

export fn arp_package_header(pkg: ?*const CPackage) ?*const CHeader {
    const p = pkg orelse return null;
    return &p.header;
}

export fn arp_package_info(pkg: ?*const CPackage, len: ?*usize) ?[*]const u8 {
    const p = pkg orelse return null;
    if (len) |l| l.* = p.header.info_size;
    return p.bytes + header.HeaderSize;
}

export fn arp_package_data(pkg: ?*const CPackage, len: ?*usize) ?[*]const u8 {
    const p = pkg orelse return null;
    if (len) |l| l.* = p.data_len;
    return p.bytes + p.data_off;
}

export fn arp_package_signature(pkg: ?*const CPackage, len: ?*usize) ?[*]const u8 {
    const p = pkg orelse return null;
    if (p.sig_len == 0) {
        if (len) |l| l.* = 0;
        return null;
    }
    if (len) |l| l.* = p.sig_len;
    return p.bytes + p.sig_off;
}

export fn arp_check_checksum(pkg: ?*CPackage) Err {
    const p = pkg orelse return .bad_arg;
    const buf = p.bytes[0..p.len];
    const info = buf[header.HeaderSize .. header.HeaderSize + p.header.info_size];
    if (!checksum.matches(p.header.checksum, info, buf[p.data_off .. p.data_off + p.data_len])) {
        return .bad_checksum;
    }
    return .ok;
}

export fn arp_package_key_id(pkg: ?*const CPackage, out: ?*[8]u8) Err {
    const p = pkg orelse return .bad_arg;
    const o = out orelse return .bad_arg;
    if (p.sig_len == 0) return .unsigned;
    const blob = signature.parse(p.bytes[p.sig_off .. p.sig_off + p.sig_len]) catch
        return .bad_signature;
    o.* = blob.key_id;
    return .ok;
}

fn toStatus(s: signature.VerifyStatus) CVerifyStatus {
    return switch (s) {
        .unsigned => .unsigned,
        .invalid => .invalid,
        .valid => .valid,
    };
}

export fn arp_verify_pkg(pkg: ?*CPackage, status: ?*CVerifyStatus, out_key_id: ?*[8]u8) Err {
    const p = pkg orelse return .bad_arg;
    const st = status orelse return .bad_arg;
    const r = signature.verify(p.bytes[0..p.len]);
    st.* = toStatus(r.status);
    if (out_key_id) |k| k.* = r.key_id orelse [_]u8{0} ** 8;
    return .ok;
}

export fn arp_verify_mem(bytes: ?[*]const u8, len: usize, status: ?*CVerifyStatus, out_key_id: ?*[8]u8) Err {
    const b = bytes orelse return .bad_arg;
    const st = status orelse return .bad_arg;
    if (len < header.HeaderSize) return .truncated;
    const r = signature.verify(b[0..len]);
    st.* = toStatus(r.status);
    if (out_key_id) |k| k.* = r.key_id orelse [_]u8{0} ** 8;
    return .ok;
}

export fn arp_verify_file(path: [*:0]const u8, trusted_dir: ?[*:0]const u8) Err {
    var pkg: ?*CPackage = null;
    const rc = arp_open(path, &pkg);
    if (rc != .ok) return rc;
    defer arp_free(pkg);

    var st: CVerifyStatus = .invalid;
    var kid: [8]u8 = [_]u8{0} ** 8;
    const vr = arp_verify_pkg(pkg, &st, &kid);
    if (vr != .ok) return vr;
    return policy(st, kid, trusted_dir);
}

fn policy(st: CVerifyStatus, kid: [8]u8, trusted_dir: ?[*:0]const u8) Err {
    return switch (st) {
        .unsigned => .unsigned,
        .invalid => .bad_signature,
        .valid => blk: {
            if (trusted_dir) |dir| {
                if (!keyInDir(dir, kid)) break :blk .untrusted_key;
            }
            break :blk .ok;
        },
    };
}

fn keyInDir(dir: [*:0]const u8, key_id: [8]u8) bool {
    var buf: [4096]u8 = undefined;
    var i: usize = 0;
    while (dir[i] != 0) : (i += 1) {
        if (i + 17 >= buf.len) return false;
        buf[i] = dir[i];
    }
    buf[i] = '/';
    i += 1;
    const hex = std.fmt.bytesToHex(key_id, .lower);
    @memcpy(buf[i .. i + 16], &hex);
    i += 16;
    buf[i] = 0;
    const p: [*:0]const u8 = @ptrCast(&buf);
    const f = c.fopen(p, "rb") orelse return false;
    _ = c.fclose(f);
    return true;
}

export fn arp_verify_detached(
    blob: ?[*]const u8,
    blob_len: usize,
    data: ?[*]const u8,
    data_len: usize,
    trusted_dir: ?[*:0]const u8,
) Err {
    const b = blob orelse return .bad_arg;
    const d = data orelse return .bad_arg;
    const r = signature.verifyDetached(b[0..blob_len], d[0..data_len]);
    return switch (r.status) {
        .unsigned, .invalid => .bad_signature,
        .valid => blk: {
            if (trusted_dir) |dir| {
                if (!keyInDir(dir, r.key_id orelse [_]u8{0} ** 8)) break :blk .untrusted_key;
            }
            break :blk .ok;
        },
    };
}

export fn arp_sign_file(path: [*:0]const u8, seed: ?[*]const u8) Err {
    const s = seed orelse return .bad_arg;
    signFileInternal(path, s[0..32].*) catch |e| return codeOf(e);
    return .ok;
}

fn signFileInternal(path: [*:0]const u8, seed: [32]u8) !void {
    const input = try readPathBytes(path, std.heap.c_allocator);
    defer std.heap.c_allocator.free(input);
    const signed_bytes = try signature.sign(std.heap.c_allocator, input, seed);
    defer std.heap.c_allocator.free(signed_bytes);
    try writePathBytes(path, signed_bytes);
}

export fn arp_sign_mem(
    in: ?[*]const u8,
    in_len: usize,
    out: ?[*]u8,
    out_cap: usize,
    out_len: ?*usize,
    seed: ?[*]const u8,
) Err {
    const ip = in orelse return .bad_arg;
    const op = out orelse return .bad_arg;
    const ol = out_len orelse return .bad_arg;
    const s = seed orelse return .bad_arg;
    signMemInternal(ip[0..in_len], op[0..out_cap], s[0..32].*, ol) catch |e| return codeOf(e);
    return .ok;
}

fn signMemInternal(input: []const u8, out: []u8, seed: [32]u8, out_len: *usize) !void {
    const signed_bytes = try signature.sign(std.heap.c_allocator, input, seed);
    defer std.heap.c_allocator.free(signed_bytes);
    if (out.len < signed_bytes.len) return error.BufferTooSmall;
    @memcpy(out[0..signed_bytes.len], signed_bytes);
    out_len.* = signed_bytes.len;
}

export fn arp_unpack_stream(
    arp_path: [*:0]const u8,
    data_out_path: [*:0]const u8,
) Err {
    unpackStreamInternal(arp_path, data_out_path) catch |e| return codeOf(e);
    return .ok;
}

fn unpackStreamInternal(arp_path: [*:0]const u8, data_out_path: [*:0]const u8) !void {
    const fin = c.fopen(arp_path, "rb") orelse return error.OpenFailed;
    defer _ = c.fclose(fin);

    if (c.fseek(fin, 0, c.SEEK_END) != 0) return error.IOFailed;
    const ft = c.ftell(fin);
    if (ft < 0) return error.IOFailed;
    const file_size: u64 = @intCast(ft);
    if (c.fseek(fin, 0, c.SEEK_SET) != 0) return error.IOFailed;

    var hdr_bytes: [header.HeaderSize]u8 = undefined;
    var off: usize = 0;
    while (off < hdr_bytes.len) {
        const n: usize = @intCast(c.fread(&hdr_bytes[off], 1, hdr_bytes.len - off, fin));
        if (n == 0) return error.Truncated;
        off += n;
    }
    const h = try header.Header.parse(hdr_bytes);
    try h.validateFormat();
    try h.validateBounds(file_size);

    const fout = c.fopen(data_out_path, "wb") orelse return error.OpenFailed;
    defer _ = c.fclose(fout);

    var sha = Sha256.init(.{});
    var buf: [64 * 1024]u8 = undefined;

    var skip: u64 = h.data_offset - header.HeaderSize;
    while (skip > 0) {
        const want: usize = @intCast(@min(skip, buf.len));
        const n: usize = @intCast(c.fread(&buf, 1, want, fin));
        if (n == 0) return error.Truncated;
        sha.update(buf[0..n]);
        skip -= n;
    }

    if (h.sig_size != 0) {
        var remaining: u64 = h.sig_offset - h.data_offset;
        while (remaining > 0) {
            const want: usize = @intCast(@min(remaining, buf.len));
            const n: usize = @intCast(c.fread(&buf, 1, want, fin));
            if (n == 0) return error.Truncated;
            if (@as(usize, @intCast(c.fwrite(&buf, 1, n, fout))) != n) return error.IOFailed;
            sha.update(buf[0..n]);
            remaining -= n;
        }
    } else {
        while (true) {
            const n: usize = @intCast(c.fread(&buf, 1, buf.len, fin));
            if (n == 0) {
                if (c.ferror(fin) != 0) return error.IOFailed;
                break;
            }
            if (@as(usize, @intCast(c.fwrite(&buf, 1, n, fout))) != n) return error.IOFailed;
            sha.update(buf[0..n]);
        }
    }

    if (!checksum.isZero(h.checksum)) {
        const got = sha.finalResult();
        if (!std.mem.eql(u8, &h.checksum, got[0..8])) return error.BadChecksum;
    }
}

fn writePathBytes(path: [*:0]const u8, bytes: []const u8) !void {
    const f = c.fopen(path, "wb") orelse return error.OpenFailed;
    defer _ = c.fclose(f);
    if (bytes.len == 0) return;
    if (@as(usize, @intCast(c.fwrite(bytes.ptr, 1, bytes.len, f))) != bytes.len)
        return error.IOFailed;
}

fn readPathBytes(path: [*:0]const u8, allocator: std.mem.Allocator) ![]u8 {
    const f = c.fopen(path, "rb") orelse return error.OpenFailed;
    defer _ = c.fclose(f);
    if (c.fseek(f, 0, c.SEEK_END) != 0) return error.IOFailed;
    const end: usize = @intCast(c.ftell(f));
    if (c.fseek(f, 0, c.SEEK_SET) != 0) return error.IOFailed;
    const buf = try allocator.alloc(u8, end);
    if (buf.len == 0) return buf;
    var off: usize = 0;
    while (off < buf.len) {
        const n: usize = @intCast(c.fread(@ptrCast(buf.ptr + off), 1, buf.len - off, f));
        if (n == 0) return error.Truncated;
        off += n;
    }
    return buf;
}

fn validHeader() header.Header {
    return .{
        .version = 1,
        .info_size = 18,
        .data_offset = 82,
        .sig_offset = 0,
        .sig_size = 0,
        .checksum = [_]u8{0} ** 8,
        .reserved = [_]u8{0} ** 26,
    };
}

test "cabi arp_pack_mem roundtrip" {
    const info = "name = \"demo\"\n";
    const data = "payload-bytes";

    const total = arp_pack_size(info.len, data.len);
    try std.testing.expectEqual(@as(usize, 64 + info.len + data.len), total);

    const out = try std.testing.allocator.alloc(u8, total);
    defer std.testing.allocator.free(out);

    const rc = arp_pack_mem(info.ptr, info.len, data.ptr, data.len, out.ptr, out.len);
    try std.testing.expectEqual(Err.ok, rc);

    var r = std.Io.Reader.fixed(out);
    const data_out = try std.testing.allocator.alloc(u8, data.len);
    defer std.testing.allocator.free(data_out);
    var w = std.Io.Writer.fixed(data_out);
    const res = try unpacker.read(std.testing.allocator, &w, &r);
    defer std.testing.allocator.free(res.info);

    try std.testing.expectEqualSlices(u8, info, res.info);
    try std.testing.expectEqualSlices(u8, data, data_out);
}

test "cabi arp_pack_stream writes valid arp" {
    const data_path = "zlibarp_cabi_data.bin";
    const out_path = "zlibarp_cabi_out.arp";
    defer _ = c.remove(data_path);
    defer _ = c.remove(out_path);

    const info = "name = \"demo\"\n";
    const data = "stream-payload-bytes";
    try writePathBytes(data_path, data);

    const rc = arp_pack_stream(out_path, info.ptr, info.len, data_path);
    try std.testing.expectEqual(Err.ok, rc);

    const whole = try readPathBytes(out_path, std.testing.allocator);
    defer std.testing.allocator.free(whole);

    try std.testing.expectEqual(@as(usize, 64 + info.len + data.len), whole.len);
    try std.testing.expectEqualSlices(u8, &header.Magic, whole[0..4]);
    try std.testing.expectEqualSlices(u8, info, whole[64 .. 64 + info.len]);
    try std.testing.expectEqualSlices(u8, data, whole[64 + info.len ..]);
}

test "cabi arp_header_parse validates" {
    const h = validHeader();
    const bytes = h.serialize();
    var ch: CHeader = undefined;
    try std.testing.expectEqual(Err.ok, arp_header_parse(&bytes, bytes.len, &ch));
    try std.testing.expectEqual(@as(u16, 1), ch.version);
    try std.testing.expectEqual(@as(u32, 18), ch.info_size);
    try std.testing.expectEqual(@as(u64, 82), ch.data_offset);

    var short: [10]u8 = undefined;
    try std.testing.expectEqual(Err.truncated, arp_header_parse(&short, short.len, &ch));

    var garbage = [_]u8{'X'} ** 64;
    try std.testing.expectEqual(Err.bad_magic, arp_header_parse(&garbage, garbage.len, &ch));

    var bad_ver = h;
    bad_ver.version = 2;
    const bv_bytes = bad_ver.serialize();
    try std.testing.expectEqual(Err.bad_version, arp_header_parse(&bv_bytes, bv_bytes.len, &ch));

    try std.testing.expectEqual(Err.bad_arg, arp_header_parse(null, 0, &ch));
}

test "cabi arp_header_parse rejects nonzero reserved" {
    var h = validHeader();
    h.reserved[0] = 1;
    const bytes = h.serialize();
    var ch: CHeader = undefined;
    try std.testing.expectEqual(Err.nonzero_reserved, arp_header_parse(&bytes, bytes.len, &ch));
}

test "cabi arp_unpack_stream extracts data" {
    const data_path = "zlibarp_cabi_in_data.bin";
    const arp_path = "zlibarp_cabi_src.arp";
    const out_path = "zlibarp_cabi_out_data.bin";
    defer _ = c.remove(data_path);
    defer _ = c.remove(arp_path);
    defer _ = c.remove(out_path);

    const info = "name = \"demo\"\n";
    const data = "stream-payload-bytes";
    try writePathBytes(data_path, data);

    try std.testing.expectEqual(Err.ok, arp_pack_stream(arp_path, info.ptr, info.len, data_path));
    try std.testing.expectEqual(Err.ok, arp_unpack_stream(arp_path, out_path));

    const extracted = try readPathBytes(out_path, std.testing.allocator);
    defer std.testing.allocator.free(extracted);
    try std.testing.expectEqualSlices(u8, data, extracted);
}

test "cabi read side errors" {
    const garbage_path = "zlibarp_cabi_bad.arp";
    defer _ = c.remove(garbage_path);
    var garbage = [_]u8{'X'} ** 64;
    try writePathBytes(garbage_path, &garbage);
    try std.testing.expectEqual(Err.bad_magic, arp_unpack_stream(garbage_path, "zlibarp_cabi_never.bin"));

    try std.testing.expectEqual(Err.open_failed, arp_unpack_stream("zlibarp_cabi_missing.arp", "zlibarp_cabi_never.bin"));
}

test "cabi pack error cases" {
    try std.testing.expectEqual(@as(usize, 0), arp_pack_size(std.math.maxInt(u32) + 1, 0));
    var buf: [64]u8 = undefined;
    try std.testing.expectEqual(Err.buffer_too_small, arp_pack_mem("a", 1, "b", 1, &buf, buf.len));
}

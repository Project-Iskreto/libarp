# libarp

English | [简体中文](README.zh-CN.md)

An ARP (Advanced Release Package) write and read library.

## ARP Format

```
┌─────────────────────────────────────────────────┐
│ Offset 0-63: 64-byte header                     │
│   - magic: "ARP\x01"                            │
│   - version: u16 (current = 1)                  │
│   - info_size: u32                              │
│   - data_offset: u64                            │
│   - sig_offset: u64 (reserved)                  │
│   - sig_size: u32 (reserved)                    │
│   - checksum: [8]u8 (reserved)                  │
│   - reserved: [26]u8 (reserved)                 │
├─────────────────────────────────────────────────┤
│ Offset 64: .info metadata (TOML-like text)      │
│   Length = info_size                            │
├─────────────────────────────────────────────────┤
│ Offset data_offset: bin.tar.zst compressed data │
│   Length = file size - data_offset              │
└─────────────────────────────────────────────────┘
```

## Features

- Parse the 64-byte header (little-endian, with bounds checking)
- Serialize a header into a byte array
- Pack: header + `.info` + data into an `.arp` file
- Unpack: `.arp` file into header + `.info` + data
- Signature and integrity verification will be supported in the future

## C API

Reading uses an opaque handle:

```c
struct arp_package *pkg = NULL;
if (arp_open("pkg.arp", &pkg) != ARP_OK) { /* ... */ }
size_t ilen, dlen, slen;
const void *info    = arp_package_info(pkg, &ilen);
const void *data    = arp_package_data(pkg, &dlen);
const void *sigblob = arp_package_signature(pkg, &slen); /* NULL when unsigned */
uint8_t key_id[8];
arp_package_key_id(pkg, key_id);
arp_free(pkg);
```

- `arp_package_info/data/signature/header/key_id` return pointers **into the package buffer**; they stay valid until `arp_free`. Only the package itself needs `arp_free`; `arp_free(NULL)` is safe.
- `data` stops at `sig_offset` for signed packages (only unsigned packages run to EOF). The signature accessor returns the raw 109-byte blob (not decoded).
- `arp_open` performs **structural checks only** (format + bounds) and reads the whole file into memory. Integrity is a separate `arp_check_checksum(pkg)`; signature verification is separate too.

Verification is a three-state query plus thin policy wrappers:

```c
enum arp_verify_status st; uint8_t kid[8];
arp_verify_mem(bytes, len, &st, kid);   /* ARP_VS_UNSIGNED / ARP_VS_INVALID / ARP_VS_VALID */
arp_verify_pkg(pkg, &st, kid);
```

- The library returns the status and `key_id`; **policy belongs to the caller**.
- `arp_verify_file(path, trusted_dir)` and `arp_verify_detached(blob, blob_len, data, data_len, trusted_dir)` are convenience wrappers: they map the status to `ARP_ERR_UNSIGNED` / `ARP_ERR_BAD_SIGNATURE` and, when `trusted_dir != NULL`, reject keys absent from `trusted_dir` (`<trusted_dir>/<key_id hex>`) with `ARP_ERR_UNTRUSTED_KEY`. `trusted_dir == NULL` verifies cryptography only.

`struct arp_pack_opts` is ABI-forward-compatible: zero-initialize it and set `abi_version = 1`. Uninitialized or unknown versions fall back to defaults (`write_checksum = 1`).

## Limitations

- `arp_open` reads the entire package into memory; large packages (hundreds of MB) are memory-heavy. mmap / streaming is planned.
- Zig: `open(bytes)` is a zero-copy view (no allocator); the caller must keep `bytes` alive. `unpack` is the streaming/copying entry point whose `UnpackResult.info` is allocated and owned by the caller.

## License

MIT

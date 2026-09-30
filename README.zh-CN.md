# libarp

[English](README.md) | 简体中文

一个用于读写 ARP（Advanced Release Package）格式的库。

## ARP 文件格式

```
┌────────────────────────────────────────┐
│ 偏移 0-63：64B 头（Header）            │
│   - magic: "ARP\x01"                   │
│   - version: u16（当前 = 1）           │
│   - info_size: u32                     │
│   - data_offset: u64                   │
│   - sig_offset: u64（0 = 未签名）      │
│   - sig_size: u32（109 或 0）          │
│   - checksum: [8]u8（sha256 前 8B）    │
│   - reserved: [26]u8（全 0）           │
├────────────────────────────────────────┤
│ 偏移 64：.info 元数据（类 TOML 文本）  │
│   长度 = info_size                     │
├────────────────────────────────────────┤
│ 偏移 data_offset：bin.tar.zst 压缩数据 │
│   长度 = sig_offset - data_offset      │
├────────────────────────────────────────┤
│ 偏移 sig_offset：Ed25519 签名区        │
│   长度 = sig_size（仅签名包）          │
└────────────────────────────────────────┘
```

checksum 覆盖 `.info` 与 `data`。
签名覆盖 `file[0..sig_offset)`。

## 功能

- 解析 64 字节文件头
- 将 Header 序列化为字节数组
- 打包：把 Header、`.info` 和数据段组装成 `.arp` 文件
- 解包：从 `.arp` 文件还原 Header、`.info` 和数据段
- 完整性：计算/校验 `sha256(info || data)[0..8]`
- 真实性：解析并校验 109 字节 Ed25519 签名
- 签名：写入 109 字节 Ed25519 签名

## C 接口

读取用不透明句柄：

```c
struct arp_package *pkg = NULL;
if (arp_open("pkg.arp", &pkg) != ARP_OK) { /* ... */ }
size_t ilen, dlen, slen;
const void *info    = arp_package_info(pkg, &ilen);
const void *data    = arp_package_data(pkg, &dlen);
const void *sigblob = arp_package_signature(pkg, &slen);
uint8_t key_id[8];
arp_package_key_id(pkg, key_id);
arp_free(pkg);
```

- `arp_package_info/data/signature/header/key_id` 返回的是**指向包缓冲的内部指针**，在 `arp_free` 前有效；只需 `arp_free` 释放包本身，`arp_free(NULL)` 安全。
- `data` 对签名包**止于 `sig_offset`**（只有未签名包才到文件末尾）；签名访问器返回**原始 109 字节 blob**（不解码）。
- `arp_open` 只做**结构性检查**（格式 + 边界），会把整个文件读入内存；完整性用 `arp_check_checksum(pkg)`，签名校验另算。

校验采用三态查询 + 策略薄封装：

```c
enum arp_verify_status st; uint8_t kid[8];
arp_verify_mem(bytes, len, &st, kid);   /* ARP_VS_UNSIGNED / ARP_VS_INVALID / ARP_VS_VALID */
arp_verify_pkg(pkg, &st, kid);
```

- 库返回状态与 `key_id`，**策略由调用方决定**。
- `arp_verify_file(path, trusted_dir)` 与 `arp_verify_detached(blob, blob_len, data, data_len, trusted_dir)` 是便捷封装：把状态映射为 `ARP_ERR_UNSIGNED` / `ARP_ERR_BAD_SIGNATURE`；当 `trusted_dir != NULL` 时，`key_id` 不在 `trusted_dir`（`<trusted_dir>/<key_id 十六进制>`）则返回 `ARP_ERR_UNTRUSTED_KEY`。`trusted_dir == NULL` 时只验密码学。

`struct arp_pack_opts` ABI 前向兼容：调用方零初始化并置 `abi_version = 1`；未初始化或未知版本走默认（`write_checksum = 1`）。

## 限制

- `arp_open` 全量读入内存；大包（数百 MB）有压力，后续用 mmap / 流式。
- Zig：`open(bytes)` 为零拷贝视图（无分配器），调用方需保证 `bytes` 存活；`unpack` 是流式/拷贝入口，`UnpackResult.info` 由调用方分配并负责释放。

## 许可证

MIT

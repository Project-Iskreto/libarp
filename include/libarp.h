#ifndef LIBARP_H
#define LIBARP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum arp_err {
    ARP_OK = 0,
    ARP_ERR_BAD_ARG = 1,
    ARP_ERR_INFO_TOO_LARGE = 2,
    ARP_ERR_OVERFLOW = 3,
    ARP_ERR_BUFFER_TOO_SMALL = 4,
    ARP_ERR_BAD_MAGIC = 5,
    ARP_ERR_BAD_VERSION = 6,
    ARP_ERR_TRUNCATED = 7,
    ARP_ERR_OPEN_FAILED = 8,
    ARP_ERR_IO_FAILED = 9,
    ARP_ERR_NONZERO_RESERVED = 10,
    ARP_ERR_BAD_CHECKSUM = 11,
    ARP_ERR_BAD_SIGNATURE = 12,
    ARP_ERR_UNSIGNED = 13,
    ARP_ERR_UNTRUSTED_KEY = 14,
    ARP_ERR_DATA_OFFSET_MISMATCH = 15,
    ARP_ERR_SIG_SIZE_BAD = 16,
    ARP_ERR_SIG_OUT_OF_BOUNDS = 17,
    ARP_ERR_ALREADY_SIGNED = 18,
    ARP_ERR_UNKNOWN = 99,
};

struct arp_header {
    uint16_t version;
    uint32_t info_size;
    uint64_t data_offset;
    uint64_t sig_offset;
    uint32_t sig_size;
    uint8_t checksum[8];
    uint8_t reserved[26];
};

size_t arp_pack_size(size_t info_len, size_t data_len);

enum arp_err arp_pack_mem(const void *info, size_t info_len,
                          const void *data, size_t data_len,
                          void *out, size_t out_cap);

enum arp_err arp_pack_stream(const char *out_path,
                             const void *info, size_t info_len,
                             const char *data_path);

enum arp_err arp_header_parse(const void *bytes, size_t bytes_len,
                              struct arp_header *out);

enum arp_err arp_unpack_stream(const char *arp_path,
                               const char *data_out_path);

struct arp_package;

enum arp_verify_status {
    ARP_VS_UNSIGNED = 0,
    ARP_VS_INVALID = 1,
    ARP_VS_VALID = 2,
};

enum arp_err arp_open(const char *path, struct arp_package **out);
void arp_free(struct arp_package *pkg);

const struct arp_header *arp_package_header(const struct arp_package *pkg);
const void *arp_package_info(const struct arp_package *pkg, size_t *len);
const void *arp_package_data(const struct arp_package *pkg, size_t *len);
const void *arp_package_signature(const struct arp_package *pkg, size_t *len);
enum arp_err arp_package_key_id(const struct arp_package *pkg, uint8_t out[8]);

enum arp_err arp_check_checksum(struct arp_package *pkg);

enum arp_err arp_verify_pkg(struct arp_package *pkg,
                            enum arp_verify_status *status,
                            uint8_t out_key_id[8]);
enum arp_err arp_verify_mem(const void *bytes, size_t len,
                            enum arp_verify_status *status,
                            uint8_t out_key_id[8]);
enum arp_err arp_verify_file(const char *arp_path, const char *trusted_dir);
enum arp_err arp_verify_detached(const void *blob, size_t blob_len,
                                 const void *data, size_t data_len,
                                 const char *trusted_dir);

struct arp_pack_opts {
    uint32_t abi_version;
    uint32_t write_checksum;
    uint32_t reserved[6];
};

enum arp_err arp_pack_mem_ex(const void *info, size_t info_len,
                             const void *data, size_t data_len,
                             void *out, size_t out_cap,
                             const struct arp_pack_opts *opts);

enum arp_err arp_pack_stream_ex(const char *out_path,
                                const void *info, size_t info_len,
                                const char *data_path,
                                const struct arp_pack_opts *opts);

enum arp_err arp_sign_file(const char *path, const uint8_t seed[32]);
enum arp_err arp_sign_mem(const void *in, size_t in_len,
                          void *out, size_t out_cap, size_t *out_len,
                          const uint8_t seed[32]);

#ifdef __cplusplus
}
#endif

#endif /* LIBARP_H */

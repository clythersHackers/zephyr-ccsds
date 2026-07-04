/**
 * @file ccsds_cfdp_filestore.h
 * @brief Thin CFDP filestore callback boundary for AkiraOS.
 */

#ifndef AKIRA_CCSDS_CFDP_FILESTORE_H
#define AKIRA_CCSDS_CFDP_FILESTORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ccsds_cfdp_filestore_ops {
    void *user;
    int (*open_read)(void *user, const char *path, void **handle,
                     uint32_t *size);
    int (*open_write_tmp)(void *user, const char *dst_path, void **handle);
    int (*read)(void *user, void *handle, uint32_t offset, uint8_t *buf,
                size_t len, size_t *nread);
    int (*write)(void *user, void *handle, uint32_t offset, const uint8_t *buf,
                 size_t len);
    int (*close)(void *user, void *handle);
    int (*commit_tmp)(void *user, const char *dst_path);
    int (*discard_tmp)(void *user, const char *dst_path);
};

typedef struct ccsds_cfdp_filestore_ops ccsds_cfdp_filestore_ops_t;

#ifdef __cplusplus
}
#endif

#endif /* AKIRA_CCSDS_CFDP_FILESTORE_H */

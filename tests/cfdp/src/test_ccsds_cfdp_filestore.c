#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/ztest.h>

#include "ccsds/ccsds_cfdp_filestore.h"

#define MEM_STORE_MAX_FILES 4u
#define MEM_STORE_MAX_PATH 32u
#define MEM_STORE_MAX_FILE_SIZE 64u

enum mem_file_mode {
    MEM_FILE_MODE_CLOSED = 0,
    MEM_FILE_MODE_READ,
    MEM_FILE_MODE_WRITE_TMP,
};

struct mem_file {
    bool exists;
    bool tmp;
    enum mem_file_mode mode;
    char path[MEM_STORE_MAX_PATH];
    uint8_t data[MEM_STORE_MAX_FILE_SIZE];
    uint32_t size;
};

struct mem_filestore {
    struct mem_file files[MEM_STORE_MAX_FILES];
};

static bool path_matches(const struct mem_file *file, const char *path)
{
    return file->exists && strcmp(file->path, path) == 0;
}

static struct mem_file *find_file(struct mem_filestore *store, const char *path,
                                  bool tmp)
{
    for (size_t i = 0u; i < MEM_STORE_MAX_FILES; i++) {
        if (path_matches(&store->files[i], path) && store->files[i].tmp == tmp) {
            return &store->files[i];
        }
    }

    return NULL;
}

static struct mem_file *alloc_file(struct mem_filestore *store)
{
    for (size_t i = 0u; i < MEM_STORE_MAX_FILES; i++) {
        if (!store->files[i].exists) {
            return &store->files[i];
        }
    }

    return NULL;
}

static int set_path(struct mem_file *file, const char *path)
{
    size_t len;

    if (path == NULL) {
        return -EINVAL;
    }

    len = strlen(path);
    if (len == 0u || len >= MEM_STORE_MAX_PATH) {
        return -EINVAL;
    }

    memcpy(file->path, path, len + 1u);
    return 0;
}

static int seed_file(struct mem_filestore *store, const char *path,
                     const uint8_t *data, uint32_t size)
{
    struct mem_file *file;

    if (store == NULL || data == NULL || size > MEM_STORE_MAX_FILE_SIZE) {
        return -EINVAL;
    }

    file = find_file(store, path, false);
    if (file == NULL) {
        file = alloc_file(store);
    }
    if (file == NULL) {
        return -ENOSPC;
    }

    memset(file, 0, sizeof(*file));
    if (set_path(file, path) != 0) {
        return -EINVAL;
    }

    file->exists = true;
    file->tmp = false;
    file->mode = MEM_FILE_MODE_CLOSED;
    memcpy(file->data, data, size);
    file->size = size;
    return 0;
}

static int mem_open_read(void *user, const char *path, void **handle,
                         uint32_t *size)
{
    struct mem_filestore *store = user;
    struct mem_file *file;

    if (store == NULL || path == NULL || handle == NULL || size == NULL) {
        return -EINVAL;
    }

    file = find_file(store, path, false);
    if (file == NULL) {
        return -ENOENT;
    }

    file->mode = MEM_FILE_MODE_READ;
    *handle = file;
    *size = file->size;
    return 0;
}

static int mem_open_write_tmp(void *user, const char *dst_path, void **handle)
{
    struct mem_filestore *store = user;
    struct mem_file *file;

    if (store == NULL || dst_path == NULL || handle == NULL) {
        return -EINVAL;
    }

    file = find_file(store, dst_path, true);
    if (file == NULL) {
        file = alloc_file(store);
    }
    if (file == NULL) {
        return -ENOSPC;
    }

    memset(file, 0, sizeof(*file));
    if (set_path(file, dst_path) != 0) {
        return -EINVAL;
    }

    file->exists = true;
    file->tmp = true;
    file->mode = MEM_FILE_MODE_WRITE_TMP;
    *handle = file;
    return 0;
}

static int mem_read(void *user, void *handle, uint32_t offset, uint8_t *buf,
                    size_t len, size_t *nread)
{
    struct mem_file *file = handle;
    uint32_t available;

    ARG_UNUSED(user);

    if (handle == NULL || buf == NULL || nread == NULL) {
        return -EINVAL;
    }
    if (!file->exists || file->mode != MEM_FILE_MODE_READ) {
        return -EBADF;
    }

    if (offset >= file->size) {
        *nread = 0u;
        return 0;
    }

    available = file->size - offset;
    if (len > available) {
        len = available;
    }

    memcpy(buf, &file->data[offset], len);
    *nread = len;
    return 0;
}

static int mem_write(void *user, void *handle, uint32_t offset,
                     const uint8_t *buf, size_t len)
{
    struct mem_file *file = handle;
    size_t end;

    ARG_UNUSED(user);

    if (handle == NULL || buf == NULL) {
        return -EINVAL;
    }
    if (!file->exists || !file->tmp || file->mode != MEM_FILE_MODE_WRITE_TMP) {
        return -EBADF;
    }
    if (offset > MEM_STORE_MAX_FILE_SIZE || len > MEM_STORE_MAX_FILE_SIZE) {
        return -EFBIG;
    }

    end = (size_t)offset + len;
    if (end > MEM_STORE_MAX_FILE_SIZE || end < offset) {
        return -EFBIG;
    }

    memcpy(&file->data[offset], buf, len);
    if (end > file->size) {
        file->size = end;
    }

    return 0;
}

static int mem_close(void *user, void *handle)
{
    struct mem_file *file = handle;

    ARG_UNUSED(user);

    if (handle == NULL) {
        return -EINVAL;
    }
    if (!file->exists || file->mode == MEM_FILE_MODE_CLOSED) {
        return -EBADF;
    }

    file->mode = MEM_FILE_MODE_CLOSED;
    return 0;
}

static int mem_commit_tmp(void *user, const char *dst_path)
{
    struct mem_filestore *store = user;
    struct mem_file *tmp;
    struct mem_file *dst;

    if (store == NULL || dst_path == NULL) {
        return -EINVAL;
    }

    tmp = find_file(store, dst_path, true);
    if (tmp == NULL) {
        return -ENOENT;
    }

    dst = find_file(store, dst_path, false);
    if (dst == NULL) {
        dst = alloc_file(store);
    }
    if (dst == NULL) {
        return -ENOSPC;
    }

    memset(dst, 0, sizeof(*dst));
    if (set_path(dst, dst_path) != 0) {
        return -EINVAL;
    }
    dst->exists = true;
    dst->tmp = false;
    dst->mode = MEM_FILE_MODE_CLOSED;
    memcpy(dst->data, tmp->data, tmp->size);
    dst->size = tmp->size;

    memset(tmp, 0, sizeof(*tmp));
    return 0;
}

static int mem_discard_tmp(void *user, const char *dst_path)
{
    struct mem_filestore *store = user;
    struct mem_file *tmp;

    if (store == NULL || dst_path == NULL) {
        return -EINVAL;
    }

    tmp = find_file(store, dst_path, true);
    if (tmp == NULL) {
        return -ENOENT;
    }

    memset(tmp, 0, sizeof(*tmp));
    return 0;
}

static void init_ops(struct mem_filestore *store,
                     ccsds_cfdp_filestore_ops_t *ops)
{
    memset(store, 0, sizeof(*store));
    *ops = (ccsds_cfdp_filestore_ops_t){
        .user = store,
        .open_read = mem_open_read,
        .open_write_tmp = mem_open_write_tmp,
        .read = mem_read,
        .write = mem_write,
        .close = mem_close,
        .commit_tmp = mem_commit_tmp,
        .discard_tmp = mem_discard_tmp,
    };
}

ZTEST(ccsds_cfdp_filestore, test_open_read_returns_handle_and_size)
{
    struct mem_filestore store;
    ccsds_cfdp_filestore_ops_t ops;
    const uint8_t data[] = { 1u, 2u, 3u, 4u };
    void *handle = NULL;
    uint32_t size = 0u;

    init_ops(&store, &ops);
    zassert_equal(seed_file(&store, "source.bin", data, sizeof(data)), 0);

    zassert_equal(ops.open_read(ops.user, "source.bin", &handle, &size), 0);
    zassert_not_null(handle);
    zassert_equal(size, sizeof(data));
}

ZTEST(ccsds_cfdp_filestore, test_read_supports_offsets_and_reports_nread)
{
    struct mem_filestore store;
    ccsds_cfdp_filestore_ops_t ops;
    const uint8_t data[] = { 10u, 11u, 12u, 13u, 14u };
    uint8_t out[4] = { 0u };
    void *handle = NULL;
    uint32_t size = 0u;
    size_t nread = 99u;

    init_ops(&store, &ops);
    zassert_equal(seed_file(&store, "source.bin", data, sizeof(data)), 0);
    zassert_equal(ops.open_read(ops.user, "source.bin", &handle, &size), 0);

    zassert_equal(ops.read(ops.user, handle, 2u, out, sizeof(out), &nread), 0);
    zassert_equal(nread, 3u);
    zassert_mem_equal(out, &data[2], nread);

    zassert_equal(ops.read(ops.user, handle, size, out, sizeof(out), &nread),
                  0);
    zassert_equal(nread, 0u);
}

ZTEST(ccsds_cfdp_filestore, test_open_write_tmp_supports_random_access_writes)
{
    struct mem_filestore store;
    ccsds_cfdp_filestore_ops_t ops;
    const uint8_t tail[] = { 'C', 'D' };
    const uint8_t head[] = { 'A', 'B' };
    uint8_t out[4] = { 0u };
    void *write_handle = NULL;
    void *read_handle = NULL;
    uint32_t size = 0u;
    size_t nread = 0u;

    init_ops(&store, &ops);

    zassert_equal(ops.open_write_tmp(ops.user, "dst.bin", &write_handle), 0);
    zassert_equal(ops.write(ops.user, write_handle, 2u, tail, sizeof(tail)), 0);
    zassert_equal(ops.write(ops.user, write_handle, 0u, head, sizeof(head)), 0);
    zassert_equal(ops.close(ops.user, write_handle), 0);
    zassert_equal(ops.commit_tmp(ops.user, "dst.bin"), 0);

    zassert_equal(ops.open_read(ops.user, "dst.bin", &read_handle, &size), 0);
    zassert_equal(size, sizeof(out));
    zassert_equal(ops.read(ops.user, read_handle, 0u, out, sizeof(out), &nread),
                  0);
    zassert_equal(nread, sizeof(out));
    zassert_mem_equal(out, "ABCD", sizeof(out));
}

ZTEST(ccsds_cfdp_filestore, test_commit_tmp_makes_file_visible)
{
    struct mem_filestore store;
    ccsds_cfdp_filestore_ops_t ops;
    const uint8_t data[] = { 0xA5u, 0x5Au };
    void *handle = NULL;
    uint32_t size = 0u;

    init_ops(&store, &ops);

    zassert_equal(ops.open_write_tmp(ops.user, "new.bin", &handle), 0);
    zassert_equal(ops.write(ops.user, handle, 0u, data, sizeof(data)), 0);
    zassert_equal(ops.commit_tmp(ops.user, "new.bin"), 0);

    handle = NULL;
    zassert_equal(ops.open_read(ops.user, "new.bin", &handle, &size), 0);
    zassert_not_null(handle);
    zassert_equal(size, sizeof(data));
}

ZTEST(ccsds_cfdp_filestore, test_discard_tmp_drops_temp_file)
{
    struct mem_filestore store;
    ccsds_cfdp_filestore_ops_t ops;
    const uint8_t data[] = { 1u };
    void *handle = NULL;
    uint32_t size = 0u;

    init_ops(&store, &ops);

    zassert_equal(ops.open_write_tmp(ops.user, "drop.bin", &handle), 0);
    zassert_equal(ops.write(ops.user, handle, 0u, data, sizeof(data)), 0);
    zassert_equal(ops.discard_tmp(ops.user, "drop.bin"), 0);
    zassert_equal(ops.open_read(ops.user, "drop.bin", &handle, &size),
                  -ENOENT);
}

ZTEST(ccsds_cfdp_filestore, test_close_invalidates_handles)
{
    struct mem_filestore store;
    ccsds_cfdp_filestore_ops_t ops;
    const uint8_t data[] = { 1u, 2u };
    uint8_t out[2] = { 0u };
    void *handle = NULL;
    uint32_t size = 0u;
    size_t nread = 0u;

    init_ops(&store, &ops);
    zassert_equal(seed_file(&store, "source.bin", data, sizeof(data)), 0);
    zassert_equal(ops.open_read(ops.user, "source.bin", &handle, &size), 0);
    zassert_equal(ops.close(ops.user, handle), 0);

    zassert_equal(ops.read(ops.user, handle, 0u, out, sizeof(out), &nread),
                  -EBADF);
    zassert_equal(ops.close(ops.user, handle), -EBADF);
}

ZTEST(ccsds_cfdp_filestore, test_invalid_callback_inputs)
{
    struct mem_filestore store;
    ccsds_cfdp_filestore_ops_t ops;
    const uint8_t data[] = { 1u };
    uint8_t out[1];
    void *handle = NULL;
    uint32_t size = 0u;
    size_t nread = 0u;

    init_ops(&store, &ops);

    zassert_equal(ops.open_read(NULL, "missing.bin", &handle, &size), -EINVAL);
    zassert_equal(ops.open_read(ops.user, NULL, &handle, &size), -EINVAL);
    zassert_equal(ops.open_read(ops.user, "missing.bin", NULL, &size),
                  -EINVAL);
    zassert_equal(ops.open_read(ops.user, "missing.bin", &handle, NULL),
                  -EINVAL);
    zassert_equal(ops.open_read(ops.user, "missing.bin", &handle, &size),
                  -ENOENT);

    zassert_equal(ops.open_write_tmp(NULL, "dst.bin", &handle), -EINVAL);
    zassert_equal(ops.open_write_tmp(ops.user, NULL, &handle), -EINVAL);
    zassert_equal(ops.open_write_tmp(ops.user, "dst.bin", NULL), -EINVAL);

    zassert_equal(ops.read(ops.user, NULL, 0u, out, sizeof(out), &nread),
                  -EINVAL);
    zassert_equal(ops.read(ops.user, handle, 0u, NULL, sizeof(out), &nread),
                  -EINVAL);
    zassert_equal(ops.read(ops.user, handle, 0u, out, sizeof(out), NULL),
                  -EINVAL);

    zassert_equal(ops.write(ops.user, NULL, 0u, data, sizeof(data)), -EINVAL);
    zassert_equal(ops.write(ops.user, handle, 0u, NULL, sizeof(data)),
                  -EINVAL);
    zassert_equal(ops.close(ops.user, NULL), -EINVAL);
    zassert_equal(ops.commit_tmp(NULL, "dst.bin"), -EINVAL);
    zassert_equal(ops.commit_tmp(ops.user, NULL), -EINVAL);
    zassert_equal(ops.discard_tmp(NULL, "dst.bin"), -EINVAL);
    zassert_equal(ops.discard_tmp(ops.user, NULL), -EINVAL);
}

ZTEST_SUITE(ccsds_cfdp_filestore, NULL, NULL, NULL, NULL, NULL);

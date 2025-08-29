// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "dirent.h"
#include "ggconfigd.h"
#include "helpers.h"
#include <fcntl.h>
#include <ggl/arena.h>
#include <ggl/buffer.h>
#include <ggl/cleanup.h>
#include <ggl/error.h>
#include <ggl/file.h>
#include <ggl/log.h>
#include <ggl/object.h>
#include <ggl/vector.h>
#include <ggl/yaml_decode.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

static GglError ggconfig_load_file_fd(int fd) {
    static uint8_t file_mem[8192];
    GglBuffer config_file = GGL_BUF(file_mem);

    GglError ret = ggl_file_read(fd, &config_file);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to read config file.");
        return GGL_ERR_FAILURE;
    }

    static uint8_t decode_mem[500 * sizeof(GglObject)];
    GglArena alloc = ggl_arena_init(GGL_BUF(decode_mem));

    GglObject config_obj;
    ret = ggl_yaml_decode_destructive(config_file, &alloc, &config_obj);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to parse config file.");
        return GGL_ERR_FAILURE;
    }

    GglObjVec key_path = GGL_OBJ_VEC((GglObject[GGL_MAX_OBJECT_DEPTH]) { 0 });

    GGL_LOGD(
        "Processing file load merge to key %s with timestamp 2",
        print_key_path(&key_path.list)
    );

    if (ggl_obj_type(config_obj) == GGL_TYPE_MAP) {
        ret = ggconfig_process_map(&key_path, ggl_obj_into_map(config_obj), 2);
        if (ret != GGL_ERR_OK) {
            return ret;
        }
    } else {
        ret = ggconfig_process_nonmap(&key_path, config_obj, 2);
        if (ret != GGL_ERR_OK) {
            return ret;
        }
    }

    return GGL_ERR_OK;
}

GglError ggconfig_load_file(GglBuffer path) {
    GGL_LOGT("Loading file %.*s", (int) path.len, path.data);
    int fd;
    GglError ret = ggl_file_open(path, O_RDONLY, 0, &fd);
    if (ret != GGL_ERR_OK) {
        GGL_LOGI("Could not open config file.");
        return GGL_ERR_FAILURE;
    }
    GGL_CLEANUP(cleanup_close, fd);

    return ggconfig_load_file_fd(fd);
}

GglError ggconfig_load_dir(GglBuffer path) {
    GGL_LOGT(
        "Loading files from config directory %.*s", (int) path.len, path.data
    );
    int config_dir;
    GglError ret = ggl_dir_open(path, O_RDONLY, false, &config_dir);
    if (ret != GGL_ERR_OK) {
        GGL_LOGI("Could not open config directory.");
        return GGL_ERR_FAILURE;
    }

    DIR *dir = fdopendir(config_dir);
    if (dir == NULL) {
        GGL_LOGE("Failed to read config directory.");
        (void) ggl_close(config_dir);
        return GGL_ERR_FAILURE;
    }
    GGL_CLEANUP(cleanup_closedir, dir);

    while (true) {
        // Directory stream is not shared between threads.
        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        struct dirent *entry = readdir(dir);
        if (entry == NULL) {
            break;
        }

        if (entry->d_type == DT_REG) {
            GGL_LOGT("Loading directory file %s", entry->d_name);

            int fd = -1;
            ret = ggl_file_openat(
                dirfd(dir),
                ggl_buffer_from_null_term(entry->d_name),
                O_RDONLY,
                0,
                &fd
            );
            if (ret != GGL_ERR_OK) {
                GGL_LOGW("Failed to open config file.");
                break;
            }
            GGL_CLEANUP(cleanup_close, fd);

            (void) ggconfig_load_file_fd(fd);
        }
    }

    return GGL_ERR_OK;
}

// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ggl/proxy/environment.h"
#include <assert.h>
#include <errno.h>
#include <ggl/arena.h>
#include <ggl/attr.h>
#include <ggl/buffer.h>
#include <ggl/core_bus/gg_config.h>
#include <ggl/error.h>
#include <ggl/log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

NULL_TERMINATED_STRING_ARG(2)
static GglError setenv_wrapper(GglBufList aliases, const char value[static 1]) {
    for (size_t i = 0; i < aliases.len; ++i) {
        GglBuffer name = aliases.bufs[i];
        assert(name.len > 0);
        assert(name.data != NULL);
        assert(name.data[name.len] == '\0');
        int ret
            // NOLINTNEXTLINE(concurrency-mt-unsafe)
            = setenv((const char *) name.data, value, true);
        if (ret != 0) {
            GGL_LOGE("setenv() failed with errno=%d.", errno);
            return GGL_ERR_FATAL;
        }
    }
    return GGL_ERR_OK;
}

GglError ggl_proxy_set_environment(void) {
    uint8_t alloc_mem[4096] = { 0 };
    GglArena alloc = ggl_arena_init(
        ggl_buffer_substr(GGL_BUF(alloc_mem), 0, sizeof(alloc_mem) - 1)
    );
    GglBuffer proxy_url;

    GglError ret = ggl_gg_config_read_str(
        GGL_BUF_LIST(
            GGL_STR("services"),
            GGL_STR("aws.greengrass.NucleusLite"),
            GGL_STR("configuration"),
            GGL_STR("networkProxy"),
            GGL_STR("proxy"),
            GGL_STR("url")
        ),
        &alloc,
        &proxy_url
    );
    if (ret == GGL_ERR_OK) {
        if (proxy_url.len == 0) {
            proxy_url = GGL_STR("");
        } else {
            assert(proxy_url.data != NULL);
            proxy_url.data[proxy_url.len] = '\0';
        }
        GGL_LOGD("Setting proxy environment variables from config.");
        GglBufList proxy_aliases = GGL_BUF_LIST(
            GGL_STR("all_proxy"),
            GGL_STR("http_proxy"),
            GGL_STR("https_proxy"),
            GGL_STR("ALL_PROXY"),
            GGL_STR("HTTP_PROXY"),
            GGL_STR("HTTPS_PROXY")
        );
        ret = setenv_wrapper(proxy_aliases, (char *) proxy_url.data);
        if (ret != GGL_ERR_OK) {
            return ret;
        }
    } else if (ret != GGL_ERR_NOENTRY) {
        return GGL_ERR_FAILURE;
    }

    alloc = ggl_arena_init(
        ggl_buffer_substr(GGL_BUF(alloc_mem), 0, sizeof(alloc_mem) - 1)
    );
    GglBuffer no_proxy;

    ret = ggl_gg_config_read_str(
        GGL_BUF_LIST(
            GGL_STR("services"),
            GGL_STR("aws.greengrass.NucleusLite"),
            GGL_STR("configuration"),
            GGL_STR("networkProxy"),
            GGL_STR("noProxyAddresses")
        ),
        &alloc,
        &no_proxy
    );
    if (ret == GGL_ERR_OK) {
        if (no_proxy.len == 0) {
            no_proxy = GGL_STR("");
        } else {
            assert(no_proxy.data != NULL);
            no_proxy.data[no_proxy.len] = '\0';
        }
        GGL_LOGD("Setting noproxy list from config.");

        GglBufList no_proxy_aliases
            = GGL_BUF_LIST(GGL_STR("no_proxy"), GGL_STR("NO_PROXY"));
        ret = setenv_wrapper(no_proxy_aliases, (char *) no_proxy.data);
        if (ret != GGL_ERR_OK) {
            return ret;
        }
    } else if (ret != GGL_ERR_NOENTRY) {
        return GGL_ERR_FAILURE;
    }

    return GGL_ERR_OK;
}

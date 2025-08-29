// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "embeds.h"
#include "ggconfigd.h"
#include "helpers.h"
#include <assert.h>
#include <ggl/arena.h>
#include <ggl/buffer.h>
#include <ggl/cleanup.h>
#include <ggl/core_bus/constants.h>
#include <ggl/core_bus/server.h>
#include <ggl/error.h>
#include <ggl/log.h>
#include <ggl/map.h>
#include <ggl/object.h>
#include <ggl/vector.h>
#include <inttypes.h>
#include <sqlite3.h>
#include <string.h>
#include <stdbool.h>

/// The maximum expected config keys (including nested) held under one component
/// configuration
#define MAX_CONFIG_DESCENDANTS_PER_COMPONENT 256

/// The maximum expected config keys held as children of a single config object
// TODO: Should be at least as big as MAX_COMPONENTS, add static assert?
#define MAX_CONFIG_CHILDREN_PER_OBJECT 64

static inline void cleanup_sqlite3_finalize(sqlite3_stmt **p) {
    if (*p != NULL) {
        sqlite3_finalize(*p);
    }
}

static bool config_initialized = false;
static sqlite3 *config_database;
static const char *config_database_name = "config.db";

static void sqlite_logger(void *ctx, int err_code, const char *str) {
    (void) ctx;
    (void) err_code;
    GGL_LOGE("sqlite: %s", str);
}

/// create the database to the correct schema
static GglError create_database(void) {
    GGL_LOGI("Initializing new configuration database.");

    // create the initial table
    int result
        = sqlite3_exec(config_database, GGL_SQL_CREATE_DB, NULL, NULL, NULL);
    if (result != SQLITE_OK) {
        GGL_LOGI("Error while creating database.");
        return GGL_ERR_FAILURE;
    }
    return GGL_ERR_OK;
}

GglError ggconfig_open(void) {
    GglError return_err = GGL_ERR_FAILURE;
    if (config_initialized == false) {
        int rc = sqlite3_config(SQLITE_CONFIG_LOG, sqlite_logger, NULL);
        if (rc != SQLITE_OK) {
            GGL_LOGE("Failed to set sqlite3 logger.");
            return GGL_ERR_FAILURE;
        }

        // do configuration
        rc = sqlite3_open(config_database_name, &config_database);
        if (rc) {
            GGL_LOGE(
                "Cannot open the configuration database: %s",
                sqlite3_errmsg(config_database)
            );
            return_err = GGL_ERR_FAILURE;
        } else {
            GGL_LOGI("Config database Opened");

            sqlite3_stmt *stmt;
            sqlite3_prepare_v2( // TODO: We should be checking the return code
                                // of each call to prepare
                config_database,
                GGL_SQL_CHECK_INITALIZED,
                -1,
                &stmt,
                NULL
            );
            GGL_CLEANUP(cleanup_sqlite3_finalize, stmt);

            if (sqlite3_step(stmt) == SQLITE_ROW) {
                GGL_LOGI("found keyTable");
                return_err = GGL_ERR_OK;
            } else {
                return_err = create_database();
                char *err_message = 0;
                rc = sqlite3_exec(
                    config_database,
                    GGL_SQL_CREATE_INDEX,
                    NULL,
                    NULL,
                    &err_message
                );
                if (rc) {
                    GGL_LOGI(
                        "Failed to add an index to the relationTable %s, "
                        "expect an "
                        "autoindex to be created",
                        err_message
                    );
                    sqlite3_free(err_message);
                }
            }
        }
        // create a temporary table for subscriber data
        char *err_message = 0;
        rc = sqlite3_exec(
            config_database, GGL_SQL_CREATE_SUB_TABLE, NULL, NULL, &err_message
        );
        if (rc) {
            GGL_LOGE("Failed to create temporary table %s", err_message);
            sqlite3_free(err_message);
            return_err = GGL_ERR_FAILURE;
        }
        config_initialized = true;
    } else {
        return_err = GGL_ERR_OK;
    }
    return return_err;
}

GglError ggconfig_close(void) {
    sqlite3_close(config_database);
    config_initialized = false;
    return GGL_ERR_OK;
}

static GglError key_insert(GglBuffer *key, int64_t *id_output) {
    GGL_LOGT("insert %.*s", (int) key->len, (char *) key->data);
    sqlite3_stmt *key_insert_stmt;
    sqlite3_prepare_v2(
        config_database, GGL_SQL_KEY_INSERT, -1, &key_insert_stmt, NULL
    );
    GGL_CLEANUP(cleanup_sqlite3_finalize, key_insert_stmt);
    sqlite3_bind_text(
        key_insert_stmt, 1, (char *) key->data, (int) key->len, SQLITE_STATIC
    );
    if (sqlite3_step(key_insert_stmt) != SQLITE_DONE) {
        GGL_LOGE(
            "Failed to insert key: %.*s with error: %s",
            (int) key->len,
            (char *) key->data,
            sqlite3_errmsg(config_database)
        );
        return GGL_ERR_FAILURE;
    }
    *id_output = sqlite3_last_insert_rowid(config_database);
    GGL_LOGT(
        "Insert %.*s result: %" PRId64, (int) key->len, key->data, *id_output
    );
    return GGL_ERR_OK;
}

static GglError value_is_present_for_key(
    int64_t key_id, bool *value_is_present_output
) {
    GGL_LOGT("Checking id %" PRId64, key_id);

    sqlite3_stmt *find_value_stmt;
    sqlite3_prepare_v2(
        config_database, GGL_SQL_VALUE_PRESENT, -1, &find_value_stmt, NULL
    );
    GGL_CLEANUP(cleanup_sqlite3_finalize, find_value_stmt);
    sqlite3_bind_int64(find_value_stmt, 1, key_id);
    int rc = sqlite3_step(find_value_stmt);
    if (rc == SQLITE_ROW) {
        int64_t pid = sqlite3_column_int(find_value_stmt, 0);
        if (pid) {
            GGL_LOGT("Id %" PRId64 " does have a value", key_id);
            *value_is_present_output = true;
            return GGL_ERR_OK;
        }
        GGL_LOGE(
            "Checking presence of value for key id %" PRId64 " failed", key_id
        );
        return GGL_ERR_FAILURE;
    }
    if (rc == SQLITE_DONE) {
        GGL_LOGT("Id %" PRId64 " does not have a value", key_id);
        *value_is_present_output = false;
        return GGL_ERR_OK;
    }
    GGL_LOGE(
        "Checking presence of value for key id %" PRId64
        " failed with error: %s",
        key_id,
        sqlite3_errmsg(config_database)
    );
    return GGL_ERR_FAILURE;
}

static GglError find_key_with_parent(
    GglBuffer *key, int64_t parent_key_id, int64_t *key_id_output
) {
    int64_t id = 0;
    GGL_LOGT(
        "searching for key %.*s with parent id %" PRId64,
        (int) key->len,
        key->data,
        parent_key_id
    );
    sqlite3_stmt *find_element_stmt;
    sqlite3_prepare_v2(
        config_database,
        GGL_SQL_GET_KEY_WITH_PARENT,
        -1,
        &find_element_stmt,
        NULL
    );
    GGL_CLEANUP(cleanup_sqlite3_finalize, find_element_stmt);
    sqlite3_bind_text(
        find_element_stmt, 1, (char *) key->data, (int) key->len, SQLITE_STATIC
    );
    sqlite3_bind_int64(find_element_stmt, 2, parent_key_id);
    int rc = sqlite3_step(find_element_stmt);
    GGL_LOGT("find element returned %d", rc);
    if (rc == SQLITE_ROW) {
        id = sqlite3_column_int(find_element_stmt, 0);
        GGL_LOGT(
            "found key %.*s with parent id %" PRId64 " at %" PRId64,
            (int) key->len,
            key->data,
            parent_key_id,
            id
        );
        *key_id_output = id;
        return GGL_ERR_OK;
    }
    if (rc == SQLITE_DONE) {
        GGL_LOGT(
            "key %.*s with parent id %" PRId64 " not found",
            (int) key->len,
            key->data,
            parent_key_id
        );
        return GGL_ERR_NOENTRY;
    }
    GGL_LOGE(
        "finding key %.*s with parent id %" PRId64 " failed with error: %s",
        (int) key->len,
        key->data,
        parent_key_id,
        sqlite3_errmsg(config_database)
    );
    return GGL_ERR_FAILURE;
}

// get or create a keyid where the key is a root (first element of a path)
static GglError get_or_create_key_at_root(GglBuffer *key, int64_t *id_output) {
    GGL_LOGT("Checking %.*s", (int) key->len, (char *) key->data);
    int64_t id = 0;

    sqlite3_stmt *root_check_stmt;
    sqlite3_prepare_v2(
        config_database, GGL_SQL_GET_ROOT_KEY, -1, &root_check_stmt, NULL
    );
    GGL_CLEANUP(cleanup_sqlite3_finalize, root_check_stmt);
    sqlite3_bind_text(
        root_check_stmt, 1, (char *) key->data, (int) key->len, SQLITE_STATIC
    );
    int rc = sqlite3_step(root_check_stmt);
    if (rc == SQLITE_ROW) { // exists as a root and here is the id
        id = sqlite3_column_int(root_check_stmt, 0);
        GGL_LOGT("Found %.*s at %" PRId64, (int) key->len, key->data, id);
    } else if (rc == SQLITE_DONE) { // doesn't exist at root, so we need to
                                    // create the key and get the id
        GglError err = key_insert(key, &id);
        if (err != GGL_ERR_OK) {
            return GGL_ERR_FAILURE;
        }
    } else {
        GGL_LOGE(
            "finding key %.*s failed with error: %s",
            (int) key->len,
            key->data,
            sqlite3_errmsg(config_database)
        );
        return GGL_ERR_FAILURE;
    }
    *id_output = id;
    return GGL_ERR_OK;
}

static GglError relation_insert(int64_t id, int64_t parent) {
    sqlite3_stmt *relation_insert_stmt;
    sqlite3_prepare_v2(
        config_database,
        GGL_SQL_INSERT_RELATION,
        -1,
        &relation_insert_stmt,
        NULL
    );
    GGL_CLEANUP(cleanup_sqlite3_finalize, relation_insert_stmt);
    sqlite3_bind_int64(relation_insert_stmt, 1, id);
    sqlite3_bind_int64(relation_insert_stmt, 2, parent);
    int rc = sqlite3_step(relation_insert_stmt);
    if (rc == SQLITE_DONE || rc == SQLITE_OK) {
        GGL_LOGT(
            "relation insert successful key:%" PRId64 ", parent:%" PRId64,
            id,
            parent
        );
    } else {
        GGL_LOGE("relation insert fail: %s", sqlite3_errmsg(config_database));
        return GGL_ERR_FAILURE;
    }
    return GGL_ERR_OK;
}

static GglError value_insert(
    int64_t key_id, GglBuffer *value, int64_t timestamp
) {
    GglError return_err = GGL_ERR_FAILURE;
    sqlite3_stmt *value_insert_stmt;
    sqlite3_prepare_v2(
        config_database, GGL_SQL_VALUE_INSERT, -1, &value_insert_stmt, NULL
    );
    GGL_CLEANUP(cleanup_sqlite3_finalize, value_insert_stmt);
    sqlite3_bind_int64(value_insert_stmt, 1, key_id);
    sqlite3_bind_text(
        value_insert_stmt,
        2,
        (char *) value->data,
        (int) value->len,
        SQLITE_STATIC
    );
    sqlite3_bind_int64(value_insert_stmt, 3, timestamp);
    int rc = sqlite3_step(value_insert_stmt);
    if (rc == SQLITE_DONE || rc == SQLITE_OK) {
        GGL_LOGT("value insert successful");
        return_err = GGL_ERR_OK;
    } else {
        GGL_LOGE(
            "value insert fail with rc %d and error %s",
            rc,
            sqlite3_errmsg(config_database)
        );
        return_err = GGL_ERR_FAILURE;
    }
    return return_err;
}

static GglError value_update(
    int64_t key_id, GglBuffer *value, int64_t timestamp
) {
    GglError return_err = GGL_ERR_FAILURE;

    sqlite3_stmt *update_value_stmt;
    sqlite3_prepare_v2(
        config_database, GGL_SQL_VALUE_UPDATE, -1, &update_value_stmt, NULL
    );
    GGL_CLEANUP(cleanup_sqlite3_finalize, update_value_stmt);
    sqlite3_bind_text(
        update_value_stmt,
        1,
        (char *) value->data,
        (int) value->len,
        SQLITE_STATIC
    );
    sqlite3_bind_int64(update_value_stmt, 2, timestamp);
    sqlite3_bind_int64(update_value_stmt, 3, key_id);
    int rc = sqlite3_step(update_value_stmt);
    if (rc == SQLITE_DONE || rc == SQLITE_OK) {
        GGL_LOGT("value update successful");
        return_err = GGL_ERR_OK;
    } else {
        GGL_LOGE(
            "value update fail with rc %d and error %s",
            rc,
            sqlite3_errmsg(config_database)
        );
        return_err = GGL_ERR_FAILURE;
    }
    return return_err;
}

static GglError value_get_timestamp(
    int64_t id, int64_t *existing_timestamp_output
) {
    sqlite3_stmt *get_timestamp_stmt;
    sqlite3_prepare_v2(
        config_database, GGL_SQL_GET_TIMESTAMP, -1, &get_timestamp_stmt, NULL
    );
    GGL_CLEANUP(cleanup_sqlite3_finalize, get_timestamp_stmt);
    sqlite3_bind_int64(get_timestamp_stmt, 1, id);
    int rc = sqlite3_step(get_timestamp_stmt);
    if (rc == SQLITE_ROW) {
        int64_t timestamp = sqlite3_column_int64(get_timestamp_stmt, 0);
        *existing_timestamp_output = timestamp;
        return GGL_ERR_OK;
    }
    if (rc == SQLITE_DONE) {
        return GGL_ERR_NOENTRY;
    }
    GGL_LOGE(
        "getting timestamp for id %" PRId64 " failed with error: %s",
        id,
        sqlite3_errmsg(config_database)
    );
    return GGL_ERR_FAILURE;
}

// key_ids_output must point to an empty GglObjVec with capacity
// GGL_MAX_OBJECT_DEPTH
static GglError get_key_ids(GglList *key_path, GglObjVec *key_ids_output) {
    GGL_LOGT("searching for %s", print_key_path(key_path));

    sqlite3_stmt *find_element_stmt;
    sqlite3_prepare_v2(
        config_database, GGL_SQL_FIND_ELEMENT, -1, &find_element_stmt, NULL
    );
    GGL_CLEANUP(cleanup_sqlite3_finalize, find_element_stmt);

    for (size_t index = 0; index < key_path->len; index++) {
        GglBuffer key = ggl_obj_into_buf(key_path->items[index]);
        sqlite3_bind_text(
            find_element_stmt,
            (int) index + 1,
            (char *) key.data,
            (int) key.len,
            SQLITE_STATIC
        );
    }

    for (size_t index = key_path->len; index < GGL_MAX_OBJECT_DEPTH; index++) {
        sqlite3_bind_null(find_element_stmt, (int) index + 1);
    }

    sqlite3_bind_int(
        find_element_stmt, GGL_MAX_OBJECT_DEPTH + 1, (int) key_path->len
    );

    for (size_t i = 0; i < key_path->len; i++) {
        int rc = sqlite3_step(find_element_stmt);
        if (rc == SQLITE_DONE) {
            GGL_LOGT(
                "id not found for key %d in %s",
                (int) i,
                print_key_path(key_path)
            );
            return GGL_ERR_NOENTRY;
        }
        if (rc != SQLITE_ROW) {
            GGL_LOGE(
                "get key id for key %d in %s fail: %s",
                (int) i,
                print_key_path(key_path),
                sqlite3_errmsg(config_database)
            );
            return GGL_ERR_FAILURE;
        }
        int64_t id = sqlite3_column_int(find_element_stmt, 0);
        GGL_LOGT(
            "found id for key %d in %s: %" PRId64,
            (int) i,
            print_key_path(key_path),
            id
        );
        GglError ret = ggl_obj_vec_push(key_ids_output, ggl_obj_i64(id));
        assert(ret == GGL_ERR_OK);
    }

    return GGL_ERR_OK;
}

// create_key_path assumes that the entire key_path does not already exist in
// the database (i.e. at least one key needs to be created). Behavior is
// undefined if the key_path fully exists already. Thus it should only be used
// within a transaction and after checking that the key_path does not fully
// exist.
// key_ids_output must point to an empty GglObjVec with capacity
// MAX_KEY_PATH_DEPTH
static GglError create_key_path(GglList *key_path, GglObjVec *key_ids_output) {
    GglBuffer root_key_buffer = ggl_obj_into_buf(key_path->items[0]);
    int64_t parent_key_id;
    GglError err = get_or_create_key_at_root(&root_key_buffer, &parent_key_id);
    if (err != GGL_ERR_OK) {
        return err;
    }
    err = ggl_obj_vec_push(key_ids_output, ggl_obj_i64(parent_key_id));
    assert(err == GGL_ERR_OK);
    bool value_is_present_for_root_key;
    err = value_is_present_for_key(
        parent_key_id, &value_is_present_for_root_key
    );
    if (err != GGL_ERR_OK) {
        GGL_LOGE(
            "failed to check for value for root key %.*s with id %" PRId64
            " with error %s",
            (int) root_key_buffer.len,
            root_key_buffer.data,
            parent_key_id,
            ggl_strerror(err)
        );
        return err;
    }
    if (value_is_present_for_root_key) {
        GGL_LOGW(
            "value already present for root key %.*s with id %" PRId64
            ". Failing request.",
            (int) root_key_buffer.len,
            root_key_buffer.data,
            parent_key_id
        );
        return GGL_ERR_FAILURE;
    }

    int64_t current_key_id = parent_key_id;
    for (size_t index = 1; index < key_path->len; index++) {
        GglBuffer current_key_buffer = ggl_obj_into_buf(key_path->items[index]);
        err = find_key_with_parent(
            &current_key_buffer, parent_key_id, &current_key_id
        );
        if (err == GGL_ERR_NOENTRY) {
            err = key_insert(&current_key_buffer, &current_key_id);
            if (err != GGL_ERR_OK) {
                return err;
            }
            err = relation_insert(current_key_id, parent_key_id);
            if (err != GGL_ERR_OK) {
                return err;
            }
        } else if (err == GGL_ERR_OK) { // the key exists and we got the id
            bool value_is_present;
            err = value_is_present_for_key(current_key_id, &value_is_present);
            if (err != GGL_ERR_OK) {
                GGL_LOGE(
                    "failed to check for value for key %d (%.*s) in key path "
                    "%s with id %" PRId64 " with error %s",
                    (int) index,
                    (int) current_key_buffer.len,
                    current_key_buffer.data,
                    print_key_path(key_path),
                    current_key_id,
                    ggl_strerror(err)
                );
                return err;
            }
            if (value_is_present) {
                GGL_LOGW(
                    "value already present for key %d (%.*s) in key path %s "
                    "with id %" PRId64 ". Failing request.",
                    (int) index,
                    (int) current_key_buffer.len,
                    current_key_buffer.data,
                    print_key_path(key_path),
                    current_key_id
                );
                return GGL_ERR_FAILURE;
            }
        } else {
            return err;
        }
        err = ggl_obj_vec_push(key_ids_output, ggl_obj_i64(current_key_id));
        assert(err == GGL_ERR_OK);
        parent_key_id = current_key_id;
    }
    return GGL_ERR_OK;
}

static GglError child_is_present_for_key(
    int64_t key_id, bool *child_is_present_output
) {
    GglError return_err = GGL_ERR_FAILURE;

    sqlite3_stmt *child_check_stmt;
    sqlite3_prepare_v2(
        config_database, GGL_SQL_HAS_CHILD, -1, &child_check_stmt, NULL
    );
    GGL_CLEANUP(cleanup_sqlite3_finalize, child_check_stmt);
    sqlite3_bind_int64(child_check_stmt, 1, key_id);
    int rc = sqlite3_step(child_check_stmt);
    if (rc == SQLITE_ROW) {
        *child_is_present_output = true;
        return_err = GGL_ERR_OK;
    } else if (rc == SQLITE_DONE) {
        *child_is_present_output = false;
        return_err = GGL_ERR_OK;
    } else {
        GGL_LOGE("child check fail : %s", sqlite3_errmsg(config_database));
        return_err = GGL_ERR_FAILURE;
    }
    return return_err;
}

static GglError notify_single_key(
    int64_t notify_key_id, GglList *changed_key_path
) {
    // TODO: read this comment copied from the JAVA and ensure this implements a
    // similar functionality A subscriber is told what Topic changed, but must
    // look in the Topic to get the new value.  There is no "old value"
    // provided, although the publish framework endeavors to suppress notifying
    // when the new value is the same as the old value. Subscribers do not
    // necessarily get notified on every change.  If a sequence of changes
    // happen in rapid succession, they may be collapsed into one notification.
    // This usually happens when a compound change occurs.

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(
        config_database, GGL_SQL_GET_SUBSCRIBERS, -1, &stmt, NULL
    );
    GGL_CLEANUP(cleanup_sqlite3_finalize, stmt);
    sqlite3_bind_int64(stmt, 1, notify_key_id);
    int rc = 0;
    GGL_LOGT(
        "notifying subscribers on key with id %" PRId64
        " that key %s has changed",
        notify_key_id,
        print_key_path(changed_key_path)
    );
    do {
        rc = sqlite3_step(stmt);
        switch (rc) {
        case SQLITE_DONE:
            GGL_LOGT("DONE");
            break;
        case SQLITE_ROW: {
            uint32_t handle = (uint32_t) sqlite3_column_int64(stmt, 0);
            GGL_LOGT("Sending to %u", handle);
            ggl_sub_respond(handle, ggl_obj_list(*changed_key_path));
        } break;
        default:
            GGL_LOGE(
                "Unexpected rc %d while getting handles to notify for key with "
                "id %" PRId64 " with error: %s",
                rc,
                notify_key_id,
                sqlite3_errmsg(config_database)
            );
            return GGL_ERR_FAILURE;
            break;
        }
    } while (rc == SQLITE_ROW);

    return GGL_ERR_OK;
}

// Given a key path and the ids of the keys in that path, notify each key along
// the path that the value at the tip of the key path has changed
static GglError notify_nested_key(GglList *key_path, GglObjVec key_ids) {
    for (size_t i = 0; i < key_ids.list.len; i++) {
        GglError ret = notify_single_key(
            ggl_obj_into_i64(key_ids.list.items[i]), key_path
        );
        if (ret != GGL_ERR_OK) {
            return ret;
        }
    }
    return GGL_ERR_OK;
}

GglError ggconfig_write_empty_map(GglList *key_path) {
    if (config_initialized == false) {
        GGL_LOGE("Database not initialized");
        return GGL_ERR_FAILURE;
    }

    sqlite3_exec(config_database, "BEGIN TRANSACTION", NULL, NULL, NULL);
    GGL_LOGT(
        "Starting transaction to write an empty map to key %s",
        print_key_path(key_path)
    );

    GglObject ids_array[GGL_MAX_OBJECT_DEPTH];
    GglObjVec ids = { .list = { .items = ids_array, .len = 0 },
                      .capacity = GGL_MAX_OBJECT_DEPTH };
    int64_t last_key_id;
    GglError err = get_key_ids(key_path, &ids);
    if (err == GGL_ERR_NOENTRY) {
        ids.list.len = 0; // Reset the ids vector to be populated fresh
        err = create_key_path(key_path, &ids);
        if (err != GGL_ERR_OK) {
            sqlite3_exec(config_database, "ROLLBACK", NULL, NULL, NULL);
            return err;
        }
        sqlite3_exec(config_database, "END TRANSACTION", NULL, NULL, NULL);
        return GGL_ERR_OK;
    }
    if (err != GGL_ERR_OK) {
        GGL_LOGE(
            "Failed to get key ids for key path %s with error %s",
            print_key_path(key_path),
            ggl_strerror(err)
        );
        sqlite3_exec(config_database, "ROLLBACK", NULL, NULL, NULL);
        return err;
    }

    last_key_id = ggl_obj_into_i64(ids.list.items[ids.list.len - 1]);

    bool value_is_present;
    err = value_is_present_for_key(last_key_id, &value_is_present);
    if (err != GGL_ERR_OK) {
        sqlite3_exec(config_database, "ROLLBACK", NULL, NULL, NULL);
        return err;
    }
    if (value_is_present) {
        GGL_LOGW(
            "Value already present for key %s with id %" PRId64
            ", so an empty map can not be merged. Failing request.",
            print_key_path(key_path),
            last_key_id
        );
        sqlite3_exec(config_database, "ROLLBACK", NULL, NULL, NULL);
        return GGL_ERR_FAILURE;
    }

    sqlite3_exec(config_database, "END TRANSACTION", NULL, NULL, NULL);
    return GGL_ERR_OK;
}

GglError ggconfig_write_value_at_key(
    GglList *key_path, GglBuffer *value, int64_t timestamp
) {
    if (config_initialized == false) {
        GGL_LOGE("Database not initialized");
        return GGL_ERR_FAILURE;
    }

    sqlite3_exec(config_database, "BEGIN TRANSACTION", NULL, NULL, NULL);
    GGL_LOGT(
        "starting transaction to insert/update key: %s",
        print_key_path(key_path)
    );

    GglObject ids_array[GGL_MAX_OBJECT_DEPTH];
    GglObjVec ids = { .list = { .items = ids_array, .len = 0 },
                      .capacity = GGL_MAX_OBJECT_DEPTH };
    int64_t last_key_id;
    GglError err = get_key_ids(key_path, &ids);
    if (err == GGL_ERR_NOENTRY) {
        ids.list.len = 0; // Reset the ids vector to be populated fresh
        err = create_key_path(key_path, &ids);
        if (err != GGL_ERR_OK) {
            sqlite3_exec(config_database, "ROLLBACK", NULL, NULL, NULL);
            return err;
        }

        last_key_id = ggl_obj_into_i64(ids.list.items[ids.list.len - 1]);
        err = value_insert(last_key_id, value, timestamp);
        if (err != GGL_ERR_OK) {
            sqlite3_exec(config_database, "ROLLBACK", NULL, NULL, NULL);
            return err;
        }
        sqlite3_exec(config_database, "END TRANSACTION", NULL, NULL, NULL);
        err = notify_nested_key(key_path, ids);
        if (err != GGL_ERR_OK) {
            GGL_LOGE(
                "Failed to notify all subscribers about update for key path %s "
                "with error %s",
                print_key_path(key_path),
                ggl_strerror(err)
            );
        }
        return GGL_ERR_OK;
    }
    if (err != GGL_ERR_OK) {
        GGL_LOGE(
            "Failed to get key ids for key path %s with error %s",
            print_key_path(key_path),
            ggl_strerror(err)
        );
        sqlite3_exec(config_database, "ROLLBACK", NULL, NULL, NULL);
        return err;
    }
    last_key_id = ggl_obj_into_i64(ids.list.items[ids.list.len - 1]);
    bool child_is_present;
    err = child_is_present_for_key(last_key_id, &child_is_present);
    if (err != GGL_ERR_OK) {
        GGL_LOGE(
            "Failed to check for child presence for key %s with id %" PRId64
            " with error %s",
            print_key_path(key_path),
            last_key_id,
            ggl_strerror(err)
        );
        sqlite3_exec(config_database, "ROLLBACK", NULL, NULL, NULL);
        return err;
    }
    if (child_is_present) {
        GGL_LOGW(
            "Key %s with id %" PRId64
            " is an object with one or more children, so "
            "it can not also store a value. Failing request.",
            print_key_path(key_path),
            last_key_id
        );
        sqlite3_exec(config_database, "ROLLBACK", NULL, NULL, NULL);
        return GGL_ERR_FAILURE;
    }

    bool value_is_present;
    err = value_is_present_for_key(last_key_id, &value_is_present);
    if (err != GGL_ERR_OK) {
        sqlite3_exec(config_database, "ROLLBACK", NULL, NULL, NULL);
        return err;
    }
    if (!value_is_present) {
        GGL_LOGW(
            "Key %s with id %" PRId64 " is an empty map, so it can not have a "
            "value written to it. Failing request.",
            print_key_path(key_path),
            last_key_id
        );
        sqlite3_exec(config_database, "ROLLBACK", NULL, NULL, NULL);
        return GGL_ERR_FAILURE;
    }

    int64_t existing_timestamp;
    err = value_get_timestamp(last_key_id, &existing_timestamp);
    if (err != GGL_ERR_OK) {
        GGL_LOGE(
            "failed to get timestamp for key %s with id %" PRId64
            " with error %s",
            print_key_path(key_path),
            last_key_id,
            ggl_strerror(err)
        );
        sqlite3_exec(config_database, "ROLLBACK", NULL, NULL, NULL);
        return err;
    }
    if (existing_timestamp > timestamp) {
        GGL_LOGD(
            "key %s has an existing timestamp %" PRId64 " newer than provided "
            "timestamp %" PRId64 ", so it will not be updated",
            print_key_path(key_path),
            existing_timestamp,
            timestamp
        );
        sqlite3_exec(config_database, "END TRANSACTION", NULL, NULL, NULL);
        return GGL_ERR_OK;
    }

    err = value_update(last_key_id, value, timestamp);
    if (err != GGL_ERR_OK) {
        GGL_LOGE(
            "failed to update value for key %s with id %" PRId64
            " with error %s",
            print_key_path(key_path),
            last_key_id,
            ggl_strerror(err)
        );
        sqlite3_exec(config_database, "ROLLBACK", NULL, NULL, NULL);
        return err;
    }
    sqlite3_exec(config_database, "END TRANSACTION", NULL, NULL, NULL);

    err = notify_nested_key(key_path, ids);
    if (err != GGL_ERR_OK) {
        GGL_LOGE(
            "failed to notify subscribers about update for key path %s with "
            "error %s",
            print_key_path(key_path),
            ggl_strerror(err)
        );
    }
    return GGL_ERR_OK;
}

static GglError read_value_at_key(
    int64_t key_id, GglObject *value, GglArena *alloc
) {
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(config_database, GGL_SQL_READ_VALUE, -1, &stmt, NULL);
    GGL_CLEANUP(cleanup_sqlite3_finalize, stmt);
    sqlite3_bind_int64(stmt, 1, key_id);
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        GGL_LOGI("no value found for key id %" PRId64, key_id);
        return GGL_ERR_NOENTRY;
    }
    if (rc != SQLITE_ROW) {
        GGL_LOGE(
            "failed to read value for key id %" PRId64
            " with rc %d and error %s",
            key_id,
            rc,
            sqlite3_errmsg(config_database)
        );
        return GGL_ERR_FAILURE;
    }
    const uint8_t *value_string = sqlite3_column_text(stmt, 0);
    unsigned long value_length = (unsigned long) sqlite3_column_bytes(stmt, 0);
    uint8_t *string_buffer = GGL_ARENA_ALLOCN(alloc, uint8_t, value_length);
    if (!string_buffer) {
        GGL_LOGE(
            "no more memory to allocate value for key id %" PRId64, key_id
        );
        return GGL_ERR_NOMEM;
    }
    memcpy(string_buffer, value_string, value_length);
    *value = ggl_obj_buf((GglBuffer) { .data = string_buffer,
                                       .len = value_length });
    return GGL_ERR_OK;
}

/// read_key_recursive will read the map or buffer at key_id and store it into
/// value.
// NOLINTNEXTLINE(misc-no-recursion)
static GglError read_key_recursive(
    int64_t key_id, GglObject *value, GglArena *alloc
) {
    GGL_LOGT("reading key id %" PRId64, key_id);

    bool value_is_present;
    GglError ret = value_is_present_for_key(key_id, &value_is_present);
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    if (value_is_present) {
        ret = read_value_at_key(key_id, value, alloc);
        GGL_LOGT(
            "value read: %.*s from key id %" PRId64,
            (int) ggl_obj_into_buf(*value).len,
            (char *) ggl_obj_into_buf(*value).data,
            key_id
        );
        return ret;
    }

    // at this point we know the key should be a map, because it's not a value
    sqlite3_stmt *read_children_stmt;
    sqlite3_prepare_v2(
        config_database, GGL_SQL_GET_CHILDREN, -1, &read_children_stmt, NULL
    );
    GGL_CLEANUP(cleanup_sqlite3_finalize, read_children_stmt);
    sqlite3_bind_int64(read_children_stmt, 1, key_id);

    // read children count
    size_t children_count = 0;
    int rc = sqlite3_step(read_children_stmt);
    while (rc == SQLITE_ROW) {
        children_count++;
        rc = sqlite3_step(read_children_stmt);
    }
    if (rc != SQLITE_DONE) {
        GGL_LOGE(
            "failed to read children count for key id %" PRId64
            " with rc %d and error %s",
            key_id,
            rc,
            sqlite3_errmsg(config_database)
        );
        return GGL_ERR_FAILURE;
    }
    GGL_LOGT(
        "the number of children keys for key id %" PRId64 " is %zd",
        key_id,
        children_count
    );
    if (children_count == 0) {
        *value = ggl_obj_map((GglMap) { 0 });
        GGL_LOGT("value read: empty map for key id %" PRId64, key_id);
        return GGL_ERR_OK;
    }

    // create the kvs for the children
    GglKV *kv_buffer = GGL_ARENA_ALLOCN(alloc, GglKV, children_count);
    if (!kv_buffer) {
        GGL_LOGE("no more memory to allocate kvs for key id %" PRId64, key_id);
        return GGL_ERR_NOMEM;
    }
    GglKVVec kv_buffer_vec = { .map = (GglMap) { .pairs = kv_buffer, .len = 0 },
                               .capacity = children_count };

    // read the children
    sqlite3_reset(read_children_stmt);
    rc = sqlite3_step(read_children_stmt);
    while (rc == SQLITE_ROW) {
        int64_t child_key_id = sqlite3_column_int64(read_children_stmt, 0);
        const uint8_t *child_key_name
            = sqlite3_column_text(read_children_stmt, 1);
        unsigned long child_key_name_length
            = (unsigned long) sqlite3_column_bytes(read_children_stmt, 1);
        uint8_t *child_key_name_memory
            = GGL_ARENA_ALLOCN(alloc, uint8_t, child_key_name_length);
        if (!child_key_name_memory) {
            GGL_LOGE(
                "no more memory to allocate value for key id %" PRId64, key_id
            );
            return GGL_ERR_NOMEM;
        }
        memcpy(child_key_name_memory, child_key_name, child_key_name_length);

        GglBuffer child_key_name_buffer
            = { .data = child_key_name_memory, .len = child_key_name_length };
        GglKV child_kv = ggl_kv(child_key_name_buffer, GGL_OBJ_NULL);

        ret = read_key_recursive(child_key_id, ggl_kv_val(&child_kv), alloc);
        if (ret != GGL_ERR_OK) {
            return ret;
        }

        ret = ggl_kv_vec_push(&kv_buffer_vec, child_kv);
        if (ret != GGL_ERR_OK) {
            GGL_LOGE("error pushing kv with error %s", ggl_strerror(ret));
            return ret;
        }

        rc = sqlite3_step(read_children_stmt);
    }
    if (rc != SQLITE_DONE) {
        GGL_LOGE(
            "failed to read children for key id %" PRId64
            " with rc %d and error %s",
            key_id,
            rc,
            sqlite3_errmsg(config_database)
        );
        return GGL_ERR_FAILURE;
    }

    *value = ggl_obj_map(kv_buffer_vec.map);
    return GGL_ERR_OK;
}

GglError ggconfig_get_value_from_key(GglList *key_path, GglObject *value) {
    if (config_initialized == false) {
        GGL_LOGE("Database not initialized.");
        return GGL_ERR_FAILURE;
    }

    static uint8_t key_value_memory[GGL_COREBUS_MAX_MSG_LEN];
    GglArena alloc = ggl_arena_init(GGL_BUF(key_value_memory));

    sqlite3_exec(config_database, "BEGIN TRANSACTION", NULL, NULL, NULL);
    GGL_LOGT("Starting transaction to read key: %s", print_key_path(key_path));

    GglObject ids_array[GGL_MAX_OBJECT_DEPTH];
    GglObjVec ids = { .list = { .items = ids_array, .len = 0 },
                      .capacity = GGL_MAX_OBJECT_DEPTH };
    GglError err = get_key_ids(key_path, &ids);
    if (err == GGL_ERR_NOENTRY) {
        sqlite3_exec(config_database, "END TRANSACTION", NULL, NULL, NULL);
        return GGL_ERR_NOENTRY;
    }
    if (err != GGL_ERR_OK) {
        sqlite3_exec(config_database, "END TRANSACTION", NULL, NULL, NULL);
        return err;
    }
    int64_t key_id = ggl_obj_into_i64(ids.list.items[ids.list.len - 1]);
    err = read_key_recursive(key_id, value, &alloc);
    sqlite3_exec(config_database, "END TRANSACTION", NULL, NULL, NULL);
    return err;
}

static GglError get_children(
    int64_t key_id, GglObjVec *children_ids_output, GglArena *alloc
) {
    GGL_LOGT("Getting children for id %" PRId64, key_id);

    sqlite3_stmt *read_children_stmt;
    sqlite3_prepare_v2(
        config_database, GGL_SQL_GET_CHILDREN, -1, &read_children_stmt, NULL
    );
    GGL_CLEANUP(cleanup_sqlite3_finalize, read_children_stmt);
    sqlite3_bind_int64(read_children_stmt, 1, key_id);

    int rc = sqlite3_step(read_children_stmt);
    while (rc == SQLITE_ROW) {
        const uint8_t *child_key_name
            = sqlite3_column_text(read_children_stmt, 1);
        unsigned long child_key_name_length
            = (unsigned long) sqlite3_column_bytes(read_children_stmt, 1);

        GGL_LOGT("Found child.");
        uint8_t *child_key_name_memory
            = GGL_ARENA_ALLOCN(alloc, uint8_t, child_key_name_length);
        if (!child_key_name_memory) {
            GGL_LOGE("No more memory to allocate while reading children keys.");
            return GGL_ERR_NOMEM;
        }

        memcpy(child_key_name_memory, child_key_name, child_key_name_length);

        GglError err = ggl_obj_vec_push(
            children_ids_output,
            ggl_obj_buf((GglBuffer) { .data = child_key_name_memory,
                                      .len = child_key_name_length })
        );
        if (err != GGL_ERR_OK) {
            GGL_LOGE("Not enough memory to push a child into the output vector."
            );
            return err;
        }
        rc = sqlite3_step(read_children_stmt);
    }
    if (rc != SQLITE_DONE) {
        GGL_LOGE(
            "Get children for key id %" PRId64
            " failed with rc: %d and msg: %s",
            key_id,
            rc,
            sqlite3_errmsg(config_database)
        );
        return GGL_ERR_FAILURE;
    }
    return GGL_ERR_OK;
}

GglError ggconfig_list_subkeys(GglList *key_path, GglList *subkeys) {
    if (config_initialized == false) {
        GGL_LOGE("Database not initialized.");
        return GGL_ERR_FAILURE;
    }

    sqlite3_exec(config_database, "BEGIN TRANSACTION", NULL, NULL, NULL);
    GGL_LOGT(
        "Starting transaction to read subkeys for key: %s",
        print_key_path(key_path)
    );

    GglObject ids_array[GGL_MAX_OBJECT_DEPTH];
    GglObjVec ids = { .list = { .items = ids_array, .len = 0 },
                      .capacity = GGL_MAX_OBJECT_DEPTH };
    GglError err = get_key_ids(key_path, &ids);
    if (err == GGL_ERR_NOENTRY) {
        sqlite3_exec(config_database, "END TRANSACTION", NULL, NULL, NULL);
        return GGL_ERR_NOENTRY;
    }
    if (err != GGL_ERR_OK) {
        sqlite3_exec(config_database, "END TRANSACTION", NULL, NULL, NULL);
        return err;
    }
    int64_t key_id = ggl_obj_into_i64(ids.list.items[ids.list.len - 1]);

    bool value_is_present;
    err = value_is_present_for_key(key_id, &value_is_present);
    if (err != GGL_ERR_OK) {
        sqlite3_exec(config_database, "END TRANSACTION", NULL, NULL, NULL);
        return err;
    }
    if (value_is_present) {
        GGL_LOGW(
            "Key %s is a value, not a map, so subkeys/children can not be "
            "listed.",
            print_key_path(key_path)
        );
        sqlite3_exec(config_database, "END TRANSACTION", NULL, NULL, NULL);
        return GGL_ERR_INVALID;
    }

    static GglObject children_ids_array[MAX_CONFIG_CHILDREN_PER_OBJECT];
    GglObjVec children_ids
        = { .list = { .items = children_ids_array, .len = 0 },
            .capacity = MAX_CONFIG_CHILDREN_PER_OBJECT };

    static uint8_t key_buffers_memory[GGL_COREBUS_MAX_MSG_LEN]; // TODO: can we
                                                                // shrink this?
    GglArena alloc = ggl_arena_init(GGL_BUF(key_buffers_memory));
    err = get_children(key_id, &children_ids, &alloc);
    if (err != GGL_ERR_OK) {
        sqlite3_exec(config_database, "END TRANSACTION", NULL, NULL, NULL);
        return err;
    }

    sqlite3_exec(config_database, "END TRANSACTION", NULL, NULL, NULL);
    subkeys->items = children_ids.list.items;
    subkeys->len = children_ids.list.len;
    return GGL_ERR_OK;
}

/// read all the descendants of key_id, including key_id itself as a descendant
static GglError get_descendants(
    int64_t key_id, GglObjVec *descendant_ids_output
) {
    GGL_LOGT("getting descendants for id %" PRId64, key_id);
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(
        config_database, GGL_SQL_GET_DESCENDANTS, -1, &stmt, NULL
    );
    GGL_CLEANUP(cleanup_sqlite3_finalize, stmt);
    sqlite3_bind_int64(stmt, 1, key_id);
    sqlite3_bind_int64(stmt, 2, key_id);

    int rc = sqlite3_step(stmt);
    while (rc == SQLITE_ROW) {
        int64_t id = sqlite3_column_int64(stmt, 0);
        GGL_LOGT("found descendant id %" PRId64, id);
        GglError err = ggl_obj_vec_push(descendant_ids_output, ggl_obj_i64(id));
        if (err != GGL_ERR_OK) {
            GGL_LOGE(
                "Not enough memory to push a descendant into the output vector."
            );
            return err;
        }
        rc = sqlite3_step(stmt);
    }
    if (rc != SQLITE_DONE) {
        GGL_LOGE(
            "get descendants for key id %" PRId64 " fail: %s",
            key_id,
            sqlite3_errmsg(config_database)
        );
        return GGL_ERR_FAILURE;
    }
    return GGL_ERR_OK;
}

static GglError delete_value(int64_t key_id) {
    GGL_LOGT("Deleting key id %" PRId64 " from the value table", key_id);
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(config_database, GGL_SQL_DELETE_VALUE, -1, &stmt, NULL);
    GGL_CLEANUP(cleanup_sqlite3_finalize, stmt);
    sqlite3_bind_int64(stmt, 1, key_id);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        GGL_LOGE(
            "delete value for key id %" PRId64 " fail: %s",
            key_id,
            sqlite3_errmsg(config_database)
        );
        return GGL_ERR_FAILURE;
    }
    return GGL_ERR_OK;
}

static GglError delete_relations(int64_t key_id) {
    GGL_LOGT(
        "Deleting all entries referencing key id %" PRId64
        " from the relation table",
        key_id
    );
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(
        config_database, GGL_SQL_DELETE_RELATIONS, -1, &stmt, NULL
    );
    GGL_CLEANUP(cleanup_sqlite3_finalize, stmt);
    sqlite3_bind_int64(stmt, 1, key_id);
    sqlite3_bind_int64(stmt, 2, key_id);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        GGL_LOGE(
            "delete relations for key id %" PRId64 " fail: %s",
            key_id,
            sqlite3_errmsg(config_database)
        );
        return GGL_ERR_FAILURE;
    }
    return GGL_ERR_OK;
}

static GglError delete_subscribers(int64_t key_id) {
    GGL_LOGT("Deleting key id %" PRId64 " from the subscribers table", key_id);
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(
        config_database, GGL_SQL_DELETE_SUBSCRIBERS, -1, &stmt, NULL
    );
    GGL_CLEANUP(cleanup_sqlite3_finalize, stmt);
    sqlite3_bind_int64(stmt, 1, key_id);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        GGL_LOGE(
            "delete subscribers on keyid %" PRId64 " fail: %s",
            key_id,
            sqlite3_errmsg(config_database)
        );
        return GGL_ERR_FAILURE;
    }
    return GGL_ERR_OK;
}

static GglError delete_key(int64_t key_id) {
    GGL_LOGT("Deleting key id %" PRId64 " from the key table", key_id);
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(config_database, GGL_SQL_DELETE_KEY, -1, &stmt, NULL);
    GGL_CLEANUP(cleanup_sqlite3_finalize, stmt);
    sqlite3_bind_int64(stmt, 1, key_id);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        GGL_LOGE(
            "delete key id %" PRId64 " fail: %s",
            key_id,
            sqlite3_errmsg(config_database)
        );
        return GGL_ERR_FAILURE;
    }
    return GGL_ERR_OK;
}

GglError ggconfig_delete_key(GglList *key_path) {
    if (config_initialized == false) {
        GGL_LOGE("Database not initialized.");
        return GGL_ERR_FAILURE;
    }

    sqlite3_exec(config_database, "BEGIN TRANSACTION", NULL, NULL, NULL);
    GGL_LOGT("Starting transaction to delete key %s", print_key_path(key_path));

    GglObject ids_array[GGL_MAX_OBJECT_DEPTH];
    GglObjVec ids = { .list = { .items = ids_array, .len = 0 },
                      .capacity = GGL_MAX_OBJECT_DEPTH };
    GglError err = get_key_ids(key_path, &ids);
    if (err == GGL_ERR_NOENTRY) {
        sqlite3_exec(config_database, "END TRANSACTION", NULL, NULL, NULL);
        GGL_LOGT(
            "Key %s does not exist, nothing to do", print_key_path(key_path)
        );
        return GGL_ERR_OK;
    }
    if (err != GGL_ERR_OK) {
        sqlite3_exec(config_database, "ROLLBACK", NULL, NULL, NULL);
        return err;
    }
    int64_t key_id = ggl_obj_into_i64(ids.list.items[ids.list.len - 1]);

    GglObject descendant_ids_array
        [MAX_CONFIG_DESCENDANTS_PER_COMPONENT]; // Deletes are recursive, so
                                                // worst case, a user is
                                                // resetting their entire
                                                // component configuration
    GglObjVec descendant_ids
        = { .list = { .items = descendant_ids_array, .len = 0 },
            .capacity = MAX_CONFIG_DESCENDANTS_PER_COMPONENT };
    err = get_descendants(key_id, &descendant_ids);
    if (err != GGL_ERR_OK) {
        sqlite3_exec(config_database, "ROLLBACK", NULL, NULL, NULL);
        return err;
    }

    for (size_t i = 0; i < descendant_ids.list.len; i++) {
        int64_t descendant_id = ggl_obj_into_i64(descendant_ids.list.items[i]);
        err = delete_subscribers(descendant_id);
        if (err != GGL_ERR_OK) {
            GGL_LOGE(
                "Failed to delete subscribers for id %" PRId64
                " with error %s. This should not happen, but keyids are not "
                "reused and thus "
                "any subscriptions on this key will not be activated anymore, "
                "so execution can continue.",
                descendant_id,
                ggl_strerror(err)
            );
        }
        err = delete_value(descendant_id);
        if (err != GGL_ERR_OK) {
            sqlite3_exec(config_database, "ROLLBACK", NULL, NULL, NULL);
            return err;
        }
        err = delete_relations(descendant_id);
        if (err != GGL_ERR_OK) {
            sqlite3_exec(config_database, "ROLLBACK", NULL, NULL, NULL);
            return err;
        }
        err = delete_key(descendant_id);
        if (err != GGL_ERR_OK) {
            sqlite3_exec(config_database, "ROLLBACK", NULL, NULL, NULL);
            return err;
        }
    }

    sqlite3_exec(config_database, "END TRANSACTION", NULL, NULL, NULL);
    return GGL_ERR_OK;
}

GglError ggconfig_get_key_notification(GglList *key_path, uint32_t handle) {
    GglError return_err = GGL_ERR_FAILURE;

    if (config_initialized == false) {
        GGL_LOGE("Database not initialized");
        return GGL_ERR_FAILURE;
    }

    sqlite3_exec(config_database, "BEGIN TRANSACTION", NULL, NULL, NULL);
    GGL_LOGT(
        "Starting transaction to subscribe to key %s", print_key_path(key_path)
    );

    // ensure this key is present in the key path. Key does not require a
    // value
    GglObject ids_array[GGL_MAX_OBJECT_DEPTH];
    GglObjVec ids = { .list = { .items = ids_array, .len = 0 },
                      .capacity = GGL_MAX_OBJECT_DEPTH };
    GglError err = get_key_ids(key_path, &ids);
    if (err == GGL_ERR_NOENTRY) {
        sqlite3_exec(config_database, "ROLLBACK", NULL, NULL, NULL);
        return GGL_ERR_NOENTRY;
    }
    if (err != GGL_ERR_OK) {
        sqlite3_exec(config_database, "ROLLBACK", NULL, NULL, NULL);
        return err;
    }
    int64_t key_id = ggl_obj_into_i64(ids.list.items[ids.list.len - 1]);

    // insert the key & handle data into the subscriber database
    GGL_LOGT("INSERT %" PRId64 ", %" PRIu32, key_id, handle);
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(
        config_database, GGL_SQL_ADD_SUBSCRIPTION, -1, &stmt, NULL
    );
    GGL_CLEANUP(cleanup_sqlite3_finalize, stmt);
    sqlite3_bind_int64(stmt, 1, key_id);
    sqlite3_bind_int64(stmt, 2, handle);
    int rc = sqlite3_step(stmt);
    sqlite3_exec(config_database, "END TRANSACTION", NULL, NULL, NULL);
    if (SQLITE_DONE != rc) {
        GGL_LOGE("%d %s", rc, sqlite3_errmsg(config_database));
    } else {
        GGL_LOGT("Success");
        return_err = GGL_ERR_OK;
    }

    return return_err;
}

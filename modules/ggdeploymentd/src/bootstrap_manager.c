// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "bootstrap_manager.h"
#include "deployment_model.h"
#include "deployment_queue.h"
#include "stale_component.h"
#include <assert.h>
#include <fcntl.h>
#include <ggl/arena.h>
#include <ggl/buffer.h>
#include <ggl/core_bus/gg_config.h>
#include <ggl/error.h>
#include <ggl/file.h>
#include <ggl/flags.h>
#include <ggl/log.h>
#include <ggl/map.h>
#include <ggl/object.h>
#include <ggl/vector.h>
#include <inttypes.h>
#include <limits.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

bool component_bootstrap_phase_completed(GglBuffer component_name) {
    // check config to see if component bootstrap steps have already been
    // completed
    uint8_t resp_mem[128] = { 0 };
    GglArena alloc = ggl_arena_init(GGL_BUF(resp_mem));
    GglBuffer resp;
    GglError ret = ggl_gg_config_read_str(
        GGL_BUF_LIST(
            GGL_STR("services"),
            GGL_STR("DeploymentService"),
            GGL_STR("deploymentState"),
            GGL_STR("bootstrapComponents"),
            component_name
        ),
        &alloc,
        &resp
    );
    if (ret == GGL_ERR_OK) {
        GGL_LOGD(
            "Bootstrap steps have already been run for %.*s.",
            (int) component_name.len,
            component_name.data
        );
        return true;
    }
    return false;
}

GglError save_component_info(
    GglBuffer component_name, GglBuffer component_version, GglBuffer type
) {
    GGL_LOGD(
        "Saving component name and version for %.*s as type %.*s to the config "
        "to track "
        "deployment state.",
        (int) component_name.len,
        component_name.data,
        (int) type.len,
        type.data
    );

    if (ggl_buffer_eq(type, GGL_STR("completed"))) {
        GglError ret = ggl_gg_config_write(
            GGL_BUF_LIST(
                GGL_STR("services"),
                GGL_STR("DeploymentService"),
                GGL_STR("deploymentState"),
                GGL_STR("components"),
                component_name
            ),
            ggl_obj_buf(component_version),
            &(int64_t) { 3 }
        );
        if (ret != GGL_ERR_OK) {
            GGL_LOGE(
                "Failed to write component info for %.*s to config.",
                (int) component_name.len,
                component_name.data
            );
            return ret;
        }
    } else if (ggl_buffer_eq(type, GGL_STR("bootstrap"))) {
        GglError ret = ggl_gg_config_write(
            GGL_BUF_LIST(
                GGL_STR("services"),
                GGL_STR("DeploymentService"),
                GGL_STR("deploymentState"),
                GGL_STR("bootstrapComponents"),
                component_name
            ),
            ggl_obj_buf(component_version),
            &(int64_t) { 3 }
        );
        if (ret != GGL_ERR_OK) {
            GGL_LOGE(
                "Failed to write component info for %.*s to config.",
                (int) component_name.len,
                component_name.data
            );
            return ret;
        }
    } else {
        GGL_LOGE(
            "Invalid component type of %.*s received. Expected type "
            "'bootstrap' or 'completed'.",
            (int) type.len,
            type.data
        );
        return GGL_ERR_INVALID;
    }

    return GGL_ERR_OK;
}

GglError save_iot_jobs_id(GglBuffer jobs_id) {
    GGL_LOGD(
        "Saving IoT Jobs ID %.*s in case of bootstrap.",
        (int) jobs_id.len,
        jobs_id.data
    );

    GglError ret = ggl_gg_config_write(
        GGL_BUF_LIST(
            GGL_STR("services"),
            GGL_STR("DeploymentService"),
            GGL_STR("deploymentState"),
            GGL_STR("jobsID")
        ),
        ggl_obj_buf(jobs_id),
        &(int64_t) { 3 }
    );
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to write IoT Jobs ID to config.");
        return ret;
    }
    return GGL_ERR_OK;
}

GglError save_iot_jobs_version(int64_t jobs_version) {
    GGL_LOGD(
        "Saving IoT Jobs version %" PRIi64 " in case of bootstrap.",
        jobs_version
    );

    GglError ret = ggl_gg_config_write(
        GGL_BUF_LIST(
            GGL_STR("services"),
            GGL_STR("DeploymentService"),
            GGL_STR("deploymentState"),
            GGL_STR("jobsVersion")
        ),
        ggl_obj_i64(jobs_version),
        &(int64_t) { 3 }
    );
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to write IoT Jobs Version to config.");
        return ret;
    }
    return GGL_ERR_OK;
}

GglError save_deployment_info(GglDeployment *deployment) {
    GGL_LOGD("Encountered component requiring bootstrap. Saving deployment "
             "state to config.");

    GglObject deployment_doc = ggl_obj_map(GGL_MAP(
        ggl_kv(
            GGL_STR("deployment_id"), ggl_obj_buf(deployment->deployment_id)
        ),
        ggl_kv(
            GGL_STR("recipe_directory_path"),
            ggl_obj_buf(deployment->recipe_directory_path)
        ),
        ggl_kv(
            GGL_STR("artifacts_directory_path"),
            ggl_obj_buf(deployment->artifacts_directory_path)
        ),
        ggl_kv(
            GGL_STR("configuration_arn"),
            ggl_obj_buf(deployment->configuration_arn)
        ),
        ggl_kv(GGL_STR("thing_group"), ggl_obj_buf(deployment->thing_group)),
        ggl_kv(GGL_STR("components"), ggl_obj_map(deployment->components))
    ));

    GglError ret = ggl_gg_config_write(
        GGL_BUF_LIST(
            GGL_STR("services"),
            GGL_STR("DeploymentService"),
            GGL_STR("deploymentState"),
            GGL_STR("deploymentDoc")
        ),
        deployment_doc,
        &(int64_t) { 3 }
    );

    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to write deployment document to config.");
        return ret;
    }

    uint8_t deployment_type_mem[24] = { 0 };
    GglBuffer deployment_type = GGL_BUF(deployment_type_mem);
    if (deployment->type == LOCAL_DEPLOYMENT) {
        deployment_type = GGL_STR("LOCAL_DEPLOYMENT");
    } else if (deployment->type == THING_GROUP_DEPLOYMENT) {
        deployment_type = GGL_STR("THING_GROUP_DEPLOYMENT");
    }

    ret = ggl_gg_config_write(
        GGL_BUF_LIST(
            GGL_STR("services"),
            GGL_STR("DeploymentService"),
            GGL_STR("deploymentState"),
            GGL_STR("deploymentType")
        ),
        ggl_obj_buf(deployment_type),
        &(int64_t) { 3 }
    );

    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to write deployment type to config.");
        return ret;
    }

    return GGL_ERR_OK;
}

GglError retrieve_in_progress_deployment(
    GglDeployment *deployment, GglBuffer *jobs_id, int64_t *jobs_version
) {
    GGL_LOGD("Searching config for any in progress deployment.");

    GglBuffer config_mem = GGL_BUF((uint8_t[2500]) { 0 });
    GglArena alloc = ggl_arena_init(config_mem);
    GglObject deployment_config;

    GglError ret = ggl_gg_config_read(
        GGL_BUF_LIST(
            GGL_STR("services"),
            GGL_STR("DeploymentService"),
            GGL_STR("deploymentState")
        ),
        &alloc,
        &deployment_config
    );
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    if (ggl_obj_type(deployment_config) != GGL_TYPE_MAP) {
        GGL_LOGE("Retrieved config not a map.");
        return GGL_ERR_INVALID;
    }

    GglObject *jobs_id_obj;
    ret = ggl_map_validate(
        ggl_obj_into_map(deployment_config),
        GGL_MAP_SCHEMA(
            { GGL_STR("jobsID"), GGL_REQUIRED, GGL_TYPE_BUF, &jobs_id_obj }
        )
    );
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    assert(ggl_obj_into_buf(*jobs_id_obj).len < 64);
    assert(jobs_id->len >= 64);

    memcpy(
        jobs_id->data,
        ggl_obj_into_buf(*jobs_id_obj).data,
        ggl_obj_into_buf(*jobs_id_obj).len
    );

    GglObject *jobs_version_obj;
    ret = ggl_map_validate(
        ggl_obj_into_map(deployment_config),
        GGL_MAP_SCHEMA({ GGL_STR("jobsVersion"),
                         GGL_REQUIRED,
                         GGL_TYPE_I64,
                         &jobs_version_obj })
    );
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    *jobs_version = ggl_obj_into_i64(*jobs_version_obj);

    GglObject *deployment_type;
    ret = ggl_map_validate(
        ggl_obj_into_map(deployment_config),
        GGL_MAP_SCHEMA({ GGL_STR("deploymentType"),
                         GGL_REQUIRED,
                         GGL_TYPE_BUF,
                         &deployment_type })
    );
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    if (ggl_buffer_eq(
            ggl_obj_into_buf(*deployment_type), GGL_STR("LOCAL_DEPLOYMENT")
        )) {
        deployment->type = LOCAL_DEPLOYMENT;
    } else if (ggl_buffer_eq(
                   ggl_obj_into_buf(*deployment_type),
                   GGL_STR("THING_GROUP_DEPLOYMENT")
               )) {
        deployment->type = THING_GROUP_DEPLOYMENT;
    }

    GglObject *deployment_doc;
    ret = ggl_map_validate(
        ggl_obj_into_map(deployment_config),
        GGL_MAP_SCHEMA({ GGL_STR("deploymentDoc"),
                         GGL_REQUIRED,
                         GGL_TYPE_MAP,
                         &deployment_doc })
    );
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    GglObject *deployment_id;
    ret = ggl_map_validate(
        ggl_obj_into_map(*deployment_doc),
        GGL_MAP_SCHEMA({ GGL_STR("deployment_id"),
                         GGL_REQUIRED,
                         GGL_TYPE_BUF,
                         &deployment_id })
    );
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    deployment->deployment_id = ggl_obj_into_buf(*deployment_id);

    GglObject *recipe_directory_path;
    ret = ggl_map_validate(
        ggl_obj_into_map(*deployment_doc),
        GGL_MAP_SCHEMA({ GGL_STR("recipe_directory_path"),
                         GGL_REQUIRED,
                         GGL_TYPE_BUF,
                         &recipe_directory_path })
    );
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    deployment->recipe_directory_path
        = ggl_obj_into_buf(*recipe_directory_path);

    GglObject *artifacts_directory_path;
    ret = ggl_map_validate(
        ggl_obj_into_map(*deployment_doc),
        GGL_MAP_SCHEMA({ GGL_STR("artifacts_directory_path"),
                         GGL_REQUIRED,
                         GGL_TYPE_BUF,
                         &artifacts_directory_path })
    );
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    deployment->artifacts_directory_path
        = ggl_obj_into_buf(*artifacts_directory_path);

    GglObject *configuration_arn;
    ret = ggl_map_validate(
        ggl_obj_into_map(*deployment_doc),
        GGL_MAP_SCHEMA({ GGL_STR("configuration_arn"),
                         GGL_REQUIRED,
                         GGL_TYPE_BUF,
                         &configuration_arn })
    );
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    deployment->configuration_arn = ggl_obj_into_buf(*configuration_arn);

    GglObject *thing_group;
    ret = ggl_map_validate(
        ggl_obj_into_map(*deployment_doc),
        GGL_MAP_SCHEMA(
            { GGL_STR("thing_group"), GGL_REQUIRED, GGL_TYPE_BUF, &thing_group }
        )
    );
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    deployment->thing_group = ggl_obj_into_buf(*thing_group);

    GglObject *components;
    ret = ggl_map_validate(
        ggl_obj_into_map(*deployment_doc),
        GGL_MAP_SCHEMA(
            { GGL_STR("components"), GGL_REQUIRED, GGL_TYPE_MAP, &components }
        )
    );
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    deployment->components = ggl_obj_into_map(*components);

    static uint8_t deployment_deep_copy_mem[5000] = { 0 };
    GglArena deployment_balloc
        = ggl_arena_init(GGL_BUF(deployment_deep_copy_mem));
    ret = deep_copy_deployment(deployment, &deployment_balloc);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to deep copy deployment.");
        return ret;
    }

    return GGL_ERR_OK;
}

GglError delete_saved_deployment_from_config(void) {
    GGL_LOGD("Deleting previously saved deployment from config.");

    GglError ret = ggl_gg_config_delete(GGL_BUF_LIST(
        GGL_STR("services"),
        GGL_STR("DeploymentService"),
        GGL_STR("deploymentState")
    ));

    if (ret != GGL_ERR_OK) {
        GGL_LOGE(
            "Failed to delete previously saved deployment state from config."
        );
        return ret;
    }

    return GGL_ERR_OK;
}

GglError process_bootstrap_phase(
    GglMap components,
    GglBuffer root_path,
    GglBufVec *bootstrap_comp_name_buf_vec,
    GglDeployment *deployment
) {
    int bootstrap_component_count = 0;
    GGL_MAP_FOREACH (component, components) {
        GglBuffer component_name = ggl_kv_key(*component);

        // check config to see if component bootstrap steps have already been
        // completed
        if (component_bootstrap_phase_completed(component_name)) {
            GGL_LOGD("Bootstrap processed. Skipping component.");
            continue;
        }

        static uint8_t bootstrap_service_file_path_buf[PATH_MAX];
        GglByteVec bootstrap_service_file_path_vec
            = GGL_BYTE_VEC(bootstrap_service_file_path_buf);
        GglError ret
            = ggl_byte_vec_append(&bootstrap_service_file_path_vec, root_path);
        ggl_byte_vec_chain_append(
            &ret, &bootstrap_service_file_path_vec, GGL_STR("/")
        );
        ggl_byte_vec_chain_append(
            &ret, &bootstrap_service_file_path_vec, GGL_STR("ggl.")
        );
        ggl_byte_vec_chain_append(
            &ret, &bootstrap_service_file_path_vec, component_name
        );
        ggl_byte_vec_chain_append(
            &ret,
            &bootstrap_service_file_path_vec,
            GGL_STR(".bootstrap.service")
        );
        if (ret == GGL_ERR_OK) {
            // check if the current component name has relevant bootstrap
            // service file created
            int fd = -1;
            ret = ggl_file_open(
                bootstrap_service_file_path_vec.buf, O_RDONLY, 0, &fd
            );
            if (ret != GGL_ERR_OK) {
                GGL_LOGD(
                    "Component %.*s does not have the relevant bootstrap "
                    "service file",
                    (int) component_name.len,
                    component_name.data
                );
            } else { // relevant bootstrap service file exists
                ret = disable_and_unlink_service(&component_name, BOOTSTRAP);
                if (ret != GGL_ERR_OK) {
                    return ret;
                }
                GGL_LOGI(
                    "Found bootstrap service file for %.*s. Processing.",
                    (int) component_name.len,
                    component_name.data
                );

                // add relevant component name into the vector
                ret = ggl_buf_vec_push(
                    bootstrap_comp_name_buf_vec, component_name
                );
                if (ret != GGL_ERR_OK) {
                    GGL_LOGE("Failed to add the bootstrap component name "
                             "into vector");
                    return ret;
                }
                bootstrap_component_count++;

                // initiate link command for 'bootstrap'
                static uint8_t link_command_buf[PATH_MAX];
                GglByteVec link_command_vec = GGL_BYTE_VEC(link_command_buf);
                ret = ggl_byte_vec_append(
                    &link_command_vec, GGL_STR("systemctl link ")
                );
                ggl_byte_vec_chain_append(
                    &ret, &link_command_vec, bootstrap_service_file_path_vec.buf
                );
                ggl_byte_vec_chain_push(&ret, &link_command_vec, '\0');
                if (ret != GGL_ERR_OK) {
                    GGL_LOGE(
                        "Failed to create systemctl link command for:%.*s",
                        (int) bootstrap_service_file_path_vec.buf.len,
                        bootstrap_service_file_path_vec.buf.data
                    );
                    return ret;
                }

                GGL_LOGD(
                    "Command to execute: %.*s",
                    (int) link_command_vec.buf.len,
                    link_command_vec.buf.data
                );

                // NOLINTBEGIN(concurrency-mt-unsafe)
                int system_ret = system((char *) link_command_vec.buf.data);
                if (WIFEXITED(system_ret)) {
                    if (WEXITSTATUS(system_ret) != 0) {
                        GGL_LOGE(
                            "systemctl link failed for:%.*s",
                            (int) bootstrap_service_file_path_vec.buf.len,
                            bootstrap_service_file_path_vec.buf.data
                        );
                        return ret;
                    }
                    GGL_LOGI(
                        "systemctl link exited for %.*s with child status "
                        "%d\n",
                        (int) bootstrap_service_file_path_vec.buf.len,
                        bootstrap_service_file_path_vec.buf.data,
                        WEXITSTATUS(system_ret)
                    );
                } else {
                    GGL_LOGE(
                        "systemctl link did not exit normally for %.*s",
                        (int) bootstrap_service_file_path_vec.buf.len,
                        bootstrap_service_file_path_vec.buf.data
                    );
                    return ret;
                }

                // initiate start command for 'bootstrap'
                static uint8_t start_command_buf[PATH_MAX];
                GglByteVec start_command_vec = GGL_BYTE_VEC(start_command_buf);
                ret = ggl_byte_vec_append(
                    &start_command_vec, GGL_STR("systemctl start ")
                );
                ggl_byte_vec_chain_append(
                    &ret, &start_command_vec, GGL_STR("ggl.")
                );
                ggl_byte_vec_chain_append(
                    &ret, &start_command_vec, component_name
                );
                ggl_byte_vec_chain_append(
                    &ret, &start_command_vec, GGL_STR(".bootstrap.service\0")
                );

                GGL_LOGD(
                    "Command to execute: %.*s",
                    (int) start_command_vec.buf.len,
                    start_command_vec.buf.data
                );
                if (ret != GGL_ERR_OK) {
                    GGL_LOGE(
                        "Failed to create systemctl start command for %.*s",
                        (int) bootstrap_service_file_path_vec.buf.len,
                        bootstrap_service_file_path_vec.buf.data
                    );
                    return ret;
                }

                // save component to config to avoid rerunning bootstrap steps
                ret = save_component_info(
                    component_name,
                    ggl_obj_into_buf(*ggl_kv_val(component)),
                    GGL_STR("bootstrap")
                );
                if (ret != GGL_ERR_OK) {
                    GGL_LOGE("Failed to save component info to config after "
                             "completing bootstrap steps.");
                    return ret;
                }

                system_ret = system((char *) start_command_vec.buf.data);
                // NOLINTEND(concurrency-mt-unsafe)
                if (WIFEXITED(system_ret)) {
                    if (WEXITSTATUS(system_ret) != 0) {
                        GGL_LOGE(
                            "systemctl start failed for%.*s",
                            (int) bootstrap_service_file_path_vec.buf.len,
                            bootstrap_service_file_path_vec.buf.data
                        );
                        return ret;
                    }
                    GGL_LOGI(
                        "systemctl start exited with child status %d\n",
                        WEXITSTATUS(system_ret)
                    );
                } else {
                    GGL_LOGE(
                        "systemctl start did not exit normally for %.*s",
                        (int) bootstrap_service_file_path_vec.buf.len,
                        bootstrap_service_file_path_vec.buf.data
                    );
                    return ret;
                }
            }
        }
    }

    if (bootstrap_component_count > 0) {
        // save deployment state and restart
        GglError ret = save_deployment_info(deployment);
        if (ret != GGL_ERR_OK) {
            GGL_LOGE("Failed to save deployment state for bootstrap.");
            return ret;
        }

        GGL_LOGI("Rebooting device for bootstrap.");
        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        int system_ret = system("systemctl reboot");
        if (WIFEXITED(system_ret)) {
            if (WEXITSTATUS(system_ret) != 0) {
                GGL_LOGE("systemctl reboot failed");
            }
            GGL_LOGI(
                "systemctl reboot exited with child status %d\n",
                WEXITSTATUS(system_ret)
            );
        } else {
            GGL_LOGE("systemctl reboot did not exit normally");
        }
    }

    return GGL_ERR_OK;
}

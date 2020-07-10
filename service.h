#pragma once

#include "file_monitor.h"

#include <libubus.h>

#include <libubox/avl.h>
#include <libubox/ustream.h>

struct restart_config_st {
    uint32_t delay_millisecs;
    uint32_t crash_threshold_secs;
    uint32_t max_crashes;
};

struct restart_state_st {
    uint32_t crash_count;
    struct uloop_timeout delay_timeout;
};

struct service_config {
    struct blob_attr * command; /* The command and args to specify when starting the service. */
    char const * pid_filename; /* Write the PID of the service to this file. */
    char const * config_filename; /* The service will reload if this file changes. */
    uint32_t terminate_timeout_millisecs; /* The maximum time to wait for a service to terminate. */
    bool log_stdout; /* Read stdout rather than direct it to /dev/null. */
    bool log_stderr; /* Read stderr rather than direct it to /dev/null. */
    bool create_new_session; /* Make the service a session leader. */
    int reload_signal; /* The signal to use to request a config reload. */
    struct blob_attr * reload_command; /* The command and args to specify when reloading the service. */

    struct restart_config_st restart;
};

typedef enum {
    stop_reason_none,
    stop_reason_deleting,
    stop_reason_restarting,
    stop_reason_request
} stop_reason_t;

struct service {
	struct avl_node avl;
    bool in_avl;
    const char *name;

    struct ubus_context * ubus;

    stop_reason_t stop_reason;

    struct timespec start_timestamp;
    int last_exit_code;
    uint32_t last_runtime_seconds;

    struct uloop_process reload_process;
    struct uloop_process service_process;
    struct uloop_timeout timeout;
    struct ustream_fd stdout;
    struct ustream_fd stderr;
    struct file_monitor_st * config_file_monitor;

    struct service_config const * config; /* The current config. */
    struct restart_state_st restart_state;

    /* If not NULL this is the config to apply after the service stops. */
    struct service_config const * next_config;
};

void
service_stopped(struct service *s);

void
ubus_init_service(struct ubus_context *ubus);


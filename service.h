#pragma once

#include "file_monitor.h"
#include "ubus_connection.h"

#include <libubus.h>
#include <libubox/avl.h>
#include <libubox/ustream.h>

struct restart_config_st
{
    uint32_t delay_millisecs;
    uint32_t crash_threshold_secs;
    uint32_t max_crashes;
};

struct restart_state_st
{
    uint32_t crash_count;
    struct uloop_timeout delay_timeout;
};

struct service_config
{
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

typedef enum {
    command_request_stop,
    command_request_start,
    command_request_restart,
    command_request_COUNT
} command_request_t;

typedef struct serviced_context_st serviced_context_st;

struct log_file_entry_st
{
    char const * filename;
    FILE * fp;
};
struct logging_st
{
    size_t num_used; /* The number of open files. */
    size_t size; /* The total number of entries. */
    struct log_file_entry_st * entries;
};

struct service
{
    struct avl_node avl;
    bool in_avl;
    const char * name;

    serviced_context_st * context;
    command_request_t last_command_request;
    stop_reason_t stop_reason;

    struct timespec start_timestamp;
    int last_exit_code;
    uint32_t last_runtime_seconds;

    struct uloop_process reload_process;
    struct uloop_process service_process;
    struct uloop_timeout timeout;
    struct ustream_fd stdout;
    struct ustream_fd stderr;

    struct logging_st logging;

    struct file_monitor_st * config_file_monitor;

    struct service_config const * config; /* The current config. */
    struct restart_state_st restart_state;

    /* If not NULL this is the config to apply after the service stops. */
    struct service_config const * next_config;
};

struct serviced_context_st {
    struct ubus_connection_ctx_st ubus_connection;
    struct avl_tree services;
};

char const *
command_request_to_string(command_request_t const command_request);

void
services_insert_service(struct serviced_context_st * context, struct service * s);

void
services_remove_service(struct service * s);

struct service *
services_lookup_service(
    struct serviced_context_st * const context, char const * service_name);

typedef void (*services_iterate_cb)(struct service * s, void * user_ctx);

void
services_iterate(
    struct ubus_context * ubus, services_iterate_cb cb, void * user_ctx);

struct service *
service_new(struct serviced_context_st * context, char const * service_name);

void
reload_command_run(struct service * const s);

bool
service_start_fresh(struct service * s);

void
service_free(struct service * s);

bool
service_delete(struct service * s);

void
service_update_config(struct service * s);

bool
configs_match(
    struct service_config const * a, struct service_config const * b);

void
config_free(struct service_config const * config_in);

bool
service_restart(struct service * s);

bool
service_reload(struct service * s);

bool
process_is_running(struct uloop_process const * process);

bool
service_is_running(struct service const * s);

bool
service_is_stopping(struct service const * s);

uint32_t
service_runtime_seconds(struct service const * s);

bool
timer_is_running(struct uloop_timeout const * timer);

int
service_send_signal(struct service const * s, unsigned sig);

void
service_stop(struct service * s, stop_reason_t stop_reason);

void
send_service_event(struct service const * s, char const * event);

void
serviced_deinit(serviced_context_st *context);

serviced_context_st *
serviced_init(char const * early_start_dir, char const * ubus_path);

void
service_process_logging_request(
    struct service * const s, char const * const filename, bool const enable);


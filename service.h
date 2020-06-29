#pragma once
#include <libubus.h>

#include <libubox/avl.h>
#include <libubox/ustream.h>

struct service_config
{
    struct blob_attr * command; /* The command and args to specify when starting the service. */
    char * pid_filename; /* Write the PID of the service to this file. */
    uint32_t terminate_timeout_millisecs; /* The maximum time to wait for a service to terminate. */
    bool log_stdout; /* Read stderr rather than direct it to /dev/null. */
    bool log_stderr; /* Read stderr rather than direct it to /dev/null. */
    bool create_new_session; /* Make the service a session leader. */
    int reload_signal; /* The signal to use to request a config reload. */
    struct blob_attr * reload_command; /* The command and args to specify when reloading the service. */
};

struct service {
	struct avl_node avl;
    bool in_avl;
    const char *name;

    struct ubus_context * ubus;

    bool delete_after_exit;
    bool restart_after_exit;

    struct timespec start_timestamp;
    int last_exit_code;
    uint32_t last_runtime_seconds;

    struct uloop_process proc;
    struct uloop_timeout timeout;
    struct ustream_fd stdout;
    struct ustream_fd stderr;

    struct service_config config;
};

void
service_stopped(struct service *s);

void
ubus_init_service(struct ubus_context *ubus);


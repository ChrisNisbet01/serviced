#include "serviced_ubus.h"
#include "debug.h"
#include "log.h"
#include "string_constants.h"
#include "utils.h"

#include <libubox/blobmsg_json.h>
#include <libubox/ulog.h>


#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static uint32_t const default_terminate_timeout_millisecs = 100;
static uint32_t const default_restart_delay_millisecs = 10;


static int
service_handle_add_request(
    struct ubus_context * const ctx,
    struct ubus_object * const obj,
    struct ubus_request_data * const req,
    char const * const method,
    struct blob_attr * const msg)
{
    struct serviced_context_st * const context =
        container_of(ctx, struct serviced_context_st, ubus_connection.context);
    service_add_error_t const add_result = service_add(context, msg);

    int res;
    switch (add_result)
    {
        case service_add_success:
            res = UBUS_STATUS_OK;
            break;
        case service_add_invalid_argument:
            res = UBUS_STATUS_INVALID_ARGUMENT;
            break;
        case service_add_unknown_error:
            res = UBUS_STATUS_UNKNOWN_ERROR;
            break;
        default:
            res = UBUS_STATUS_OK;
            break;
    }

    return res;
}

enum {
    SERVICE_GENERIC_NAME,
    __SERVICE_GENERIC_MAX
};

static const struct blobmsg_policy service_generic_policy[__SERVICE_GENERIC_MAX] = {
    [SERVICE_GENERIC_NAME] = { name_, BLOBMSG_TYPE_STRING },
};

static int
service_lookup_by_request_msg(
    struct serviced_context_st * const context,
    struct blob_attr * const msg,
    struct service * * const s_out)
{
    struct blob_attr * tb[__SERVICE_GENERIC_MAX];
    int result;
    struct service * s;
    blobmsg_parse(service_generic_policy, __SERVICE_GENERIC_MAX, tb,
                  blobmsg_data(msg), blobmsg_data_len(msg));

    char const * service_name = blobmsg_get_string(tb[SERVICE_GENERIC_NAME]);

    if (service_name == NULL)
    {
        s = NULL;
        result = UBUS_STATUS_INVALID_ARGUMENT;
        goto done;
    }

    s = services_lookup_service(context, service_name);
    if (s == NULL)
    {
        result = UBUS_STATUS_NOT_FOUND;
        debug("Service %s not found\n", service_name);
        goto done;
    }

    result = UBUS_STATUS_OK;

done:
    if (s_out != NULL)
    {
        *s_out = s;
    }

    return result;
}

static int
service_handle_delete_request(
    struct ubus_context * const ctx,
    struct ubus_object * const obj,
    struct ubus_request_data * const req,
    char const * const method,
    struct blob_attr * const msg)
{
    struct serviced_context_st * const context =
        container_of(ctx, struct serviced_context_st, ubus_connection.context);
    struct service * s;
    int result = service_lookup_by_request_msg(context, msg, &s);

    if (result != UBUS_STATUS_OK)
    {
        goto done;
    }

    if (!service_delete(s))
    {
        result = UBUS_STATUS_INVALID_ARGUMENT;
        goto done;
    }

    result = UBUS_STATUS_OK;

done:
    return result;
}

static int
service_handle_start_request(
    struct ubus_context * const ctx,
    struct ubus_object * const obj,
    struct ubus_request_data * const req,
    char const * const method,
    struct blob_attr * const msg)
{
    struct serviced_context_st * const context =
        container_of(ctx, struct serviced_context_st, ubus_connection.context);
    struct service * s;
    int result = service_lookup_by_request_msg(context, msg, &s);

    if (result != UBUS_STATUS_OK)
    {
        goto done;
    }

    if (!service_start_fresh(s))
    {
        result = UBUS_STATUS_INVALID_ARGUMENT;
        goto done;
    }

    result = UBUS_STATUS_OK;

done:
    return result;
}

static int
service_handle_stop_request(
    struct ubus_context * const ctx,
    struct ubus_object * const obj,
    struct ubus_request_data * const req,
    char const * const method,
    struct blob_attr * const msg)
{
    struct serviced_context_st * const context =
        container_of(ctx, struct serviced_context_st, ubus_connection.context);
    struct service * s;
    int result = service_lookup_by_request_msg(context, msg, &s);

    if (result != UBUS_STATUS_OK)
    {
        goto done;
    }

    if (!service_stop(s, stop_reason_request))
    {
        result = UBUS_STATUS_INVALID_ARGUMENT;
        goto done;
    }

    result = UBUS_STATUS_OK;

done:
    return result;
}

static int
service_handle_reload_request(
    struct ubus_context * const ctx,
    struct ubus_object * const obj,
    struct ubus_request_data * const req,
    char const * const method,
    struct blob_attr * const msg)
{
    struct serviced_context_st * const context =
        container_of(ctx, struct serviced_context_st, ubus_connection.context);
    struct service * s;
    int result = service_lookup_by_request_msg(context, msg, &s);

    if (result != UBUS_STATUS_OK)
    {
        goto done;
    }

    if (!service_reload(s))
    {
        result = UBUS_STATUS_INVALID_ARGUMENT;
        goto done;
    }

    result = UBUS_STATUS_OK;

done:
    return result;
}

static int
service_handle_restart_request(
    struct ubus_context * const ctx,
    struct ubus_object * const obj,
    struct ubus_request_data * const req,
    char const * const method,
    struct blob_attr * const msg)
{
    struct serviced_context_st * const context =
        container_of(ctx, struct serviced_context_st, ubus_connection.context);
    struct service * s;
    int result = service_lookup_by_request_msg(context, msg, &s);

    if (result != UBUS_STATUS_OK)
    {
        goto done;
    }

    if (!service_restart(s))
    {
        result = UBUS_STATUS_INVALID_ARGUMENT;
        goto done;
    }

    result = UBUS_STATUS_OK;

done:
    return result;
}

enum {
    SERVICE_CONFIG_COMMAND,
    SERVICE_CONFIG_RELOAD_COMMAND,
    SERVICE_CONFIG_STDOUT,
    SERVICE_CONFIG_STDERR,
    SERVICE_CONFIG_PIDFILE,
    SERVICE_CONFIG_CONFIGFILE,
    SERVICE_CONFIG_RELOADSIG,
    SERVICE_CONFIG_TERMTIMEOUT,
    SERVICE_CONFIG_NEW_SESSION,
    SERVICE_CONFIG_RESTART,
    __SERVICE_CONFIG_MAX,
};

static const struct blobmsg_policy service_config_policy[__SERVICE_CONFIG_MAX] = {
    [SERVICE_CONFIG_COMMAND] = { command_, BLOBMSG_TYPE_ARRAY },
    [SERVICE_CONFIG_RELOAD_COMMAND] = { reload_command_, BLOBMSG_TYPE_ARRAY },
    [SERVICE_CONFIG_STDOUT] = { stdout_, BLOBMSG_TYPE_BOOL },
    [SERVICE_CONFIG_STDERR] = { stderr_, BLOBMSG_TYPE_BOOL },
    [SERVICE_CONFIG_PIDFILE] = { pid_file_, BLOBMSG_TYPE_STRING },
    [SERVICE_CONFIG_CONFIGFILE] = { config_file_, BLOBMSG_TYPE_STRING },
    [SERVICE_CONFIG_RELOADSIG] = { reload_signal_, BLOBMSG_TYPE_INT32 },
    [SERVICE_CONFIG_TERMTIMEOUT] = { terminate_timeout_millisecs_, BLOBMSG_TYPE_INT32 },
    [SERVICE_CONFIG_NEW_SESSION] = { new_session_, BLOBMSG_TYPE_BOOL },
    [SERVICE_CONFIG_RESTART] = { restart_config_, BLOBMSG_TYPE_TABLE }
};

static struct blob_attr *
parse_command(struct blob_attr * const attr)
{
    struct blob_attr * command;

    debug("%s\n", __func__);

    if (blobmsg_array_is_type(attr, BLOBMSG_TYPE_STRING))
    {
        command = blob_memdup(attr);
    }
    else
    {
        command = NULL;
    }

    return command;
}

enum {
    RESTART_CONFIG_DELAY_MILLISECS,
    RESTART_CONFIG_CRASH_THRESHOLD_SECS,
    RESTART_CONFIG_MAX_CRASHES,
    __RESTART_CONFIG_MAX,
};

static const struct blobmsg_policy restart_config_policy[__RESTART_CONFIG_MAX] = {
    [RESTART_CONFIG_DELAY_MILLISECS] = { delay_millisecs_, BLOBMSG_TYPE_INT32 },
    [RESTART_CONFIG_CRASH_THRESHOLD_SECS] = { crash_threshold_secs_, BLOBMSG_TYPE_INT32 },
    [RESTART_CONFIG_MAX_CRASHES] = { max_crashes_, BLOBMSG_TYPE_INT32 }
};

static void
parse_restart(
    struct restart_config_st * const restart, struct blob_attr * const restart_attr)
{
    if (restart_attr == NULL)
    {
        goto done;
    }

    struct blob_attr * tb[__RESTART_CONFIG_MAX];

    blobmsg_parse(restart_config_policy, __RESTART_CONFIG_MAX, tb,
                  blobmsg_data(restart_attr), blobmsg_data_len(restart_attr));

    restart->delay_millisecs =
        blobmsg_get_u32_or_default(
            tb[RESTART_CONFIG_DELAY_MILLISECS], default_restart_delay_millisecs);
    restart->crash_threshold_secs =
        blobmsg_get_u32_or_default(tb[RESTART_CONFIG_CRASH_THRESHOLD_SECS], 0);
    restart->max_crashes =
        blobmsg_get_u32_or_default(tb[RESTART_CONFIG_MAX_CRASHES], 0);

done:
    return;
}

static struct service_config const *
parse_config(struct blob_attr * const msg)
{
    bool success;
    struct service_config * config = calloc(1, sizeof *config);

    debug("%s\n", __func__);

    if (config == NULL)
    {
        success = false;
        goto done;
    }

    struct blob_attr * tb[__SERVICE_CONFIG_MAX];

    blobmsg_parse(service_config_policy, __SERVICE_CONFIG_MAX, tb,
                  blobmsg_data(msg), blobmsg_data_len(msg));

    config->command = parse_command(tb[SERVICE_CONFIG_COMMAND]);
    if (config->command == NULL)
    {
        success = false;
        goto done;
    }

    /*
     * The reload command is optional, so check that the user has supplied one
     * first.
     */
    if (tb[SERVICE_CONFIG_RELOAD_COMMAND] != NULL)
    {
        config->reload_command = parse_command(tb[SERVICE_CONFIG_RELOAD_COMMAND]);
        if (config->reload_command == NULL)
        {
            success = false;
            goto done;
        }
    }

    config->terminate_timeout_millisecs =
        blobmsg_get_u32_or_default(
            tb[SERVICE_CONFIG_TERMTIMEOUT], default_terminate_timeout_millisecs);
    config->reload_signal =
        blobmsg_get_u32_or_default(tb[SERVICE_CONFIG_RELOADSIG], 0);
    if (tb[SERVICE_CONFIG_PIDFILE] != NULL)
    {
        config->pid_filename =
            strdup(blobmsg_get_string(tb[SERVICE_CONFIG_PIDFILE]));
    }
    if (tb[SERVICE_CONFIG_CONFIGFILE] != NULL)
    {
        config->config_filename =
            strdup(blobmsg_get_string(tb[SERVICE_CONFIG_CONFIGFILE]));
    }
    config->log_stdout =
        blobmsg_get_bool_or_default(tb[SERVICE_CONFIG_STDOUT], false);
    config->log_stderr =
        blobmsg_get_bool_or_default(tb[SERVICE_CONFIG_STDERR], false);
    config->create_new_session =
        blobmsg_get_bool_or_default(tb[SERVICE_CONFIG_NEW_SESSION], false);

    parse_restart(&config->restart, tb[SERVICE_CONFIG_RESTART]);


    success = true;

done:
    if (!success)
    {
        debug("config parse failed\n");
        config_free(config);
        config = NULL;
    }

    return config;
}

static bool
service_update(struct service * const s, struct blob_attr * const msg)
{
    bool success;
    struct service_config const * const new_config = parse_config(msg);

    debug("%s\n", __func__);

    if (new_config == NULL)
    {
        debug("Invalid config for service %s\n", s->name);
        success = false;
        goto done;
    }

    if (s->next_config != NULL && configs_match(new_config, s->next_config))
    {
        /*
         * Managed to send an updated config that matches the pending one
         * before the service stopped.
         * Nothing to do.
         */
        debug("new config matches pending config. Nothing to do.\n");
        config_free(new_config);
        success = true;
        goto done;
    }

    if (configs_match(new_config, s->config))
    {
        /* This config matches the current one.
         * Nothing to do.
         */
        debug("new config matches current config. Nothing to do.\n");
        config_free(new_config);
        success = true;
        goto done;
    }

    config_free(s->next_config);
    s->next_config = new_config;

    if (service_is_running(s))
    {
        if (!service_is_stopping(s))
        {
            /* The new config will be applied after the service has stopped. */
            service_restart(s);
        }
    }
    else
    {
        /* Can simply replace the configs now. */
        service_update_config(s);
    }

    success = true;

done:
    return success;
}

enum {
    SERVICE_UPDATE_NAME,
    SERVICE_UPDATE_AUTO_START,
    SERVICE_UPDATE_COMMAND,
    SERVICE_UPDATE_RELOAD_COMMAND,
    SERVICE_UPDATE_STDOUT,
    SERVICE_UPDATE_STDERR,
    SERVICE_UPDATE_PIDFILE,
    SERVICE_UPDATE_CONFIGFILE,
    SERVICE_UPDATE_RELOADSIG,
    SERVICE_UPDATE_TERMTIMEOUT,
    SERVICE_UPDATE_NEW_SESSION,
    SERVICE_UPDATE_RESTART,
    __SERVICE_UPDATE_MAX,
};

static const struct blobmsg_policy service_update_policy[__SERVICE_UPDATE_MAX] = {
    [SERVICE_UPDATE_NAME] = { name_, BLOBMSG_TYPE_STRING },
    [SERVICE_UPDATE_AUTO_START] = { auto_start_, BLOBMSG_TYPE_BOOL },
    [SERVICE_UPDATE_COMMAND] = { command_, BLOBMSG_TYPE_ARRAY },
    [SERVICE_UPDATE_RELOAD_COMMAND] = { reload_command_, BLOBMSG_TYPE_ARRAY },
    [SERVICE_UPDATE_STDOUT] = { stdout_, BLOBMSG_TYPE_BOOL },
    [SERVICE_UPDATE_STDERR] = { stderr_, BLOBMSG_TYPE_BOOL },
    [SERVICE_UPDATE_PIDFILE] = { pid_file_, BLOBMSG_TYPE_STRING },
    [SERVICE_UPDATE_CONFIGFILE] = { config_file_, BLOBMSG_TYPE_STRING },
    [SERVICE_UPDATE_RELOADSIG] = { reload_signal_, BLOBMSG_TYPE_INT32 },
    [SERVICE_UPDATE_TERMTIMEOUT] = { terminate_timeout_millisecs_, BLOBMSG_TYPE_INT32 },
    [SERVICE_UPDATE_NEW_SESSION] = { new_session_, BLOBMSG_TYPE_BOOL },
    [SERVICE_UPDATE_RESTART] = { restart_config_, BLOBMSG_TYPE_TABLE }
};

static int
service_handle_update_request(
    struct ubus_context * const ctx,
    struct ubus_object * const obj,
    struct ubus_request_data * const req,
    char const * const method,
    struct blob_attr * const msg)
{
    struct serviced_context_st * const context =
        container_of(ctx, struct serviced_context_st, ubus_connection.context);
    struct service * s;
    int result = service_lookup_by_request_msg(context, msg, &s);

    if (result != UBUS_STATUS_OK)
    {
        goto done;
    }

    if (!service_update(s, msg))
    {
        result = UBUS_STATUS_INVALID_ARGUMENT;
        goto done;
    }

    result = UBUS_STATUS_OK;

done:
    return result;
}

enum {
    SERVICE_SIGNAL_NAME,
    SERVICE_SIGNAL_SIGNAL,
    __SERVICE_SIGNAL_MAX,
};

static const struct blobmsg_policy service_signal_policy[__SERVICE_SIGNAL_MAX] = {
    [SERVICE_SIGNAL_NAME] = { name_, BLOBMSG_TYPE_STRING },
    [SERVICE_SIGNAL_SIGNAL] = { signal_, BLOBMSG_TYPE_INT32 },
};

static int
service_handle_signal_request(
    struct ubus_context * const ctx,
    struct ubus_object * const obj,
    struct ubus_request_data * const req,
    char const * const method,
    struct blob_attr * const msg)
{
    struct blob_attr * tb[__SERVICE_SIGNAL_MAX];
    int res;
    struct serviced_context_st * const context =
        container_of(ctx, struct serviced_context_st, ubus_connection.context);

    blobmsg_parse(service_signal_policy, __SERVICE_SIGNAL_MAX, tb,
                  blobmsg_data(msg), blobmsg_data_len(msg));

    int const sig =
        blobmsg_get_u32_or_default(tb[SERVICE_SIGNAL_SIGNAL], SIGHUP);
    char const * const service_name =
        blobmsg_get_string(tb[SERVICE_SIGNAL_NAME]);

    if (service_name == NULL)
    {
        res = UBUS_STATUS_INVALID_ARGUMENT;
        goto done;
    }

    struct service * const s = services_lookup_service(context, service_name);

    if (s == NULL)
    {
        debug("Service %s not found\n", service_name);
        res = UBUS_STATUS_NOT_FOUND;
        goto done;
    }

    res = service_send_signal(s, sig);

done:
    return res;
}

static void
dump_restart_data(
    struct service_config const * const config,
    struct restart_state_st const * const restart_state,
    struct blob_buf * const b)
{
    void * const restart_cookie = blobmsg_open_table(b, restart_config_);

    blobmsg_add_u32(b, delay_millisecs_, config->restart.delay_millisecs);
    blobmsg_add_u32(b, crash_threshold_secs_, config->restart.crash_threshold_secs);
    blobmsg_add_u32(b, max_crashes_, config->restart.max_crashes);

    blobmsg_add_u32(b, crash_count_, restart_state->crash_count);
    blobmsg_add_u8(b, restart_pending_, timer_is_running(&restart_state->delay_timeout));
    blobmsg_close_table(b, restart_cookie);
}

static void
dump_service_data(struct service const * const s, struct blob_buf * const b)
{
    struct service_config const * const config = s->config;

    blobmsg_add_u8(b, running_, service_is_running(s));
    if (service_is_running(s))
    {
        blobmsg_add_u32(b, pid_, s->service_process.pid);
        blobmsg_add_u32(b, runtime_seconds_, service_runtime_seconds(s));
    }
    else
    {
        blobmsg_add_u32(b, last_exit_code_, s->last_exit_code);
        blobmsg_add_u32(b, runtime_seconds_, s->last_runtime_seconds);
    }

    /* Dump some of the configuration so it's possible to check it. */
    blobmsg_add_blob(b, config->command);
    if (config->reload_signal != 0)
    {
        blobmsg_add_u32(b, reload_signal_, config->reload_signal);
    }
    if (config->reload_command != NULL)
    {
        blobmsg_add_blob(b, config->reload_command);
        if (process_is_running(&s->reload_process))
        {
            blobmsg_add_u32(b, reload_pid_, s->reload_process.pid);
        }
    }
    blobmsg_add_u32(b, terminate_timeout_millisecs_, config->terminate_timeout_millisecs);
    blobmsg_add_u8(b, log_stdout_, config->log_stdout);
    blobmsg_add_u8(b, log_stderr_, config->log_stderr);
    blobmsg_add_u8(b, new_session_, config->create_new_session);
    if (config->pid_filename != NULL)
    {
        blobmsg_add_string(b, pid_file_, config->pid_filename);
    }
    if (config->config_filename != NULL)
    {
        blobmsg_add_string(b, config_file_, config->config_filename);
    }
}

static void
service_dump(struct service const * const s, struct blob_buf * const b)
{
    void * const cookie = blobmsg_open_table(b, s->name);

    dump_service_data(s, b);
    dump_restart_data(s->config, &s->restart_state, b);
    blobmsg_close_table(b, cookie);
}

struct dump_context {
    struct blob_buf * b;
    char const * service_name;
};

static void
service_dump_cb(struct service * s, void * user_ctx)
{
    struct dump_context const * const ctx = user_ctx;
    bool const should_dump =
        ctx->service_name == NULL || strcmp(s->name, ctx->service_name) == 0;

    if (should_dump)
    {
        service_dump(s, ctx->b);
    }
}

static void
service_dump_populate(
    struct ubus_context * const ubus,
    struct blob_buf * const b,
    char const * const service_name)
{
    struct dump_context ctx = {
        .b = b,
        .service_name = service_name
    };
    services_iterate(ubus, service_dump_cb, &ctx);
}

enum {
    SERVICE_DUMP_NAME,
    __SERVICE_DUMP_MAX,
};

static const struct blobmsg_policy service_dump_policy[__SERVICE_DUMP_MAX] = {
    [SERVICE_DUMP_NAME] = { name_, BLOBMSG_TYPE_STRING },
};

static int
service_handle_dump_request(
    struct ubus_context * const ctx,
    struct ubus_object * const obj,
    struct ubus_request_data * const req,
    char const * const method,
    struct blob_attr * const msg)
{
    struct blob_attr * tb[__SERVICE_DUMP_MAX];

    blobmsg_parse(service_dump_policy, __SERVICE_DUMP_MAX, tb,
                  blobmsg_data(msg), blobmsg_data_len(msg));

    struct blob_buf b;

    blob_buf_full_init(&b, 0);
    service_dump_populate(ctx, &b, blobmsg_get_string(tb[SERVICE_DUMP_NAME]));
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);

    return UBUS_STATUS_OK;
}

static void
config_file_timeout(void * const user_ctx)
{
    struct service * const s = user_ctx;

    debug("%s: service %s pid %d\n", __func__, s->name, s->service_process.pid);

    send_service_event(s, service_config_file_has_changed_);

    service_reload(s);
}

enum {
    SERVICE_ADD_NAME,
    SERVICE_ADD_AUTO_START,
    SERVICE_ADD_COMMAND,
    SERVICE_ADD_RELOAD_COMMAND,
    SERVICE_ADD_STDOUT,
    SERVICE_ADD_STDERR,
    SERVICE_ADD_PIDFILE,
    SERVICE_ADD_CONFIGFILE,
    SERVICE_ADD_RELOADSIG,
    SERVICE_ADD_TERMTIMEOUT,
    SERVICE_ADD_NEW_SESSION,
    SERVICE_ADD_RESTART,
    __SERVICE_ADD_MAX,
};

static const struct blobmsg_policy service_add_policy[__SERVICE_ADD_MAX] = {
    [SERVICE_ADD_NAME] = { name_, BLOBMSG_TYPE_STRING },
    [SERVICE_ADD_AUTO_START] = { auto_start_, BLOBMSG_TYPE_BOOL },
    [SERVICE_ADD_COMMAND] = { command_, BLOBMSG_TYPE_ARRAY },
    [SERVICE_ADD_RELOAD_COMMAND] = { reload_command_, BLOBMSG_TYPE_ARRAY },
    [SERVICE_ADD_STDOUT] = { stdout_, BLOBMSG_TYPE_BOOL },
    [SERVICE_ADD_STDERR] = { stderr_, BLOBMSG_TYPE_BOOL },
    [SERVICE_ADD_PIDFILE] = { pid_file_, BLOBMSG_TYPE_STRING },
    [SERVICE_ADD_CONFIGFILE] = { config_file_, BLOBMSG_TYPE_STRING },
    [SERVICE_ADD_RELOADSIG] = { reload_signal_, BLOBMSG_TYPE_INT32 },
    [SERVICE_ADD_TERMTIMEOUT] = { terminate_timeout_millisecs_, BLOBMSG_TYPE_INT32 },
    [SERVICE_ADD_NEW_SESSION] = { new_session_, BLOBMSG_TYPE_BOOL },
    [SERVICE_ADD_RESTART] = { restart_config_, BLOBMSG_TYPE_TABLE }
};

service_add_error_t
service_add(struct serviced_context_st * const context, struct blob_attr * const msg)
{
    struct blob_attr * tb[__SERVICE_ADD_MAX];
    service_add_error_t result;

    blobmsg_parse(service_add_policy, __SERVICE_ADD_MAX, tb,
                  blobmsg_data(msg), blobmsg_data_len(msg));

    char const * service_name = blobmsg_get_string(tb[SERVICE_ADD_NAME]);

    if (service_name == NULL)
    {
        result = service_add_invalid_argument;
        goto done;
    }

    if (services_lookup_service(context, service_name) != NULL)
    {
        debug("Service %s already exists\n", service_name);
        result = service_add_invalid_argument;
        goto done;
    }

    debug("Create new service %s\n", service_name);

    struct service * const s = service_new(context, service_name);

    if (s == NULL)
    {
        result = service_add_unknown_error;
        goto done;
    }

    s->config = parse_config(msg);
    if (s->config == NULL)
    {
        debug("Invalid config for service %s\n", s->name);
        service_free(s);
        result = service_add_invalid_argument;
        goto done;
    }

    services_insert_service(context, s);

    if (s->config->config_filename != NULL)
    {
        s->config_file_monitor =
            file_monitor_open(
                s->config->config_filename, config_file_timeout, s);
    }

    if (blobmsg_get_bool_or_default(tb[SERVICE_ADD_AUTO_START], false))
    {
        /* No need to send a separate 'start' message. Start it right now. */
        service_start_fresh(s);
    }

    result = service_add_success;

done:
    return result;
}

static struct ubus_method main_object_methods[] = {
    UBUS_METHOD(add_, service_handle_add_request, service_add_policy),
    UBUS_METHOD(delete_, service_handle_delete_request, service_generic_policy),
    UBUS_METHOD(start_, service_handle_start_request, service_generic_policy),
    UBUS_METHOD(stop_, service_handle_stop_request, service_generic_policy),
    UBUS_METHOD(reload_, service_handle_reload_request, service_generic_policy),
    UBUS_METHOD(restart_, service_handle_restart_request, service_generic_policy),
    UBUS_METHOD(update_, service_handle_update_request, service_update_policy),
    UBUS_METHOD(signal_, service_handle_signal_request, service_signal_policy),
    UBUS_METHOD(dump_, service_handle_dump_request, service_dump_policy),
};

static struct ubus_object_type main_object_type =
    UBUS_OBJECT_TYPE(service_, main_object_methods);

static struct ubus_object main_object = {
    .name = service_,
    .type = &main_object_type,
    .methods = main_object_methods,
    .n_methods = ARRAY_SIZE(main_object_methods),
};

static void ubus_init_service(struct ubus_context * const ctx)
{
    ubus_add_object(ctx, &main_object);
}

static void
ubus_reconnected(struct ubus_connection_ctx_st * const connection_context)
{
    struct ubus_context * const ubus_ctx = &connection_context->context;

    debug("reconnected\n");
    connection_context->connected = true;
    ubus_add_uloop(ubus_ctx);
}

static void
ubus_connected(struct ubus_connection_ctx_st * const connection_context)
{
    struct ubus_context * const ubus_ctx = &connection_context->context;

    debug("connected\n");
    connection_context->connected = true;
    ubus_init_service(ubus_ctx);
    ubus_init_log(ubus_ctx);
    ubus_add_uloop(ubus_ctx);
}

static void
ubus_disconnected(struct ubus_connection_ctx_st * const connection_context)
{
    debug("ubus disconnected\n");
    connection_context->connected = false;
}

void
serviced_ubus_init(
    struct serviced_context_st * const context, char const * const ubus_path)
{
    ubus_connection_init(
        &context->ubus_connection,
        ubus_path,
        ubus_connected,
        ubus_reconnected,
        ubus_disconnected);
}


#include "service.h"
#include "debug.h"
#include "serviced_ubus.h"
#include "string_constants.h"
#include "utils.h"

#include <fcntl.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libubox/blobmsg_json.h>

static uint32_t const default_terminate_timeout_millisecs = 100;

static inline bool
process_is_running(struct uloop_process const * const process)
{
    return process->pending;
}

static void
close_output_stream(struct ustream_fd * const stream)
{
    if (stream->fd.fd > -1)
    {
        ustream_free(&stream->stream);
        close(stream->fd.fd);
        stream->fd.fd = -1;
    }
}

static void
close_output_streams(struct service * const s)
{
    close_output_stream(&s->stdout);
    close_output_stream(&s->stderr);
}

static void
config_free(struct service_config * const config)
{
    free(config->pid_filename);
    config->pid_filename = NULL;
    free(config->command);
    config->command = NULL;
    free(config->reload_command);
    config->reload_command = NULL;
}

static void
service_free(struct service * const s)
{
    if (s == NULL)
    {
        goto done;
    }

    services_remove_service(s->ubus, s);
    close_output_streams(s);
    uloop_process_delete(&s->proc);
    uloop_timeout_cancel(&s->timeout);
    config_free(&s->config);

    free(s);

done:
    return;
}

static struct service *
service_alloc(char const * const service_name)
{
    char * name;
    struct service * const s =
        calloc_a(sizeof *s, &name, strlen(service_name) + 1);

    strcpy(name, service_name);
    s->name = name;
    s->avl.key = s->name;

    return s;
}

static int
send_signal_to_process(
    struct uloop_process const * const process, unsigned const sig)
{
    debug("Send signal %d to PID %d\n", sig, (int)process->pid);
    return kill(process->pid, sig);
}


static void
stop_running_process(struct service * const s)
{
    send_signal_to_process(&s->proc, SIGTERM);
    uloop_timeout_set(&s->timeout, s->config.terminate_timeout_millisecs);
}

static char * *
command_array_to_args(struct blob_attr * const command)
{
    /* Allow for the NULL terminator. */
    int const argc = blobmsg_array_length(command) + 1;
    char * * const argv = alloca(sizeof(*argv) * argc);
    struct blob_attr * cur;
    int rem;
    int i = 0;

    blobmsg_for_each_attr(cur, command, rem)
    {
        argv[i++] = blobmsg_get_string(cur);
    }
    argv[i] = NULL;

    return argv;
}

static void
redirect_file(int const from, int const to, int const o_flag)
{
    int const fd = (from != -1) ? from : open("/dev/null", o_flag);

    if (fd > -1)
    {
        dup2(fd, to);
        close(fd);
    }
}

static void
service_run(struct service * const s, int const stdout_fd, int const stderr_fd)
{
    /* This is called by the child process. */

    if (s->config.create_new_session)
    {
        debug("Service %s running in new session\n", s->name);
        setsid();
    }

    redirect_file(-1, STDIN_FILENO, O_RDONLY);
    redirect_file(stdout_fd, STDOUT_FILENO, O_WRONLY);
    redirect_file(stderr_fd, STDERR_FILENO, O_WRONLY);

    char * * const argv = command_array_to_args(s->config.command);

    execvp(argv[0], argv);
    exit(-1);
}

static void
assign_output_stream_to_parent(
    struct ustream_fd * const stream, int const * const pipe_fd)
{
    if (pipe_fd[0] > -1)
    {
        /* Parent wants to read this output. */
        ustream_fd_init(stream, pipe_fd[0]);
        fcntl(pipe_fd[0], F_SETFD, FD_CLOEXEC);
        /* Parent doesn't write to the outputs. */
        close(pipe_fd[1]);
    }
}

static void
initialise_pipe(int * const pipe_fd, bool const will_read_pipe)
{
    if (!will_read_pipe || pipe(pipe_fd) != 0)
    {
        pipe_fd[0] = -1;
        pipe_fd[1] = -1;
    }
}

static bool
service_start(struct service * const s)
{
    if (process_is_running(&s->proc))
    {
        debug("Service %s is already running\n", s->name);
        goto done;
    }

    close_output_streams(s);

    int stdout_pipe[2];
    int stderr_pipe[2];

    initialise_pipe(stdout_pipe, s->config.log_stdout);
    initialise_pipe(stderr_pipe, s->config.log_stderr);

    pid_t const pid = fork();

    if (pid < 0)
    {
        goto done;
    }

    if (pid == 0)
    {
        /* Child process. */
        uloop_done();
        /* The child doesn't read from its outputs. */
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        service_run(s, stdout_pipe[1], stderr_pipe[1]);
        /* Shouldn't get here. */
        goto done;
    }

    /* Parent process. */
    debug("Started service %s, PID %d\n", s->name, (int)pid);

    s->proc.pid = pid;
    write_pid_file(s->config.pid_filename, s->proc.pid);

    clock_gettime(CLOCK_MONOTONIC, &s->start_timestamp);

    uloop_process_add(&s->proc);

    assign_output_stream_to_parent(&s->stdout, stdout_pipe);
    assign_output_stream_to_parent(&s->stderr, stderr_pipe);

    if (stderr_pipe[0] > -1)
    {
        /* Parent wants to read stderr. */
        ustream_fd_init(&s->stderr, stderr_pipe[0]);
        fcntl(stderr_pipe[0], F_SETFD, FD_CLOEXEC);
        /* Parent doesn't write to the outputs. */
        close(stderr_pipe[1]);
    }

    send_service_event(s->ubus, s->name, service_has_started_);

done:
    return true;
}

static bool
service_stop(struct service * const s)
{
    bool success;

    if (process_is_running(&s->proc))
    {
        stop_running_process(s);
        success = true;
    }
    else
    {
        /*
         * Return an error so the caller can identify if the service was
         * running or not when the stop request was received.
         */
        success = false;
    }

    return success;
}

static bool
service_restart(struct service * const s)
{
    if (process_is_running(&s->proc))
    {
        s->restart_after_exit = true;
        stop_running_process(s);
    }
    else
    {
        service_start(s);
    }

    return true;

}

static bool
service_delete(struct service * const s)
{
    /*
     * Service must be stopped before it be deleted. The process exit handler
     * will call this function again once the process exits.
     */
    if (process_is_running(&s->proc))
    {
        s->delete_after_exit = true;
        service_stop(s);
    }
    else
    {
        send_service_event(s->ubus, s->name, service_deleted_);
        service_free(s);
    }

    return true;
}

static int
service_send_signal(struct service const * const s, unsigned const sig)
{
    int res;

    if (!process_is_running(&s->proc))
    {
        debug("Service %s not running. can't send signal\n", s->name);
        res = UBUS_STATUS_OK;
        goto done;
    }

    if (send_signal_to_process(&s->proc, sig) == 0)
    {
        res = UBUS_STATUS_OK;
        goto done;
    }

    switch (errno)
    {
    case EINVAL:
        res = UBUS_STATUS_INVALID_ARGUMENT;
        goto done;
    case EPERM:
        res = UBUS_STATUS_PERMISSION_DENIED;
        goto done;
    case ESRCH:
        res = UBUS_STATUS_NOT_FOUND;
        goto done;
    }

    res = UBUS_STATUS_UNKNOWN_ERROR;

done:
    return res;
}

static bool
service_reload(struct service * const s, struct blob_attr * const msg)
{
    if (process_is_running(&s->proc))
    {
        if (s->config.reload_signal != 0)
        {
            service_send_signal(s, s->config.reload_signal);
        }
        else if (s->config.reload_command != NULL)
        {
            debug("need reload command support\n");
            /*
             * Run this command to get the service config reloaded.
             * An example of the command to run might be something like a
             * ubus call service reload.
             */
            /* Temp debug, just restart the service. */
            s->restart_after_exit = true;
            service_stop(s);
        }
        else
        {
            /*
             * The service doesn't support reload via a signal or command, so
             * it must be restarted instead.
             */
            s->restart_after_exit = true;
            service_stop(s);
        }
    }
    else
    {
        /* The service isnt' running, so may as well just start it. */
        service_start(s);
    }

    return true;
}

static void
service_has_stopped(struct service * const s)
{
    send_service_event(s->ubus, s->name, service_has_stopped_);
    if (s->delete_after_exit)
    {
        s->delete_after_exit = false;
        service_delete(s);
        /* s will be invalid at this point if it has been deleted. */
    }
    else if (s->restart_after_exit)
    {
        s->restart_after_exit = false;
        service_start(s);
    }
}

static void
stderr_reader(struct ustream * const s, int const bytes)
{
    do
    {
        int len;
        char const * const buf = ustream_get_read_buf(s, &len);

        if (buf == NULL)
        {
            break;
        }

        debug("%s", buf);
        /* Log it? */
        ustream_consume(s, len);
    } while (1);
}

static void
stdout_reader(struct ustream * const s, int const bytes)
{
    do
    {
        int len;
        char const * const buf = ustream_get_read_buf(s, &len);

        if (buf == NULL)
        {
            break;
        }
#if DEBUG
        time_t t = time(NULL);
        struct tm tm = *localtime(&t);
        debug("%d-%02d-%02d %02d:%02d:%02d: ",
              tm.tm_year + 1900,
              tm.tm_mon + 1,
              tm.tm_mday,
              tm.tm_hour,
              tm.tm_min,
              tm.tm_sec);

        debug("%s", buf);
#endif
        /* Log it? */
        ustream_consume(s, len);
    } while (1);
}

static void
service_timeout(struct uloop_timeout * const t)
{
    struct service * const s =
        container_of(t, struct service, timeout);

    debug("service %s pid %d didn't stop on SIGTERM, sending SIGKILL.\n",
          s->name, s->proc.pid);

    send_signal_to_process(&s->proc, SIGKILL);
}

static int
service_exit_code(int const ret)
{
    int exit_code;

    if (WIFEXITED(ret))
    {
        exit_code = WEXITSTATUS(ret);
        goto done;
    }

    if (WIFSIGNALED(ret))
    {
        exit_code = WTERMSIG(ret);
        goto done;
    }

    if (WIFSTOPPED(ret))
    {
        exit_code = WSTOPSIG(ret);
        goto done;
    }

    exit_code = EXIT_FAILURE;

done:
    return exit_code;
}

static uint32_t
service_runtime_seconds(struct service const * const s)
{
    struct timespec tp;

    clock_gettime(CLOCK_MONOTONIC, &tp);
    long const runtime_seconds = tp.tv_sec - s->start_timestamp.tv_sec;

    return runtime_seconds;
}

static void
service_has_exited(struct uloop_process * p, int exit_code)
{
    struct service * const s =
        container_of(p, struct service, proc);
    uint32_t const runtime_seconds = service_runtime_seconds(s);

    debug("Service %s exited with error code %d after %" PRIu32 " seconds\n",
          s->name, exit_code, runtime_seconds);

    s->last_exit_code = service_exit_code(exit_code);
    s->last_runtime_seconds = runtime_seconds;

    uloop_timeout_cancel(&s->timeout);
    remove_pid_file(s->config.pid_filename);
    service_has_stopped(s);
    /*
     * 's' may be invalid after this call if was deleted once the process
     * stopped after handling a 'delete' request.
     */
}

static void
service_init(struct service * const s, struct ubus_context * const ubus)
{
    debug("%s\n", __func__);
    s->ubus = ubus;

    s->timeout.cb = service_timeout;
    s->proc.cb = service_has_exited;
    s->last_exit_code = EXIT_SUCCESS;

    s->stdout.fd.fd = -1;
    s->stdout.stream.string_data = true;
    s->stdout.stream.notify_read = stdout_reader;

    s->stderr.fd.fd = -1;
    s->stderr.stream.string_data = true;
    s->stderr.stream.notify_read = stderr_reader;
}

enum {
    SERVICE_CONFIG_COMMAND,
    SERVICE_CONFIG_RELOAD_COMMAND,
    SERVICE_CONFIG_STDOUT,
    SERVICE_CONFIG_STDERR,
    SERVICE_CONFIG_PIDFILE,
    SERVICE_CONFIG_RELOADSIG,
    SERVICE_CONFIG_TERMTIMEOUT,
    SERVICE_CONFIG_NEW_SESSION,
    __SERVICE_CONFIG_MAX,
};

static const struct blobmsg_policy service_config_policy[__SERVICE_CONFIG_MAX] = {
    [SERVICE_CONFIG_COMMAND] = { command_, BLOBMSG_TYPE_ARRAY },
    [SERVICE_CONFIG_RELOAD_COMMAND] = { reload_command_, BLOBMSG_TYPE_ARRAY },
    [SERVICE_CONFIG_STDOUT] = { stdout_, BLOBMSG_TYPE_BOOL },
    [SERVICE_CONFIG_STDERR] = { stderr_, BLOBMSG_TYPE_BOOL },
    [SERVICE_CONFIG_PIDFILE] = { pid_file_, BLOBMSG_TYPE_STRING },
    [SERVICE_CONFIG_RELOADSIG] = { reload_signal_, BLOBMSG_TYPE_INT32 },
    [SERVICE_CONFIG_TERMTIMEOUT] = { terminate_timeout_millisecs_, BLOBMSG_TYPE_INT32 },
    [SERVICE_CONFIG_NEW_SESSION] = { new_session_, BLOBMSG_TYPE_BOOL }
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

static bool
parse_config(struct service_config * const config, struct blob_attr * const msg)
{
    bool success;
    struct blob_attr * tb[__SERVICE_CONFIG_MAX];

    debug("%s\n", __func__);

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
    if (tb[SERVICE_CONFIG_RELOAD_COMMAND])
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
    if (tb[SERVICE_CONFIG_PIDFILE])
    {
        config->pid_filename =
            strdup(blobmsg_get_string(tb[SERVICE_CONFIG_PIDFILE]));
    }
    config->log_stdout =
        blobmsg_get_bool_or_default(tb[SERVICE_CONFIG_STDOUT], false);
    config->log_stderr =
        blobmsg_get_bool_or_default(tb[SERVICE_CONFIG_STDERR], false);
    config->create_new_session =
        blobmsg_get_bool_or_default(tb[SERVICE_CONFIG_NEW_SESSION], false);

    success = true;

done:
    return success;
}

enum {
    SERVICE_ADD_NAME,
    SERVICE_ADD_AUTO_START,
    __SERVICE_ADD_MAX,
};

static const struct blobmsg_policy service_add_policy[__SERVICE_ADD_MAX] = {
    [SERVICE_ADD_NAME] = { name_, BLOBMSG_TYPE_STRING },
    [SERVICE_ADD_AUTO_START] = { auto_start_, BLOBMSG_TYPE_BOOL },
};

static int
service_handle_add_request(
    struct ubus_context * const ctx,
    struct ubus_object * const obj,
    struct ubus_request_data * const req,
    char const * const method,
    struct blob_attr * const msg)
{
    struct blob_attr * tb[__SERVICE_ADD_MAX];
    int result;

    blobmsg_parse(service_add_policy, __SERVICE_ADD_MAX, tb,
                  blobmsg_data(msg), blobmsg_data_len(msg));

    char const * service_name = blobmsg_get_string(tb[SERVICE_ADD_NAME]);

    if (service_name == NULL)
    {
        result = UBUS_STATUS_INVALID_ARGUMENT;
        goto done;
    }

    if (services_lookup_service(ctx, service_name) != NULL)
    {
        debug("Service %s already exists\n", service_name);
        result = UBUS_STATUS_INVALID_ARGUMENT;
        goto done;
    }

    debug("Create new service %s\n", service_name);

    struct service * const s = service_alloc(service_name);

    if (s == NULL)
    {
        result = UBUS_STATUS_UNKNOWN_ERROR;
        goto done;
    }

    service_init(s, ctx);

    if (!parse_config(&s->config, msg))
    {
        debug("Invalid config for service %s\n", s->name);
        service_free(s);
        result = UBUS_STATUS_INVALID_ARGUMENT;
        goto done;
    }

    services_insert_service(ctx, s);
    send_service_event(s->ubus, s->name, service_added_);

    if (blobmsg_get_bool_or_default(tb[SERVICE_ADD_AUTO_START], false))
    {
        /* No need to send a separate 'start' message. Start it right now. */
        service_start(s);
    }

    result = UBUS_STATUS_OK;

done:
    return result;
}

static bool
handle_request_method(
    struct service * const s,
    char const * const method,
    struct blob_attr * const msg)
{
    bool success;

    /* FIXME: Not keen on this long if/else if chain. */
    if (strcmp(method, start_) == 0)
    {
        success = service_start(s);
    }
    else if (strcmp(method, stop_) == 0)
    {
        success = service_stop(s);
    }
    else if (strcmp(method, restart_) == 0)
    {
        success = service_restart(s);
    }
    else if (strcmp(method, delete_) == 0)
    {
        success = service_delete(s);
    }
    else if (strcmp(method, reload_) == 0)
    {
        success = service_reload(s, msg);
    }
    else
    {
        success = false;
    }

    return success;
}

enum {
    SERVICE_START_STOP_NAME,
    __SERVICE_START_STOP_MAX
};

static const struct blobmsg_policy service_start_stop_restart_policy[__SERVICE_START_STOP_MAX] = {
    [SERVICE_START_STOP_NAME] = { name_, BLOBMSG_TYPE_STRING },
};

static int
service_handle_start_stop_restart_request(
    struct ubus_context * const ctx,
    struct ubus_object * const obj,
    struct ubus_request_data * const req,
    char const * const method,
    struct blob_attr * const msg)
{
    struct blob_attr * tb[__SERVICE_START_STOP_MAX];
    int result;

    blobmsg_parse(service_start_stop_restart_policy, __SERVICE_START_STOP_MAX, tb,
                  blobmsg_data(msg), blobmsg_data_len(msg));

    char const * service_name = blobmsg_get_string(tb[SERVICE_START_STOP_NAME]);

    if (service_name == NULL)
    {
        result = UBUS_STATUS_INVALID_ARGUMENT;
        goto done;
    }

    struct service * const s = services_lookup_service(ctx, service_name);

    if (s == NULL)
    {
        debug("Service %s not found\n", service_name);
        result = UBUS_STATUS_NOT_FOUND;
        goto done;
    }

    if (!handle_request_method(s, method, msg))
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

    struct service * const s = services_lookup_service(ctx, service_name);

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
service_dump(struct service const * const s, struct blob_buf * const b)
{
    void * const cookie = blobmsg_open_table(b, s->name);

    /* Dump some state. */
    blobmsg_add_u8(b, running_, process_is_running(&s->proc));
    if (process_is_running(&s->proc))
    {
        blobmsg_add_u32(b, pid_, s->proc.pid);
        blobmsg_add_u32(b, runtime_seconds_, service_runtime_seconds(s));
    }
    else
    {
        blobmsg_add_u32(b, last_exit_code_, s->last_exit_code);
        blobmsg_add_u32(b, runtime_seconds_, s->last_runtime_seconds);
    }

    /* Dump some of the configuration so it's possible to check it. */
    blobmsg_add_blob(b, s->config.command);
    if (s->config.reload_command != NULL)
    {
        blobmsg_add_blob(b, s->config.reload_command);
    }
    blobmsg_add_u32(b, terminate_timeout_millisecs_, s->config.terminate_timeout_millisecs);
    blobmsg_add_u8(b, log_stdout_, s->config.log_stdout);
    blobmsg_add_u8(b, log_stderr_, s->config.log_stderr);
    blobmsg_add_u8(b, new_session_, s->config.create_new_session);
    if (s->config.pid_filename != NULL)
    {
        blobmsg_add_string(b, pid_file_, s->config.pid_filename);
    }

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

    return 0;
}

static struct ubus_method main_object_methods[] = {
    UBUS_METHOD(add_, service_handle_add_request, service_add_policy),
    UBUS_METHOD(delete_, service_handle_start_stop_restart_request, service_start_stop_restart_policy),
    UBUS_METHOD(start_, service_handle_start_stop_restart_request, service_start_stop_restart_policy),
    UBUS_METHOD(stop_, service_handle_start_stop_restart_request, service_start_stop_restart_policy),
    UBUS_METHOD(reload_, service_handle_start_stop_restart_request, service_start_stop_restart_policy),
    UBUS_METHOD(restart_, service_handle_start_stop_restart_request, service_start_stop_restart_policy),
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

void ubus_init_service(struct ubus_context * const ctx)
{
    ubus_add_object(ctx, &main_object);
}

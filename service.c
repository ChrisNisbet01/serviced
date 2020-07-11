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
static uint32_t const default_restart_delay_millisecs = 10;

static inline bool
process_is_running(struct uloop_process const * const process)
{
    return process->pending;
}

static bool
service_is_running(struct service const * const s)
{
    return process_is_running(&s->service_process);
}

static inline bool
timer_is_running(struct uloop_timeout const * const timer)
{
    return timer->pending;
}

static inline bool
service_is_stopping(struct service const * const s)
{
    return timer_is_running(&s->timeout);
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
config_free(struct service_config const * const config_in)
{
    if (config_in == NULL)
    {
        goto done;
    }

    struct service_config * const config = UNCONST(config_in);

    free(UNCONST(config->pid_filename));
    config->pid_filename = NULL;

    free(UNCONST(config->config_filename));
    config->config_filename = NULL;

    free(config->command);
    config->command = NULL;
    free(config->reload_command);
    config->reload_command = NULL;

    free(config);

done:
    return;
}

static void
service_free(struct service * const s)
{
    if (s == NULL)
    {
        goto done;
    }

    debug("%s: %s\n", __func__, s->name);

    services_remove_service(s->ubus, s);

    file_monitor_close(s->config_file_monitor);

    close_output_streams(s);
    uloop_process_delete(&s->service_process);
    uloop_process_delete(&s->reload_process);
    uloop_timeout_cancel(&s->timeout);
    uloop_timeout_cancel(&s->restart_state.delay_timeout);
    config_free(s->config);
    config_free(s->next_config);

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
stop_running_process(struct service * const s, stop_reason_t const stop_reason)
{
    send_signal_to_process(&s->service_process, SIGTERM);

    struct service_config const * const config = s->config;

    uloop_timeout_set(&s->timeout, config->terminate_timeout_millisecs);
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
redirect_fd(int const from, int const to, int const o_flag)
{
    int const fd = (from != -1) ? from : open("/dev/null", o_flag);

    if (fd > -1)
    {
        TEMP_FAILURE_RETRY(dup2(fd, to));
        close(fd);
    }
}

static void
run_command(struct blob_attr * command, int const stdout_fd, int const stderr_fd)
{
    /* This is called by the child process. */

    redirect_fd(-1, STDIN_FILENO, O_RDONLY);
    redirect_fd(stdout_fd, STDOUT_FILENO, O_WRONLY);
    redirect_fd(stderr_fd, STDERR_FILENO, O_WRONLY);

    char * * const argv = command_array_to_args(command);

    execvp(argv[0], argv);
    exit(-1);
}

static void
service_run(struct service * const s, int const stdout_fd, int const stderr_fd)
{
    /* This is called by the child process. */
    struct service_config const * const config = s->config;

    if (config->create_new_session)
    {
        debug("Service %s running in new session\n", s->name);
        setsid();
    }

    run_command(config->command, stdout_fd, stderr_fd);
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
    struct service_config const * const config = s->config;

    if (service_is_running(s))
    {
        debug("Service %s is already running\n", s->name);
        goto done;
    }

    close_output_streams(s);

    int stdout_pipe[2];
    int stderr_pipe[2];

    initialise_pipe(stdout_pipe, config->log_stdout);
    initialise_pipe(stderr_pipe, config->log_stderr);

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

    s->service_process.pid = pid;
    write_pid_file(config->pid_filename, s->service_process.pid);

    clock_gettime(CLOCK_MONOTONIC, &s->start_timestamp);

    uloop_process_add(&s->service_process);

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

static void
restart_state_initialise(struct restart_state_st * const restart)
{
    uloop_timeout_cancel(&restart->delay_timeout);
    restart->crash_count = 0;
}

static bool
service_start_fresh(struct service * const s)
{
    restart_state_initialise(&s->restart_state);

    return service_start(s);
}

static bool
service_stop(struct service * const s, stop_reason_t const stop_reason)
{
    bool success;

    if (service_is_running(s))
    {
        s->stop_reason = stop_reason;
        if (!service_is_stopping(s))
        {
            send_service_event(s->ubus, s->name, service_stopping_);
            stop_running_process(s, stop_reason);
        }
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
    if (service_is_running(s))
    {
        service_stop(s, stop_reason_restarting);
    }
    else
    {
        service_start_fresh(s);
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
    if (service_is_running(s))
    {
        service_stop(s, stop_reason_deleting);
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

    if (!service_is_running(s))
    {
        debug("Service %s not running. can't send signal\n", s->name);
        res = UBUS_STATUS_OK;
        goto done;
    }

    if (send_signal_to_process(&s->service_process, sig) == 0)
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

static void
reload_process_has_exited(struct uloop_process * p, int exit_code)
{
#if DEBUG != 0
    struct service * const s =
        container_of(p, struct service, reload_process);

    debug("Service %s reload process has exited with code: %d\n",
          s->name,
          service_exit_code(exit_code));
#endif
}

static void
reload_command_run(struct service * const s)
{
    pid_t const pid = fork();

    if (pid < 0)
    {
        goto done;
    }

    if (pid == 0)
    {
        struct service_config const * const config = s->config;

        /* Child process. */
        uloop_done();
        run_command(config->reload_command, -1, -1);
        /* Shouldn't get here. */
        goto done;
    }

    /* Parent process. */
    debug("%s: running reload command, PID %d\n", s->name, (int)pid);

    s->reload_process.pid = pid;

    uloop_process_add(&s->reload_process);

done:
    return;
}

static bool
service_reload(struct service * const s)
{
    if (service_is_running(s))
    {
        struct service_config const * const config = s->config;

        if (config->reload_signal != 0)
        {
            service_send_signal(s, config->reload_signal);
        }
        else if (config->reload_command != NULL)
        {
            reload_command_run(s);
        }
        else
        {
            /*
             * The service doesn't support reload via a signal or command, so
             * it must be restarted instead.
             */
            service_stop(s, stop_reason_restarting);
        }
    }
    else
    {
        /*
         * The service isn't running, so may as well just start it.
         * If the caller wants to reload the config, surely he expects it to
         * be running.
         */
        service_start_fresh(s);
    }

    return true;
}

static bool
commands_match(struct blob_attr const * const a, struct blob_attr const * const b)
{
    return blob_attr_equal(a, b);
}

static bool filenames_match(char const * const a, char const * const b)
{
    bool match;

    if (((a == NULL) ^ (b == NULL)) || (a != NULL && strcmp(a, b) != 0))
    {
        match = false;
    }
    else
    {
        match = true;
    }

    return match;
}

static bool
configs_match(
    struct service_config const * const a, struct service_config const * b)
{
    bool match;

    if (!commands_match(a->command, b->command))
    {
        match = false;
        goto done;
    }
    if (!commands_match(a->reload_command, b->reload_command))
    {
        match = false;
        goto done;
    }

    if (!filenames_match(a->pid_filename, b->pid_filename))
    {
        match = false;
        goto done;
    }

    if (!filenames_match(a->config_filename, b->config_filename))
    {
        match = false;
        goto done;
    }

    if (a->terminate_timeout_millisecs != b->terminate_timeout_millisecs)
    {
        match = false;
        goto done;
    }
    if (a->log_stdout != b->log_stdout)
    {
        match = false;
        goto done;
    }
    if (a->log_stderr != b->log_stderr)
    {
        match = false;
        goto done;
    }
    if (a->create_new_session != b->create_new_session)
    {
        match = false;
        goto done;
    }
    if (a->reload_signal != b->reload_signal)
    {
        match = false;
        goto done;
    }

    match = true;

done:
    return match;
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

static void service_update_config(struct service * const s)
{
    if (s->next_config != NULL)
    {
        config_free(s->config);
        s->config = s->next_config;
        s->next_config = NULL;
    }
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

static void
service_stopped_unexpectedly(struct service * const s)
{
    struct service_config const * const config = s->config;
    struct restart_config_st const * const restart_config = &config->restart;
    bool const interested_in_crashes = restart_config->crash_threshold_secs > 0;

    if (interested_in_crashes)
    {
        bool const failed_to_start =
            s->last_runtime_seconds < restart_config->crash_threshold_secs;
        struct restart_state_st * const restart_state = &s->restart_state;

        if (failed_to_start)
        {
            restart_state->crash_count++;
            send_service_event(s->ubus, s->name, service_failed_to_start_);
        }
        else
        {
            restart_state->crash_count = 0;
        }

        bool const restricting_crashes = restart_config->max_crashes > 0;

        if (restricting_crashes)
        {
            bool const too_many_consecutive_crashes =
                restart_state->crash_count >= restart_config->max_crashes;

            if (too_many_consecutive_crashes)
            {
                send_service_event(s->ubus, s->name, service_reached_crash_limit_);
            }
            else
            {
                /* This will be true even if the service was stopped manually.
                 * It might be better to have a configuration parameter to
                 * indicate if the service should restart after it has been
                 * stopped by way of UBUS request.
                 */
                uloop_timeout_set(
                    &restart_state->delay_timeout, restart_config->delay_millisecs);
            }
        }
    }

    service_update_config(s);
}

static void
service_has_stopped(struct service * const s)
{
    send_service_event(s->ubus, s->name, service_has_stopped_);
    stop_reason_t const stop_reason = s->stop_reason;

    s->stop_reason = stop_reason_none;
    if (stop_reason == stop_reason_deleting)
    {
        service_delete(s);
        /* s will be invalid at this point if it has been deleted. */
    }
    else if (stop_reason == stop_reason_restarting)
    {
        service_update_config(s);
        service_start_fresh(s);
    }
    else if (stop_reason == stop_reason_request)
    {
        service_update_config(s);
    }
    else
    {
        service_stopped_unexpectedly(s);
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
        debug("%s", buf);
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
          s->name, s->service_process.pid);

    send_signal_to_process(&s->service_process, SIGKILL);
}

static void
restart_delay_timeout(struct uloop_timeout * const t)
{
    struct service * const s =
        container_of(t, struct service, restart_state.delay_timeout);

    debug("service %s restart timer lapsed. Restarting service\n", s->name);

    service_start(s);
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
        container_of(p, struct service, service_process);
    struct service_config const * const config = s->config;
    uint32_t const runtime_seconds = service_runtime_seconds(s);

    debug("Service %s exited with error code %d after %" PRIu32 " seconds\n",
          s->name, exit_code, runtime_seconds);

    s->last_exit_code = service_exit_code(exit_code);
    s->last_runtime_seconds = runtime_seconds;

    uloop_timeout_cancel(&s->timeout);
    remove_pid_file(config->pid_filename);
    service_has_stopped(s);
    /*
     * 's' may be invalid after this call if was deleted once the process
     * stopped after handling a 'delete' request.
     */
}

static void
config_file_timeout(void * const user_ctx)
{
    struct service * const s = user_ctx;

    debug("%s: service %s pid %d\n", __func__, s->name, s->service_process.pid);

    send_service_event(s->ubus, s->name, service_config_file_has_changed_);

    service_reload(s);
}

static void
service_init(struct service * const s, struct ubus_context * const ubus)
{
    debug("%s\n", __func__);
    s->ubus = ubus;

    s->timeout.cb = service_timeout;
    s->restart_state.delay_timeout.cb = restart_delay_timeout;
    s->service_process.cb = service_has_exited;
    s->reload_process.cb = reload_process_has_exited;
    s->last_exit_code = EXIT_SUCCESS;

    s->stdout.fd.fd = -1;
    s->stdout.stream.string_data = true;
    s->stdout.stream.notify_read = stdout_reader;

    s->stderr.fd.fd = -1;
    s->stderr.stream.string_data = true;
    s->stderr.stream.notify_read = stderr_reader;

    s->config_file_monitor = NULL;
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

    s->config = parse_config(msg);
    if (s->config == NULL)
    {
        debug("Invalid config for service %s\n", s->name);
        service_free(s);
        result = UBUS_STATUS_INVALID_ARGUMENT;
        goto done;
    }

    services_insert_service(ctx, s);
    send_service_event(s->ubus, s->name, service_added_);

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
        success = service_start_fresh(s);
    }
    else if (strcmp(method, stop_) == 0)
    {
        success = service_stop(s, stop_reason_request);
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
        success = service_reload(s);
    }
    else if (strcmp(method, update_) == 0)
    {
        success = service_update(s, msg);
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

static struct ubus_method main_object_methods[] = {
    UBUS_METHOD(add_, service_handle_add_request, service_add_policy),
    UBUS_METHOD(delete_, service_handle_start_stop_restart_request, service_start_stop_restart_policy),
    UBUS_METHOD(start_, service_handle_start_stop_restart_request, service_start_stop_restart_policy),
    UBUS_METHOD(stop_, service_handle_start_stop_restart_request, service_start_stop_restart_policy),
    UBUS_METHOD(reload_, service_handle_start_stop_restart_request, service_start_stop_restart_policy),
    UBUS_METHOD(restart_, service_handle_start_stop_restart_request, service_start_stop_restart_policy),
    UBUS_METHOD(update_, service_handle_start_stop_restart_request, service_start_stop_restart_policy),
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

#include "service.h"
#include "debug.h"
#include "early_start.h"
#include "serviced_ubus.h"
#include "string_constants.h"
#include "utils.h"

#include <ubus_utils/ubus_utils.h>
#include <libubox/avl-cmp.h>
#include <libubox/blobmsg_json.h>
#include <libubox/ulog.h>

#include <fcntl.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void
close_output_streams(struct service * const s)
{
    close_output_stream(&s->stdout);
    close_output_stream(&s->stderr);
}

static void
restart_state_initialise(struct restart_state_st * const restart)
{
    uloop_timeout_cancel(&restart->delay_timeout);
    restart->crash_count = 0;
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

static char * *
command_array_to_args(struct blob_attr * const command, char * * const argv)
{
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

static void debug_print_command_args(char * * const argv)
{
    for (char const * parg = argv[0]; parg != NULL; parg++)
    {
        debug("arg: %s\n", parg);
    }
}

static void
run_command(struct blob_attr * command, int const stdout_fd, int const stderr_fd)
{
    /* This is called by the child process. */

    redirect_fd(-1, STDIN_FILENO, O_RDONLY);
    redirect_fd(stdout_fd, STDOUT_FILENO, O_WRONLY);
    redirect_fd(stderr_fd, STDERR_FILENO, O_WRONLY);

    /* Allow for the NULL terminator. */
    int const argc = blobmsg_array_length(command) + 1;
    char * * const argv = calloc(argc, sizeof(*argv));

    command_array_to_args(command, argv);

    debug_print_command_args(argv);

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

    send_service_event(s, service_has_started_);

done:
    return true;
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
            send_service_event(s, service_failed_to_start_);
        }
        else
        {
            restart_state->crash_count = 0;
        }

        bool const restricting_crashes = restart_config->max_crashes > 0;
        bool const too_many_consecutive_crashes =
            restart_state->crash_count >= restart_config->max_crashes;

        if (restricting_crashes && too_many_consecutive_crashes)
        {
            send_service_event(s, service_reached_crash_limit_);
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

    service_update_config(s);
}

static void
service_has_stopped(struct service * const s)
{
    send_service_event(s, service_has_stopped_);
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
reload_process_has_exited(struct uloop_process * const p, int const exit_code)
{
#if DEBUG != 0
    struct service * const s =
        container_of(p, struct service, reload_process);

    debug("Service %s reload process has exited with code: %d\n",
          s->name,
          service_exit_code(exit_code));
#else
    UNUSED_ARG(p);
    UNUSED_ARG(exit_code);
#endif
}

char const *
command_request_to_string(command_request_t const command_request)
{
    char const * command_names[command_request_COUNT] =
    {
        [command_request_stop] = stop_,
        [command_request_start] = start_,
        [command_request_restart] = restart_
    };
    char const * command_name =
        command_request < command_request_COUNT
        ? command_names[command_request]
        : "unknown";

    return command_name;
}

void
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

static void
write_to_log_files(
    struct logging_st * const logging, char const * const buf, size_t const len)
{
    for (size_t i = 0; i < logging->num_used; i++)
    {
        struct log_file_entry_st * const entry = &logging->entries[i];

        if (entry->fp != NULL)
        {
            if (fwrite(buf, 1, len, entry->fp) != len)
            {
                fclose(entry->fp);
                entry->fp = NULL;
            }
        }
    }
}

static void
stderr_reader(struct ustream * const stream, int const bytes)
{
    UNUSED_ARG(bytes);

    struct service * const s =
        container_of(stream, struct service, stderr.stream);
    int len;
    char const * const buf = ustream_get_read_buf(stream, &len);

    if (buf != NULL && len >= 0)
    {
        ULOG_INFO("read %s and len %d\n", buf, len);

        write_to_log_files(&s->logging , buf, (size_t)len);
        debug_output_write_to_debug_apps(s->context->debug_output_context, buf);

        ustream_consume(stream, len);
    }
}

static void
stdout_reader(struct ustream * const stream, int const bytes)
{
    UNUSED_ARG(bytes);

    struct service * const s =
        container_of(stream, struct service, stdout.stream);
    int len;
    char const * const buf = ustream_get_read_buf(stream, &len);

    if (buf != NULL && len >= 0)
    {
        ULOG_INFO("read %s and len %d\n", buf, len);

        write_to_log_files(&s->logging , buf, (size_t)len);
        debug_output_write_to_debug_apps(s->context->debug_output_context, buf);

        ustream_consume(stream, len);
    }
}

static void
service_init(struct service * const s, struct serviced_context_st * const context)
{
    debug("%s\n", __func__);
    s->context = context;

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

static void
stop_running_process(struct service * const s, stop_reason_t const stop_reason)
{
    UNUSED_ARG(stop_reason);

    send_signal_to_process(&s->service_process, SIGTERM);

    struct service_config const * const config = s->config;

    uloop_timeout_set(&s->timeout, config->terminate_timeout_millisecs);
}

void
services_insert_service(
    struct serviced_context_st * const context, struct service * const s)
{
    avl_insert(&context->services, &s->avl);
    s->in_avl = true;

    send_service_event(s, service_added_);
}

void
services_remove_service(struct service * const s)
{
    struct serviced_context_st * const context = s->context;

    if (s->in_avl)
    {
        avl_delete(&context->services, &s->avl);
        s->in_avl = false;
    }
}

struct service *
services_lookup_service(
    struct serviced_context_st * const context, char const * const service_name)
{
    struct service * s; /* Required by avl_find_element. */

    return avl_find_element(&context->services, service_name, s, avl);
}

void
services_iterate(
    struct ubus_context * const ubus,
    services_iterate_cb const cb,
    void * const user_ctx)
{
    struct serviced_context_st * const context =
        container_of(ubus, struct serviced_context_st, ubus_state.ubus_connection.context);
    struct service * s;

    avl_for_each_element(&context->services, s, avl)
    {
        cb(s, user_ctx);
    }
}

struct service *
service_new(
    struct serviced_context_st * const context, char const * const service_name)
{
    struct service * const s = service_alloc(service_name);

    if (s == NULL)
    {
        goto done;
    }


    service_init(s, context);

done:
    return s;
}

bool
service_start_fresh(struct service * const s)
{
    restart_state_initialise(&s->restart_state);

    return service_start(s);
}

static void close_log_files(struct logging_st * const logging)
{
    for (size_t i = 0; i < logging->num_used; i++)
    {
        struct log_file_entry_st * const entry = &logging->entries[i];

        if (entry->fp != NULL)
        {
            fclose(entry->fp);
        }
        free(UNCONST(entry->filename));
    }
    free(logging->entries);
}

static void
service_process_logging_disable_request(
    struct service * const s, char const * const filename)
{
    struct logging_st * logging = &s->logging;
    size_t i;

    for (i = 0; i < logging->num_used; i++)
    {
        struct log_file_entry_st * const entry = &logging->entries[i];

        if (entry->filename != NULL && strcmp(entry->filename, filename) == 0)
        {
            if (entry->fp != NULL)
            {
                fclose(entry->fp);
                entry->fp = NULL;
            }
            free(UNCONST(entry->filename));
            entry->filename = NULL;
            break;
        }
    }

    if (i < logging->num_used)
    {
        /* Shift the subsequent entries down, leaving the space at the end. */
        i++;
        for (; i < logging->num_used; i++)
        {
            struct log_file_entry_st * const previous_entry =
                &logging->entries[i - 1];
            struct log_file_entry_st * const entry =
                &logging->entries[i];

            previous_entry->filename = entry->filename;
            entry->filename = NULL;
            previous_entry->fp = entry->fp;
            entry->fp = NULL;
        }
        logging->num_used--;
    }
}

static void
service_process_logging_enable_request(
    struct service * const s, char const * const filename)
{
    /*
     * When processing a request to enable logging, first close any existing
     * log to this filename because there may have been some issue with writing
     * to the file.
     */
    service_process_logging_disable_request(s, filename);
    /* At this point the file isn't being logged. */
    struct logging_st * logging = &s->logging;

    if (logging->num_used == logging->size)
    {
        size_t new_count = logging->size + 1;
        struct log_file_entry_st * const new_entries =
            calloc(sizeof *new_entries, new_count);

        if (new_entries == NULL)
        {
            goto done;
        }
        if (logging->entries != NULL)
        {
            memcpy(new_entries,
                   logging->entries,
                   sizeof(*logging->entries) * logging->size);
        }
        free(logging->entries);
        logging->entries = new_entries;
        logging->size++;
    }

    struct log_file_entry_st * const entry =
        &logging->entries[logging->num_used];

    memset(entry, 0, sizeof *entry);
    entry->filename = strdup(filename);
    if (entry->filename == NULL)
    {
        goto done;
    }
    entry->fp = fopen(entry->filename, "a");
    if (entry->fp == NULL)
    {
        free(UNCONST(entry->filename));
        entry->filename = NULL;
        goto done;
    }
    setvbuf(entry->fp, NULL, _IONBF, 0);
    logging->num_used++;

done:
    return;
}

void
service_process_logging_request(
    struct service * const s, char const * const filename, bool const enable)
{
    if (!enable)
    {
        service_process_logging_disable_request(s, filename);
    }
    else
    {
        service_process_logging_enable_request(s, filename);
    }
}

void
service_free(struct service * const s)
{
    if (s == NULL)
    {
        goto done;
    }

    debug("%s: %s\n", __func__, s->name);

    send_service_event(s, service_deleted_);
    services_remove_service(s);

    file_monitor_close(s->config_file_monitor);

    close_output_streams(s);
    uloop_process_delete(&s->service_process);
    uloop_process_delete(&s->reload_process);
    uloop_timeout_cancel(&s->timeout);
    uloop_timeout_cancel(&s->restart_state.delay_timeout);
    config_free(s->config);
    config_free(s->next_config);

    close_log_files(&s->logging);

    free(s);

done:
    return;
}

bool
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
        service_free(s);
    }

    return true;
}

void
service_update_config(struct service * const s)
{
    if (s->next_config != NULL)
    {
        config_free(s->config);
        s->config = s->next_config;
        s->next_config = NULL;
    }
}

bool
configs_match(
    struct service_config const * const a, struct service_config const * const b)
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

void
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

bool
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
        /* TODO: Make this configurable? */
        service_start_fresh(s);
    }

    return true;
}

bool
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

bool
process_is_running(struct uloop_process const * const process)
{
    return process->pending;
}

bool
service_is_running(struct service const * const s)
{
    return process_is_running(&s->service_process);
}

uint32_t
service_runtime_seconds(struct service const * const s)
{
    struct timespec tp;

    clock_gettime(CLOCK_MONOTONIC, &tp);
    long const runtime_seconds = tp.tv_sec - s->start_timestamp.tv_sec;

    return runtime_seconds;
}

bool
timer_is_running(struct uloop_timeout const * const timer)
{
    return timer->pending;
}

bool
service_is_stopping(struct service const * const s)
{
    return timer_is_running(&s->timeout);
}

void
send_service_event(struct service const * const s, char const * const event)
{
    struct blob_buf b;

    ULOG_INFO("service: %s event: %s\n", s->name, event);

    debug_output_write_to_debug_apps(
        s->context->debug_output_context, "service: %s event: %s\n", s->name, event);

    if (!s->context->ubus_state.connected)
    {
        goto done;
    }

    blob_buf_full_init(&b, 0);
    blobmsg_add_string(&b, service_, s->name);
    ubus_send_event(&s->context->ubus_state.ubus_connection.context, event, b.head);
    blob_buf_free(&b);

done:
    return;
}

int
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

void
service_stop(struct service * const s, stop_reason_t const stop_reason)
{
    if (service_is_running(s))
    {
        s->stop_reason = stop_reason;
        if (!service_is_stopping(s))
        {
            send_service_event(s, service_stopping_);
            stop_running_process(s, stop_reason);
        }
    }
    else
    {
        /*
         * The restart timer might be running. Stop it if it is because
         * this stop request should take precedence.
         */
        uloop_timeout_cancel(&s->restart_state.delay_timeout);
    }

    return;
}

int
service_debug_output_init(struct serviced_context_st * const context)
{
    return debug_output_fd_init(context->debug_output_context);
}

void
serviced_deinit(serviced_context_st * const context)
{
    if (context == NULL)
    {
        goto done;
    }

    struct service * s;
    struct service * ptr;

    avl_for_each_element_safe(&context->services, s, avl, ptr)
    {
        service_free(s);
    }

    ubus_connection_shutdown(&context->ubus_state.ubus_connection);
    /*
     * Leave the debug output until the end so users can see as much debug as
     * possible.
     */
    debug_output_deinit(context->debug_output_context);

    free(context);

done:
    return;
}

serviced_context_st *
serviced_init(char const * const early_start_dir, char const * const ubus_path)
{
    struct serviced_context_st * const context = calloc(1, sizeof *context);

    if (context == NULL)
    {
        goto done;
    }

    avl_init(&context->services, avl_strcmp, false, NULL);

    context->debug_output_context = debug_output_init();

    start_early_services(context, early_start_dir);
    serviced_ubus_init(context, ubus_path);

done:
    return context;
}


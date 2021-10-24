#include "file_monitor.h"
#include "debug.h"

#include <ubus_utils/ubus_utils.h>

#include <fcntl.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct file_monitor_st
{
    union
    {
        char buf[sizeof(struct inotify_event)+ NAME_MAX + 1];
        struct inotify_event event;
    } ev;
    size_t event_bytes;
    struct uloop_timeout change_timeout;

    char const * dir_name;
    char const * file_name;
    char * dir_name_copy;
    char * file_name_copy;
    struct ustream_fd stream;
    int inotify_wd;
    file_monitor_cb cb;
    void * cb_ctx;
};

static int const config_file_quiet_time_millisecs = 1000;

static void
change_timeout(struct uloop_timeout * const t)
{
    struct file_monitor_st * const monitor =
        container_of(t, struct file_monitor_st, change_timeout);

    if (monitor->cb != NULL)
    {
        monitor->cb(monitor->cb_ctx);
    }
}

static void
inotify_cb(struct ustream * const s, int const bytes)
{
    UNUSED_ARG(bytes);

    struct file_monitor_st * const monitor =
        container_of(s, struct file_monitor_st, stream.stream);
    bool monitored_file_changed = false;

    debug("%s bytes %d\n", __func__, bytes);
    do
    {
        /*
         * Read the event in two stages. The first stage is to read the event
         * header, which will then contain the length of the trailing data.
         */
        bool have_event_header =
            monitor->event_bytes >= sizeof monitor->ev.event;

        if (!have_event_header)
        {
            monitor->event_bytes +=
                ustream_read(
                    s,
                    monitor->ev.buf + monitor->event_bytes,
                    sizeof monitor->ev.event - monitor->event_bytes);
        }

        have_event_header =
            monitor->event_bytes >= sizeof monitor->ev.event;
        if (!have_event_header)
        {
            break;
        }

        size_t const required_bytes =
            sizeof monitor->ev.event + monitor->ev.event.len;
        bool have_required_bytes = required_bytes == monitor->event_bytes;
        if (!have_required_bytes)
        {
            monitor->event_bytes +=
                ustream_read(
                    s,
                    &monitor->ev.buf[monitor->event_bytes],
                    required_bytes - monitor->event_bytes);
        }

        have_required_bytes = required_bytes == monitor->event_bytes;
        if (!have_required_bytes)
        {
            break;
        }

        if (strcmp(monitor->ev.event.name, monitor->file_name) == 0)
        {
            monitored_file_changed = true;
        }
        monitor->event_bytes = 0;

    } while (1);

    if (!monitored_file_changed)
    {
        goto done;
    }
    uloop_timeout_set(&monitor->change_timeout, config_file_quiet_time_millisecs);

done:
    return;
}

static struct file_monitor_st *
file_monitor_alloc(void)
{
    struct file_monitor_st * const monitor = calloc(1, sizeof *monitor);

    debug("%s\n", __func__);

    if (monitor == NULL)
    {
        goto done;
    }

    monitor->inotify_wd = -1;
    monitor->change_timeout.cb = change_timeout;

    struct ustream_fd * const stream = &monitor->stream;

    stream->fd.fd = -1;

done:
    return monitor;
}

void
file_monitor_close(struct file_monitor_st * const monitor)
{
    debug("%s\n", __func__);

    if (monitor == NULL)
    {
        goto done;
    }

    uloop_timeout_cancel(&monitor->change_timeout);

    free(monitor->dir_name_copy);
    free(monitor->file_name_copy);

    struct ustream_fd * const stream = &monitor->stream;

    if (stream->fd.fd > -1)
    {
        if (monitor->inotify_wd > -1)
        {
            inotify_rm_watch(stream->fd.fd, monitor->inotify_wd);
        }
        ustream_free(&stream->stream);
        close(stream->fd.fd);
    }

    free(monitor);

done:
    return;
}

struct file_monitor_st *
file_monitor_open(
    char const * const file_to_monitor,
    file_monitor_cb const cb,
    void * const cb_ctx)
{
    bool success;
    struct file_monitor_st * monitor = file_monitor_alloc();

    debug("%s\n", __func__);

    if (monitor == NULL)
    {
        success = false;
        goto done;
    }

    monitor->dir_name_copy = strdup(file_to_monitor);
    monitor->file_name_copy = strdup(file_to_monitor);
    if (monitor->dir_name_copy == NULL || monitor->file_name_copy == NULL)
    {
        success = false;
        goto done;
    }

    monitor->dir_name = dirname(monitor->dir_name_copy);
    monitor->file_name = basename(monitor->file_name_copy);
    monitor->cb = cb;
    monitor->cb_ctx = cb_ctx;

    struct ustream_fd * const stream = &monitor->stream;

    stream->stream.string_data = false;
    stream->stream.notify_read = inotify_cb;
    int fd = inotify_init();
    if (fd < 0)
    {
        debug("inotify_init failed\n");
        success = false;
        goto done;
    }

    ustream_fd_init(stream, fd);
    fcntl(fd, F_SETFD, FD_CLOEXEC);

    debug("watch for changes in dir: %s\n", monitor->dir_name);

    /*
     * The directory is monitored rather than the file itself so that if the
     * file is created the change will be seen.
     */
    monitor->inotify_wd =
        inotify_add_watch(fd, monitor->dir_name, IN_CREATE | IN_DELETE | IN_MODIFY);
    if (monitor->inotify_wd < 0)
    {
        debug("failed to add watch for %s\n", file_to_monitor);
    }

    success = true;

done:
    if (!success)
    {
        file_monitor_close(monitor);
        monitor = NULL;
    }

    return monitor;
}


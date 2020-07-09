#include "file_monitor.h"

#include "debug.h"
#include "utils.h"

#include <fcntl.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
inotify_reader(struct ustream * const s, int const bytes)
{
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
    if (monitor->cb != NULL)
    {
        monitor->cb(monitor);
    }

done:
    return;
}

void
file_monitor_init(struct file_monitor_st * const monitor)
{
    debug("%s\n", __func__);

    memset(monitor, 0, sizeof *monitor);
    monitor->inotify_wd = -1;

    struct ustream_fd * const stream = &monitor->stream;

    stream->fd.fd = -1;
}

bool
file_monitor_open(
    struct file_monitor_st * const monitor,
    char const * const file_to_monitor,
    file_monitor_cb const cb)
{
    debug("%s\n", __func__);

    bool success;
    struct ustream_fd * const stream = &monitor->stream;

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
    stream->stream.string_data = false;
    stream->stream.notify_read = inotify_reader;
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
    monitor->inotify_wd =
        inotify_add_watch(fd, monitor->dir_name, IN_CREATE | IN_DELETE | IN_MODIFY);
    if (monitor->inotify_wd < 0)
    {
        debug("failed to add watch for %s\n", file_to_monitor);
    }
    success = true;

done:
    return success;
}

void
file_monitor_close(struct file_monitor_st * const monitor)
{
    debug("%s\n", __func__);
    struct ustream_fd * const stream = &monitor->stream;

    free(monitor->dir_name_copy);
    monitor->dir_name_copy = NULL;
    monitor->dir_name = NULL;
    free(monitor->file_name_copy);
    monitor->file_name_copy = NULL;
    monitor->file_name = NULL;

    if (stream->fd.fd > -1)
    {
        if (monitor->inotify_wd > -1)
        {
            inotify_rm_watch(stream->fd.fd, monitor->inotify_wd);
            monitor->inotify_wd = -1;
        }
        ustream_free(&stream->stream);
        close(stream->fd.fd);
        stream->fd.fd = -1;
    }
}


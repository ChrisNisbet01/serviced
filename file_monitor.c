#include "file_monitor.h"

#include "debug.h"

#include <fcntl.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

static void
inotify_reader(struct ustream * const s, int const bytes)
{
    debug("%s bytes %d\n", __func__, bytes);
    do
    {
        int len;
        char const * const buf = ustream_get_read_buf(s, &len);

        if (buf == NULL)
        {
            break;
        }

        ustream_consume(s, len);
    } while (1);


    struct file_monitor_st * const monitor =
        container_of(s, struct file_monitor_st, stream.stream);

    if (monitor->cb != NULL)
    {
        monitor->cb(monitor);
    }
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

    monitor->inotify_wd =
        inotify_add_watch(fd, file_to_monitor, IN_CREATE | IN_DELETE | IN_MODIFY);
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


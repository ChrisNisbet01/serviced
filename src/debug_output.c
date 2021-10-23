#include "debug_output.h"
#include "debug.h"
#include "utils.h"

#include <libubox/ustream.h>
#include <ubus_utils/ubus_utils.h>

#include <stdbool.h>
#include <stdlib.h>
#include <sys/queue.h>

struct debug_fd_st
{
    TAILQ_ENTRY(debug_fd_st) entry;
    struct debug_output_context_st * context;
    int fds[2];
    struct uloop_timeout timeout;
    struct ustream_fd s;
};

TAILQ_HEAD(debug_fd_queue_st, debug_fd_st);

struct debug_output_context_st
{
    struct debug_fd_queue_st debug_fd_queue;
};

static void
debug_fd_free(struct debug_fd_st * const debug_fd)
{
    struct debug_output_context_st * const context = debug_fd->context;

    TAILQ_REMOVE(&context->debug_fd_queue, debug_fd, entry);
    close_output_stream(&debug_fd->s);
    free(debug_fd);
}

static void debug_fds_free(struct debug_output_context_st * const context)
{
    struct debug_fd_st * debug_fd;
    struct debug_fd_st * tmp;

    TAILQ_FOREACH_SAFE(debug_fd, &context->debug_fd_queue, entry, tmp)
    {
        if (debug_fd->s.stream.write_error)
        {
            debug_fd_free(debug_fd);
        }
    }
}

static void
debug_fd_notify_state(struct ustream * const s)
{
    struct debug_fd_st * const debug_fd = container_of(s, struct debug_fd_st, s.stream);

    if (s->write_error || s->eof)
    {
        debug("Notify state and FD EOF (%d) or error (%d)\n",
              s->eof, s->write_error);

        debug_fd_free(debug_fd);
    }
}

void
debug_output_write_to_debug_apps(
    struct debug_output_context_st * const context, char const * const format, ...)
{
    if (context == NULL)
    {
        goto done;
    }

    struct debug_fd_st * debug_fd;
    struct debug_fd_st * tmp;

    TAILQ_FOREACH_SAFE(debug_fd, &context->debug_fd_queue, entry, tmp)
    {
        if (debug_fd->s.stream.write_error)
        {
            debug("error writing to debug FD %d\n", debug_fd->fds[1]);

            debug_fd_free(debug_fd);
        }
        else
        {
            va_list arg;

            va_start(arg, format);
            (void)ustream_vprintf(&debug_fd->s.stream, format, arg);
            va_end(arg);
        }
    }

done:
    return;
}

int
debug_output_fd_init(struct debug_output_context_st * const context)
{
    int fd;
    struct debug_fd_st * const debug_fd = calloc(1, sizeof(*debug_fd));

    if (context == NULL)
    {
        fd = -1;
        goto done;
    }

    if (debug_fd == NULL)
    {
        fd = -1;
        goto done;
    }

    initialise_pipe(debug_fd->fds, true);
    /*
     * This is the FD that the requestor will read from. Note that this fd will
     * be closed after it is sent back in the ubus response, so there is no
     * need to close it again when this debug_fd is cleaned up.
     */
    fd = debug_fd->fds[0];
    if (fd == -1)
    {
        goto done;
    }

    debug_fd->context = context;
    debug_fd->s.stream.notify_state = debug_fd_notify_state;

    ustream_fd_init(&debug_fd->s, debug_fd->fds[1]);

    TAILQ_INSERT_TAIL(&context->debug_fd_queue, debug_fd, entry);

done:
    if (fd < 0)
    {
        free(debug_fd);
    }

    return fd;
}

void
debug_output_deinit(struct debug_output_context_st * const context)
{
    if (context == NULL)
    {
        goto done;
    }

    debug_fds_free(context);
    free(context);

done:
    return;
}

struct debug_output_context_st *
debug_output_init(void)
{
    struct debug_output_context_st * const context = calloc(1, sizeof *context);

    if (context == NULL)
    {
        goto done;
    }

    TAILQ_INIT(&context->debug_fd_queue);

done:
    return context;
}

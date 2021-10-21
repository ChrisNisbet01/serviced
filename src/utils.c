#include "utils.h"
#include "debug.h"

#include <libubox/blobmsg_json.h>

#include <unistd.h>

bool
remove_pid_file(char const * const filename)
{
    bool result;

    if (filename == NULL)
    {
        result = true;
        goto done;
    }

    if (unlink(filename))
    {
        debug("Failed to remove pid file: %s: %m\n", filename);
        result = false;
        goto done;
    }

    result = true;

done:
    return result;
}

bool
write_pid_file(char const * const filename, pid_t const pid)
{
    bool success;

    if (filename == NULL)
    {
        success = true;
        goto done;
    }

    FILE * const fp = fopen(filename, "w");

    if (fp == NULL)
    {
        success = false;
        goto done;
    }

    if (fprintf(fp, "%d\n", pid) < 0)
    {
        success = false;
        goto done;
    }

    if (fclose(fp))
    {
        success = false;
        goto done;
    }

    success = true;

done:
    if (!success)
    {
        debug("Failed to write PID %u to PID file: %s\n", (int)pid, filename);
    }

    return success;
}

int
send_signal_to_process(
    struct uloop_process const * const process, unsigned const sig)
{
    debug("Send signal %d to PID %d\n", sig, (int)process->pid);
    return kill(process->pid, sig);
}



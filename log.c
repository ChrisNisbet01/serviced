#include "log.h"

#include <libubox/ulog.h>

void
log_open(
    int const log_threshold,
    unsigned const log_channels,
    unsigned const log_facility,
    char const * const log_id)
{
    ulog_threshold(log_threshold);
    if (log_threshold >= 0)
    {
        ulog_open(log_channels, log_facility, log_id);
    }
}

void
log_close(void)
{
    ulog_close();
}

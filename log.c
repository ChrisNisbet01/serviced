#include "log.h"

#include "string_constants.h"

#include <libubox/ulog.h>

static unsigned log_channels_ = 0;
static int log_threshold_ = -1;

void
log_open(int const log_threshold, unsigned const log_channels)
{
    log_channels_ = log_channels;
    log_threshold_ = log_threshold;

    ulog_threshold(log_threshold_);
    if (log_threshold_ >= 0)
    {
        ulog_open(log_channels_, LOG_DAEMON, serviced_);
    }
}

void
log_close(void)
{
    ulog_close();
}

unsigned
log_channels_get(void)
{
    return log_channels_;
}

int
log_threshold_get(void)
{
    return log_threshold_;
}

#pragma once

#include <libubus.h>

void
log_open(int log_threshold, unsigned log_channels);

void
log_close(void);

void
ubus_init_log(struct ubus_context * ubus_ctx);


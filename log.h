#pragma once

void
log_open(int log_threshold, unsigned log_channels);

void
log_close(void);

unsigned
log_channels_get(void);

int
log_threshold_get(void);


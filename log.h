#pragma once

void
log_open(
    int log_threshold,
    unsigned log_channels,
    unsigned log_facility,
    char const * log_id);

void
log_close(void);


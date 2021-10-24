#pragma once

#include <libubox/ustream.h>

#include <limits.h>
#include <sys/inotify.h>

struct file_monitor_st;

typedef void (*file_monitor_cb)(void * cb_ctx);

typedef struct file_monitor_st file_monitor_st;

file_monitor_st *
file_monitor_open(
    char const * file_to_monitor, file_monitor_cb cb, void * cb_ctx);

void
file_monitor_close(file_monitor_st * monitor);


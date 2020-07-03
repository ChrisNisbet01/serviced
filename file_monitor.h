#pragma once

#include <libubox/ustream.h>

struct file_monitor_st;

typedef void (*file_monitor_cb)(struct file_monitor_st * monitor);

struct file_monitor_st {
    struct ustream_fd stream;
    int inotify_wd;
    file_monitor_cb cb;
};

void
file_monitor_init(struct file_monitor_st * monitor);

bool
file_monitor_open(
    struct file_monitor_st * monitor, char const * file_to_monitor, file_monitor_cb cb);

void
file_monitor_close(struct file_monitor_st * monitor);


#pragma once

#include <libubox/ustream.h>

#include <limits.h>
#include <sys/inotify.h>

struct file_monitor_st;

typedef void (*file_monitor_cb)(struct file_monitor_st * monitor);

struct file_monitor_st {
    union
    {
        char buf[sizeof(struct inotify_event)+ NAME_MAX + 1];
        struct inotify_event event;
    } ev;
    size_t event_bytes;

    char const * dir_name;
    char const * file_name;
    char * dir_name_copy;
    char * file_name_copy;
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


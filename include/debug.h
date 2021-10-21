#pragma once

#if DEBUG != 0

#include <libubox/ulog.h>

#include <stdio.h>

#define ULOG_DEBUG(fmt, ...) ulog(LOG_DEBUG, fmt, ## __VA_ARGS__)

#define debug(fmt, ...) \
do { \
	ULOG_DEBUG("%s:%d: ", __FILE__, __LINE__); \
	ULOG_DEBUG(fmt, ## __VA_ARGS__); \
} while (0)

#else
#define debug(fmt, ...) do { } while (0)
#endif


#pragma once

#if DEBUG

#include <stdio.h>

#define debug(fmt, ...) \
do { \
	fprintf(stderr, "%s:%d: ", __FILE__, __LINE__); \
	fprintf(stderr, fmt, ## __VA_ARGS__); \
    fflush(stderr); \
} while (0)

#else
#define debug(fmt, ...) do { } while (0)
#endif


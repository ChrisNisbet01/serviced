#pragma once

#include <libubox/blob.h>
#include <libubox/blobmsg.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define UNUSED_ARG(arg) (void)(arg)

#define UNCONST(ptr) ((void *)(ptr))

#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar) \
	for ((var) = TAILQ_FIRST((head)); \
		 (var) && ((tvar) = TAILQ_NEXT((var), field), 1); \
		 (var) = (tvar))
#endif

/*
 * blobbuf_init() doesn't initialise the blob_buf fully, so this wrapper
 * does the job for us.
 */
void
blob_buf_full_init(struct blob_buf *b, int const id);

/*
 * blobmsg_check_array() doesn't check the blob for NULL, so this wrapper
 * does the job for us.
 */
bool
blobmsg_array_is_type(
	struct blob_attr const *array_blob, enum blobmsg_type type);

/*
 * blobmsg_get_u32() doesn't check the blob for NULL, so this wrapper
 * does the job for us.
 * Return the default value if attr is NULL.
 */
uint32_t
blobmsg_get_u32_or_default(struct blob_attr *attr, uint32_t default_value);

/*
 * blobmsg_get_bool() doesn't check the blob for NULL, so this wrapper
 * does the job for us.
 * Return the default value if attr is NULL.
 */
bool
blobmsg_get_bool_or_default(struct blob_attr *attr, bool default_value);

char const *
blobmsg_get_string_or_default(
	struct blob_attr *attr, char const *default_value);

size_t
blobmsg_array_length(struct blob_attr const * attr);

bool
remove_pid_file(char const * filename);

bool
write_pid_file(char const * filename, pid_t pid);


#pragma once

#include <libubox/blob.h>
#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool
remove_pid_file(char const * filename);

bool
write_pid_file(char const * filename, pid_t pid);

int
send_signal_to_process(
    struct uloop_process const * process, unsigned const sig);

void
initialise_pipe(int * pipe_fd, bool will_read_pipe);

void
close_output_stream(struct ustream_fd * stream);


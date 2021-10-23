#pragma once

typedef struct debug_output_context_st debug_output_context_st;

void
debug_output_write_to_debug_apps(
    struct debug_output_context_st * context, char const * format, ...);

int
debug_output_fd_init(struct debug_output_context_st * context);

void
debug_output_deinit(debug_output_context_st * context);

debug_output_context_st *
debug_output_init(void);




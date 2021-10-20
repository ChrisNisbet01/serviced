#pragma once

void
iterate_files_in_directory(
    char const * const directory_pattern,
    void (*cb)(char const * filename, void * user_ctx),
    void * const user_ctx);


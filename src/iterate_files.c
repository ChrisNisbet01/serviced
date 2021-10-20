#include "iterate_files.h"

#include <glob.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

void
iterate_files_in_directory(
    char const * const directory_pattern,
    void (*cb)(char const * filename, void * user_ctx),
    void * const user_ctx)
{
    glob_t globbuf;

    if (directory_pattern == NULL)
    {
        goto done;
    }

    memset(&globbuf, 0, sizeof globbuf);

    glob(directory_pattern, 0, NULL, &globbuf);

    for (size_t i = 0; i < globbuf.gl_pathc; i++)
    {
        cb(globbuf.gl_pathv[i], user_ctx);
    }

    globfree(&globbuf);

done:
    return;
}


#include "serviced_ubus.h"

#include <libubox/uloop.h>

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>

static void
ignore_sigpipe(void)
{
    struct sigaction sa;

    if (sigaction(SIGPIPE, NULL, &sa) == 0)
    {
        sa.sa_handler = SIG_IGN;
        sigaction(SIGPIPE, &sa, NULL);
    }
}

static bool
run(char const * const ubus_path)
{
    bool success;

    /*
     * serviced should run in its own session so it's not killed if/when its
     * parent dies.
     */
    //setsid();

    ignore_sigpipe();

    uloop_init();

    serviced_context_st * const context = serviced_init(ubus_path);

    if (context != NULL)
    {
        uloop_run();
        success = true;
        serviced_deinit(context);
    }
    else
    {
        success = false;
    }

    uloop_done();

    return success;
}

static void
usage(FILE * const fp, char const * const program_name)
{
    fprintf(fp,
            "usage: %s [-u ubus_path]\n"
            "serviced\n\n"
            "\t-h\thelp      - this help\n"
            "\t-u\tubus path - UBUS socket path\n",
            program_name);
}

int
main(int argc, char ** argv)
{
    int exit_code;
    char const * ubus_path = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "hu:")) != -1)
    {
        switch (opt)
        {
            case 'u':
                ubus_path = optarg;
                break;
            case 'h':
                usage(stdout, argv[0]);
                exit_code = EXIT_SUCCESS;
                goto done;
            default:
                usage(stderr, argv[0]);
                exit_code = EXIT_FAILURE;
                goto done;
        }
    }

    exit_code = run(ubus_path) ? EXIT_SUCCESS : EXIT_FAILURE;

done:
    return exit_code;
}

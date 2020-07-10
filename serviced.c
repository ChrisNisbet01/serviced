#include "log.h"
#include "serviced_ubus.h"

#include <libubox/uloop.h>
#include <libubox/ulog.h>

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
            "\t-u\tubus path - UBUS socket path\n"
            "\t-s\t          - log to syslog\n"
            "\t-e\t          - log to stderr\n"
            "\t-k\t          - log to kmsg\n"
            "\t-f\t          - log facility\n"
            "\t-t\t          - log threshold\n",
            program_name);
}

int
main(int argc, char ** argv)
{
    int exit_code;
    char const * ubus_path = NULL;
    int opt;
    unsigned log_channels = 0;
    unsigned int log_facility = LOG_DAEMON;
    int log_threshold = -1;

    while ((opt = getopt(argc, argv, "sekhu:f:t:")) != -1)
    {
        switch (opt)
        {
            case 's':
                log_channels |= ULOG_SYSLOG;
                break;
            case 'e':
                log_channels |= ULOG_STDIO;
                break;
            case 'k':
                log_channels |= ULOG_KMSG;
                break;
            case 'f':
                log_facility = atoi(optarg);
                break;
            case 't':
                log_threshold = atoi(optarg);
                break;
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

    log_open(log_threshold, log_channels, log_facility, "serviced");

    ULOG_NOTE("serviced started\n");

    exit_code = run(ubus_path) ? EXIT_SUCCESS : EXIT_FAILURE;

done:
    if (exit_code == EXIT_SUCCESS)
    {
        ULOG_NOTE("serviced exiting\n");
    }
    else
    {
        ULOG_ERR("serviced exiting\n");
    }

    log_close();

    return exit_code;
}

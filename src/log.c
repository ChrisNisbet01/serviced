#include "log.h"
#include "string_constants.h"

#include <ubus_utils/ubus_utils.h>
#include <libubox/blobmsg_json.h>
#include <libubox/ulog.h>

static unsigned log_channels_ = 0;
static int log_threshold_ = -1;

void
log_open(int const log_threshold, unsigned const log_channels)
{
    log_channels_ = log_channels;
    log_threshold_ = log_threshold;

    ulog_threshold(log_threshold_);
    if (log_threshold_ >= 0)
    {
        ulog_open(log_channels_, LOG_DAEMON, serviced_);
    }
}

void
log_close(void)
{
    ulog_close();
}

static unsigned
parse_channel(char const * const str)
{
    unsigned channel;

    if (strcasecmp(str, "stderr") == 0)
    {
        channel = ULOG_STDIO;
    }
    else if (strcasecmp(str, "syslog") == 0)
    {
        channel = ULOG_SYSLOG;
    }
    else if (strcasecmp(str, "kmsg") == 0)
    {
        channel = ULOG_KMSG;
    }
    else
    {
        channel = 0;
    }

    return channel;
}

static bool
parse_log_channels(struct blob_attr * const attr, unsigned * log_channels)
{
    bool success;
    unsigned channels = 0;

    if (attr == NULL)
    {
        /*
         * If the caller didn't specify new log channels just use the existing
         * channels.
         */
        channels = log_channels_;
        success = true;
        goto done;
    }

    if (!blobmsg_array_is_type(attr, BLOBMSG_TYPE_STRING))
    {
        success = false;
        goto done;
    }

    struct blob_attr * cur;
    int rem;

    blobmsg_for_each_attr(cur, attr, rem)
    {
        channels |= parse_channel(blobmsg_get_string(cur));
    }

    success = true;

done:
    if (success)
    {
        *log_channels = channels;
    }
    return success;
}

static bool
parse_log_threshold(struct blob_attr * const attr, int * log_threshold)
{
    bool success;
    int threshold;

    if (attr == NULL)
    {
        /*
         * If the caller didn't specify a new threshold just use the existing
         * threshold.
         */
        threshold = log_threshold_;
        success = true;
        goto done;
    }

    char const * const new_threshold = blobmsg_get_string(attr);

    if (strcasecmp(new_threshold, "EMERG") == 0)
    {
        threshold = LOG_EMERG;
    }
    else if (strcasecmp(new_threshold, "ALERT") == 0)
    {
        threshold = LOG_ALERT;
    }
    else if (strcasecmp(new_threshold, "CRIT") == 0)
    {
        threshold = LOG_CRIT;
    }
    else if (strcasecmp(new_threshold, "ERR") == 0)
    {
        threshold =  LOG_ERR;
    }
    else if (strcasecmp(new_threshold, "WARNING") == 0)
    {
        threshold = LOG_WARNING;
    }
    else if (strcasecmp(new_threshold, "NOTICE") == 0)
    {
        threshold = LOG_NOTICE;
    }
    else if (strcasecmp(new_threshold, "INFO") == 0)
    {
        threshold =  LOG_INFO;
    }
    else if (strcasecmp(new_threshold, "DEBUG") == 0)
    {
        threshold = LOG_DEBUG;
    }
    else if (strcasecmp(new_threshold, "NONE") == 0)
    {
        threshold = -1;
    }
    else
    {
        success = false;
        goto done;
    }

    success = true;

done:
    if (success)
    {
        *log_threshold = threshold;
    }
    return success;
}

enum {
    LOG_CHANNELS,
    LOG_THRESHOLD,
    __LOG_MAX,
};

static const struct blobmsg_policy log_policy[__LOG_MAX] =
{
    [LOG_CHANNELS] = { channels_, BLOBMSG_TYPE_ARRAY },
    [LOG_THRESHOLD] = { threshold_, BLOBMSG_TYPE_STRING }
};

static int
handle_log_request(
    struct ubus_context * const ctx,
    struct ubus_object * const obj,
    struct ubus_request_data * const req,
    char const * const method,
    struct blob_attr * const msg)
{
    int res;
    struct blob_attr * tb[__LOG_MAX];

    UNUSED_ARG(ctx);
    UNUSED_ARG(obj);
    UNUSED_ARG(req);
    UNUSED_ARG(method);

    blobmsg_parse(log_policy, __LOG_MAX, tb,
                  blobmsg_data(msg), blobmsg_data_len(msg));

    unsigned channels = 0;

    if (!parse_log_channels(tb[LOG_CHANNELS], &channels))
    {
        res = UBUS_STATUS_INVALID_ARGUMENT;
        goto done;
    }

    int threshold = -1;

    if (!parse_log_threshold(tb[LOG_THRESHOLD], &threshold))
    {
        res = UBUS_STATUS_INVALID_ARGUMENT;
        goto done;
    }

    log_open(threshold, channels);
    res = UBUS_STATUS_OK;

done:
    return res;
}

static struct ubus_method log_object_methods[] =
{
    UBUS_METHOD(log_, handle_log_request, log_policy),
};

static struct ubus_object_type log_object_type =
    UBUS_OBJECT_TYPE(log_, log_object_methods);

static struct ubus_object log_object =
{
    .name = service_log_,
    .type = &log_object_type,
    .methods = log_object_methods,
    .n_methods = ARRAY_SIZE(log_object_methods),
};

void
ubus_init_log(struct ubus_context * const ubus_ctx)
{
    ubus_add_object(ubus_ctx, &log_object);
}


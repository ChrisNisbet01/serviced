#include "log_ubus.h"
#include "log.h"
#include "string_constants.h"
#include "utils.h"

#include <libubox/blobmsg_json.h>
#include <libubox/ulog.h>

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

    if (attr == NULL)
    {
        /*
         * If the caller didn't specify new log channels just use the existing
         * channels.
         */
        *log_channels = log_channels_get();
        success = true;
        goto done;
    }

    unsigned channels = 0;

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

    *log_channels = channels;
    success = true;

done:
    return success;
}

static bool
parse_log_threshold(struct blob_attr * const attr, int * log_threshold)
{
    bool success;

    if (attr == NULL)
    {
        /*
         * If the caller didn't specify a new threshold just use the existing
         * threshold.
         */
        *log_threshold = log_threshold_get();
        success = true;
        goto done;
    }

    unsigned threshold;
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

    *log_threshold = threshold;
    success = true;

done:
    return success;
}

enum {
    LOG_CHANNELS,
    LOG_THRESHOLD,
    __LOG_MAX,
};

static const struct blobmsg_policy log_policy[__LOG_MAX] = {
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

static struct ubus_method log_object_methods[] = {
    UBUS_METHOD(log_, handle_log_request, log_policy),
};

static struct ubus_object_type log_object_type =
    UBUS_OBJECT_TYPE(log_, log_object_methods);

static struct ubus_object log_object = {
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

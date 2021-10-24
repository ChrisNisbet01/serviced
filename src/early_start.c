#include "early_start.h"
#include "debug.h"
#include "iterate_files.h"
#include "serviced_ubus.h"

#include <ubus_utils/ubus_utils.h>
#include <json-c/json.h>
#include <libubox/blobmsg_json.h>

static bool
parse_early_start_json(
    json_object * const json_obj, struct serviced_context_st * const context)
{
    bool success;
    struct blob_buf blob;

    blob_buf_full_init(&blob, 0);

    if (!blobmsg_add_json_element(&blob, "", json_obj))
    {
        success = false;
        goto done;
    }

    success = service_add(context, blob_data(blob.head)) == service_add_success;

done:
    blob_buf_free(&blob);

    return success;
}

static bool
load_early_start_from_json_file(
    char const * const filename, struct serviced_context_st * const context)
{
    bool success;
    json_object * const json_obj = json_object_from_file(filename);

    if (json_obj == NULL)
    {
        success = false;
        goto done;
    }

    success = parse_early_start_json(json_obj, context);

done:
    json_object_put(json_obj);

    if (!success)
    {
        debug("failed to load %s\n", filename);
    }

    return success;
}

static void
early_start_callback(char const * const filename, void * const ctx)
{
    struct serviced_context_st * const context = ctx;

    debug("loading service from %s\n", filename);
    load_early_start_from_json_file(filename, context);
}

void
start_early_services(
    struct serviced_context_st * const context, char const * const early_start_filespec)
{
    debug("%s pattern %s\n", __func__, early_start_filespec);
    iterate_files_in_directory(early_start_filespec, early_start_callback, context);
}


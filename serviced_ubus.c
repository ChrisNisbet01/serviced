#include "serviced_ubus.h"
#include "debug.h"
#include "string_constants.h"
#include "utils.h"

#include <libubox/avl-cmp.h>

#include <stddef.h>
#include <unistd.h>

static void
ubus_reconnected(struct ubus_connection_ctx_st * const connection_context)
{
	struct ubus_context * const ubus_ctx = &connection_context->context;

    debug("reconnected\n");
	ubus_add_uloop(ubus_ctx);
}

static void
ubus_connected(struct ubus_connection_ctx_st * const connection_context)
{
	struct ubus_context * const ubus_ctx = &connection_context->context;

    debug("connected\n");
	ubus_init_service(ubus_ctx);
	ubus_add_uloop(ubus_ctx);
}

void
serviced_deinit(serviced_context_st * const context)
{
	if (context == NULL)
    {
		goto done;
	}

    ubus_connection_shutdown(&context->ubus_connection);

done:
	return;
}

serviced_context_st *serviced_init(char const * const ubus_path)
{
	struct serviced_context_st * const context = calloc(1, sizeof *context);

	if (context == NULL)
    {
		goto done;
	}

    avl_init(&context->services, avl_strcmp, false, NULL);

    ubus_connection_init(
        &context->ubus_connection,
        ubus_path,
        ubus_connected,
        ubus_reconnected);

done:
	return context;
}

void
send_service_event(
    struct ubus_context * const ubus,
    char const * const service_name,
    char const * const event)
{
    struct blob_buf b;

    blob_buf_full_init(&b, 0);
    blobmsg_add_string(&b, service_, service_name);
    ubus_send_event(ubus, event, b.head);
    blob_buf_free(&b);
}

typedef void (*services_iterate_cb)(struct service * s, void * user_ctx);

void
services_insert_service(
    struct ubus_context * const ubus, struct service * const s)
{
    struct serviced_context_st * const context =
        container_of(ubus, struct serviced_context_st, ubus_connection.context);

    avl_insert(&context->services, &s->avl);
    s->in_avl = true;
}

void
services_remove_service(
    struct ubus_context * const ubus, struct service * const s)
{
    struct serviced_context_st * const context =
        container_of(ubus, struct serviced_context_st, ubus_connection.context);

    if (s->in_avl)
    {
        avl_delete(&context->services, &s->avl);
        s->in_avl = false;
    }
}

struct service *
services_lookup_service(
    struct ubus_context * const ubus, char const * const service_name)
{
    struct serviced_context_st * const context =
        container_of(ubus, struct serviced_context_st, ubus_connection.context);
    struct service * s; /* Required by avl_find_element. */

    return avl_find_element(&context->services, service_name, s, avl);
}

void
services_iterate(
    struct ubus_context * const ubus,
    services_iterate_cb const cb,
    void * const user_ctx)
{
    struct serviced_context_st * const context =
        container_of(ubus, struct serviced_context_st, ubus_connection.context);
    struct service * s;

    avl_for_each_element(&context->services, s, avl)
    {
        cb(s, user_ctx);
    }
}

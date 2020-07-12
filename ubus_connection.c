#include "ubus_connection.h"

static int const ubus_connect_interval_ms = 2000;

static void
ubus_reconnect_cb(struct uloop_timeout * const timeout)
{
    struct ubus_connection_ctx_st * const connection_context =
        container_of(timeout, struct ubus_connection_ctx_st, timeout);
    struct ubus_context * const ubus_ctx = &connection_context->context;

    if (ubus_reconnect(ubus_ctx, connection_context->path) == UBUS_STATUS_OK)
    {
        if (connection_context->reconnected_cb != NULL)
        {
            connection_context->reconnected_cb(connection_context);
        }
    }
    else
    {
        uloop_timeout_set(timeout, ubus_connect_interval_ms);
    }
}

static void
ubus_disconnect_cb(struct ubus_context * const ubus_ctx)
{
    struct ubus_connection_ctx_st * const connection_context =
        container_of(ubus_ctx, struct ubus_connection_ctx_st, context);
    struct uloop_timeout * const timeout = &connection_context->timeout;

    if (connection_context->disconnected_cb != NULL)
    {
        connection_context->disconnected_cb(connection_context);
    }

    timeout->cb = ubus_reconnect_cb;
    uloop_timeout_set(timeout, ubus_connect_interval_ms);
}

static void
ubus_connect_timeout_cb(struct uloop_timeout * const timeout)
{
    struct ubus_connection_ctx_st * const connection_context =
        container_of(timeout, struct ubus_connection_ctx_st, timeout);
    struct ubus_context * const ubus_ctx = &connection_context->context;

    if (ubus_connect_ctx(ubus_ctx, connection_context->path) < 0)
    {
        uloop_timeout_set(
            &connection_context->timeout, ubus_connect_interval_ms);
    }
    else
    {
        ubus_ctx->connection_lost = ubus_disconnect_cb;
        if (connection_context->connected_cb != NULL)
        {
            connection_context->connected_cb(connection_context);
        }
    }
}

void
ubus_connection_init(
    struct ubus_connection_ctx_st * const context,
    char const * const ubus_path,
    ubus_connected_cb const connected_cb,
    ubus_reconnected_cb const reconnected_cb,
    ubus_disconnected_cb const disconnected_cb)
{
    context->path = ubus_path;
    context->connected_cb = connected_cb;
    context->reconnected_cb = reconnected_cb;
    context->disconnected_cb = disconnected_cb;

    context->timeout.cb = ubus_connect_timeout_cb;
    ubus_connect_timeout_cb(&context->timeout);
}

void
ubus_connection_shutdown(struct ubus_connection_ctx_st * const context)
{
    ubus_shutdown(&context->context);
    uloop_timeout_cancel(&context->timeout);
}


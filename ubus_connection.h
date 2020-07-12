#pragma once

#include <libubus.h>
#include <libubox/uloop.h>

struct ubus_connection_ctx_st;

typedef void
(*ubus_connected_cb)(struct ubus_connection_ctx_st *context);

typedef void
(*ubus_reconnected_cb)(struct ubus_connection_ctx_st *context);

typedef void
(*ubus_disconnected_cb)(struct ubus_connection_ctx_st *context);

struct ubus_connection_ctx_st {
	char const *path;
	struct ubus_context context;
	struct uloop_timeout timeout;
	ubus_connected_cb connected_cb;
	ubus_reconnected_cb reconnected_cb;
    ubus_disconnected_cb disconnected_cb;
};

void
ubus_connection_init(
	struct ubus_connection_ctx_st *context,
	char const *ubus_path,
	ubus_connected_cb connected_cb,
	ubus_reconnected_cb reconnected_cb,
    ubus_disconnected_cb disconnected_cb);

void
ubus_connection_shutdown(struct ubus_connection_ctx_st * const context);


#pragma once

#include "ubus_connection.h"
#include "service.h"

#include <libubus.h>

typedef struct serviced_context_st serviced_context_st;
struct serviced_context_st {
    struct ubus_connection_ctx_st ubus_connection;
    struct avl_tree services;
};

void
serviced_deinit(serviced_context_st *context);

serviced_context_st *
serviced_init(char const * const ubus_path);

void
send_service_event(
    struct ubus_context * ubus, char const * service_name, char const * event);

typedef void (*services_iterate_cb)(struct service * s, void * user_ctx);

void
services_insert_service(
    struct ubus_context * ubus, struct service * s);

void
services_remove_service(
    struct ubus_context * ubus, struct service * s);

struct service *
services_lookup_service(struct ubus_context * ubus, char const * service_name);

void
services_iterate(
    struct ubus_context * ubus, services_iterate_cb cb, void * user_ctx);



#pragma once

#include "ubus_connection.h"
#include "service.h"

#include <libubus.h>

typedef enum service_add_error_t {
    service_add_success,
    service_add_invalid_argument,
    service_add_unknown_error
} service_add_error_t;

typedef void (*services_iterate_cb)(struct service * s, void * user_ctx);

typedef struct serviced_context_st serviced_context_st;

struct serviced_context_st {
    struct ubus_connection_ctx_st ubus_connection;
    struct avl_tree services;
};

void
serviced_deinit(serviced_context_st *context);

serviced_context_st *
serviced_init(char const * early_start_dir, char const * ubus_path);

void
services_insert_service(struct serviced_context_st * context, struct service * s);

void
services_remove_service(struct service * s);

struct service *
services_lookup_service(
    struct serviced_context_st * const context, char const * service_name);

void
services_iterate(
    struct ubus_context * ubus, services_iterate_cb cb, void * user_ctx);

struct service *
service_new(struct serviced_context_st * context, char const * service_name);

bool
configs_match(
    struct service_config const * a, struct service_config const * b);

bool
service_restart(struct service * s);

bool
service_reload(struct service * s);

void
config_free(struct service_config const * config_in);

bool
process_is_running(struct uloop_process const * process);

bool
service_is_running(struct service const * s);

bool
service_is_stopping(struct service const * s);

void
service_update_config(struct service * s);

uint32_t
service_runtime_seconds(struct service const * s);

bool
timer_is_running(struct uloop_timeout const * timer);

int
service_send_signal(struct service const * s, unsigned sig);

bool
service_delete(struct service * s);

bool
service_stop(struct service * s, stop_reason_t stop_reason);

bool
service_start_fresh(struct service * s);

void
service_free(struct service * s);

void
send_service_event(struct service const * s, char const * event);

service_add_error_t
service_add(struct serviced_context_st * context, struct blob_attr * msg);


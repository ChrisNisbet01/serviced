#pragma once

#include "ubus_connection.h"
#include "service.h"

#include <libubus.h>

typedef struct serviced_context_st serviced_context_st;

void
serviced_deinit(serviced_context_st *context);

serviced_context_st *
serviced_init(char const * const ubus_path);

typedef void (*services_iterate_cb)(struct service * s, void * user_ctx);

void
services_insert_service(struct ubus_context * ubus, struct service * s);

void
services_remove_service(struct service * s);

struct service *
services_lookup_service(struct ubus_context * ubus, char const * service_name);

void
services_iterate(
    struct ubus_context * ubus, services_iterate_cb cb, void * user_ctx);

struct service *
service_new(char const * service_name, struct ubus_context * ubus);

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


#pragma once

#include "service.h"

typedef enum service_add_error_t {
    service_add_success,
    service_add_invalid_argument,
    service_add_unknown_error
} service_add_error_t;

void
serviced_ubus_init(
    struct serviced_context_st * context, char const * ubus_path);

service_add_error_t
service_add(struct serviced_context_st * context, struct blob_attr * msg);

void write_to_debug_apps(char const * const buf, size_t const len);


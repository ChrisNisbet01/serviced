add_library(serviced_early_start INTERFACE)

set(PUBLIC_HEADERS 
  0001_ubusd.json
)

set_target_properties(serviced_early_start 
  PROPERTIES 
    PUBLIC_HEADER "${PUBLIC_HEADERS}"
)

install(TARGETS serviced_early_start
    PUBLIC_HEADER DESTINATION share/serviced/early_start
)


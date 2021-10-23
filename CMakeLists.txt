cmake_minimum_required(VERSION 3.10)

set(EXE_NAME serviced)

project(${EXE_NAME} VERSION 1.0.0 DESCRIPTION "service manager (similar to procd)")

option(DEBUG "Include debug output" OFF)

add_compile_options(
   -std=gnu11
  -O3 
  -Wall 
  -Wextra 
  -Werror
  -g 
  -D_GNU_SOURCE 
)

if(DEBUG)
  add_compile_options(-DDEBUG=1)
endif()

include(GNUInstallDirs)

find_library(BLOBMSG_JSON blobmsg_json CONFIG REQUIRED)
find_library(JSON_C json-c)
find_library(UBOX ubox)
find_library(UBUS ubus)
find_package(ubus_utils REQUIRED)

set(PROJECT_HEADERS
  include/debug.h
  include/debug_output.h
  include/early_start.h
  include/file_monitor.h
  include/iterate_files.h
  include/log.h
  include/service.h
  include/serviced_ubus.h
  include/string_constants.h
  include/utils.h
)

SET(SOURCES 
  src/debug_output.c
  src/early_start.c
  src/file_monitor.c
  src/iterate_files.c
  src/log.c
  src/service.c
  src/serviced.c
  src/serviced_ubus.c
  src/string_constants.c
  src/utils.c
)

add_executable(${PROJECT_NAME} ${SOURCES} ${PROJECT_HEADERS})

add_dependencies(${PROJECT_NAME} 
  ubus_utils
)

target_include_directories(${PROJECT_NAME}
  PRIVATE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
)

target_link_libraries(${PROJECT_NAME}
  ubus_utils
  ${BLOBMSG_JSON}
  ${UBOX}
  ${JSON_C}
  ${UBUS}
)

set_target_properties(${PROJECT_NAME} 
  PROPERTIES 
    VERSION ${PROJECT_VERSION}
    OUTPUT_NAME ${EXE_NAME}
)

install(TARGETS ${PROJECT_NAME} 
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

add_subdirectory(early.d)

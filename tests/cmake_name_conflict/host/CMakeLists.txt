# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT name_conflict_u.h name_conflict_u.c name_conflict_args.h
  DEPENDS edger8r ../name_conflict.edl
  COMMAND edger8r --untrusted --search-path ${CMAKE_CURRENT_SOURCE_DIR}/..
          name_conflict.edl)

add_executable(name_conflict_host host.cpp name_conflict_u.c name_conflict_u.h
                                  name_conflict_args.h)

target_include_directories(name_conflict_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(name_conflict_host oehostapp)

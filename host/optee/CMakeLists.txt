# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

list(APPEND PLATFORM_SDK_ONLY_SRC
  optee/log.c)

list(APPEND PLATFORM_FLAGS "")

if (UNIX)
    add_subdirectory(linux)

else()
    message(FATAL_ERROR "OP-TEE is not yet supported on platforms other than Linux.")
endif()


set(PLATFORM_FLAGS ${PLATFORM_FLAGS} PARENT_SCOPE)
set(PLATFORM_SDK_ONLY_SRC ${PLATFORM_SDK_ONLY_SRC} PARENT_SCOPE)
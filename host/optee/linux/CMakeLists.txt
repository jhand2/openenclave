# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

list(APPEND PLATFORM_SDK_ONLY_SRC
  optee/linux/enclave.c)

set(PLATFORM_SDK_ONLY_SRC ${PLATFORM_SDK_ONLY_SRC} PARENT_SCOPE)
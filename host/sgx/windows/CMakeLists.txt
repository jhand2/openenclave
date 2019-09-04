# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

##==============================================================================
##
## these rules build the oehost target.
##
##==============================================================================


# oedebugrt is accessed via a bridge on Win32 and need not be linked.
list(APPEND PLATFORM_SDK_ONLY_SRC
    sgx/windows/debugrtbridge.c)

list(APPEND PLATFORM_SDK_ONLY_SRC
  sgx/windows/aep.asm
  sgx/windows/aesm.c
  sgx/windows/enter.asm
  sgx/windows/entersim.asm
  sgx/windows/exception.c
  sgx/windows/sgxquoteproviderloader.c
  sgx/windows/xstate.c)

set(PLATFORM_HOST_ONLY_SRC ${PLATFORM_HOST_ONLY_SRC} PARENT_SCOPE)
set(PLATFORM_SDK_ONLY_SRC ${PLATFORM_SDK_ONLY_SRC} PARENT_SCOPE)
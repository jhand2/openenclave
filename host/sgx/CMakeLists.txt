# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

list(APPEND PLATFORM_HOST_ONLY_SRC
  ../common/sgx/qeidentity.c
  ../common/sgx/quote.c
  ../common/sgx/report.c
  ../common/sgx/revocation.c
  ../common/sgx/sgxcertextensions.c
  ../common/sgx/tcbinfo.c
  ../common/sgx/tlsverifier.c
  sgx/hostverify_report.c
  sgx/sgxquoteprovider.c)

list(APPEND PLATFORM_SDK_ONLY_SRC
  sgx/calls.c
  sgx/create.c
  sgx/elf.c
  sgx/enclave.c
  sgx/enclavemanager.c
  sgx/exception.c
  sgx/sgx_u_wrapper.c
  sgx/load.c
  sgx/loadelf.c
  sgx/loadpe.c
  sgx/ocalls.c
  sgx/quote.c
  sgx/registers.c
  sgx/report.c
  sgx/sgxload.c
  sgx/sgxmeasure.c
  sgx/sgxquote.c
  sgx/sgxsign.c
  sgx/sgxtypes.c)

list(APPEND PLATFORM_FLAGS "-m64")

if(UNIX)
  add_subdirectory(linux)
elseif(WIN32)
  add_subdirectory(windows)
else()
    message(FATAL_ERROR "Unknown OS. Only supported OSes are Linux and Windows")
endif()

set(PLATFORM_FLAGS ${PLATFORM_FLAGS} PARENT_SCOPE)
set(PLATFORM_HOST_ONLY_SRC ${PLATFORM_HOST_ONLY_SRC} PARENT_SCOPE)
set(PLATFORM_SDK_ONLY_SRC ${PLATFORM_SDK_ONLY_SRC} PARENT_SCOPE)
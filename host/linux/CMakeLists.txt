# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

list(APPEND PLATFORM_HOST_ONLY_SRC
../common/cert.c
crypto/openssl/asn1.c
crypto/openssl/cert.c
crypto/openssl/crl.c
crypto/openssl/ec.c
crypto/openssl/init.c
crypto/openssl/key.c
crypto/openssl/rsa.c
crypto/openssl/sha.c
linux/hostthread.c)

list(APPEND PLATFORM_SDK_ONLY_SRC
../common/asn1.c
crypto/openssl/hmac.c
crypto/openssl/random.c
linux/syscall.c
linux/time.c
linux/windows.c)

set(PLATFORM_HOST_ONLY_SRC ${PLATFORM_HOST_ONLY_SRC} PARENT_SCOPE)
set(PLATFORM_SDK_ONLY_SRC ${PLATFORM_SDK_ONLY_SRC} PARENT_SCOPE)
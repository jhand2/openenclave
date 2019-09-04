# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

list(APPEND SDK_ONLY_SRC
    ../3rdparty/mbedtls/mbedtls/library/bignum.c
    ../common/asn1.c
    ../common/cert.c
    crypto/bcrypt/cert.c
    crypto/bcrypt/crl.c
    crypto/bcrypt/ec.c
    crypto/bcrypt/hmac.c
    crypto/bcrypt/key.c
    crypto/bcrypt/pem.c
    crypto/bcrypt/random.c
    crypto/bcrypt/rsa.c
    crypto/bcrypt/sha.c
    windows/hostthread.c
    windows/syscall.c
    windows/time.c)

set(PLATFORM_SDK_ONLY_SRC ${SDK_ONLY_SRC} PARENT_SCOPE)
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <stdio.h>
#include <string.h>
#include "syscallx.h"

void _start(void)
{
#if 1
    syscall3(SYS_write, 1, (long)"xxx\n", 4);
    syscall3(SYS_write, 1, (long)"yyy\n", 4);
    long ret = syscall3(SYS_write, 1, (long)"zzz\n", 4);

    if (ret == 0)
    {
        syscall3(SYS_write, 1, (long)"okay\n", 5);
    }
    else
    {
        syscall3(SYS_write, 1, (long)"!okay\n", 6);
    }

    syscall1(999, 222);
#else

    syscall6(0x01, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F);
    syscall6(0x02, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F);
    syscall6(0x03, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F);

#endif
}

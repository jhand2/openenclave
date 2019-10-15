// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/cpuid.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include "cpuid_t.h"

static void _execute_cpuid_instruction(
    unsigned int leaf,
    unsigned int subleaf,
    unsigned int* eax,
    unsigned int* ebx,
    unsigned int* ecx,
    unsigned int* edx)
{
    asm volatile("cpuid"
                 : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                 : "0"(leaf), "2"(subleaf));
}

static uint64_t _exception_handler(oe_exception_record_t* exception)
{
    oe_context_t* context = exception->context;

    if (exception->code == OE_EXCEPTION_ILLEGAL_INSTRUCTION)
    {
        uint64_t opcode = *((uint16_t*)context->rip);

        if (opcode == OE_CPUID_OPCODE)
        {
            return OE_EXCEPTION_CONTINUE_EXECUTION;
        }
        else
        {
            oe_abort();
        }
    }

    return OE_EXCEPTION_CONTINUE_SEARCH;
}

extern void (*oe_continue_execution_hook)(oe_context_t* context);

static void _continue_execution_hook(oe_context_t* context)
{
    extern void oe_execute_cpuid_instruction_ocall(
        uint32_t leaf,
        uint32_t subleaf,
        uint32_t * eax,
        uint32_t * ebx,
        uint32_t * ecx,
        uint32_t * edx);

    if (*((uint16_t*)context->rip) == OE_CPUID_OPCODE)
    {
        uint32_t rax;
        uint32_t rbx;
        uint32_t rcx;
        uint32_t rdx;

        oe_host_printf("=== _continue_execution_hook()\n");

        cpuid_ocall(
            (uint32_t)context->rax, /* leaf */
            (uint32_t)context->rcx, /* subleaf */
            &rax,
            &rbx,
            &rcx,
            &rdx);

        context->rax = rax;
        context->rbx = rbx;
        context->rcx = rcx;
        context->rdx = rdx;

        /* Skip over the CPUID instrunction. */
        context->rip += 2;
    }
}

void test_cpuid(void)
{
    oe_result_t result;

    result = oe_add_vectored_exception_handler(false, _exception_handler);
    OE_TEST(result == OE_OK);

    oe_continue_execution_hook = _continue_execution_hook;

    /* Execute the CPUID instruction to get leaf count. */
    {
        uint32_t leaf = 4;
        uint32_t subleaf = 1;
        uint32_t eax = 0;
        uint32_t ebx = 0;
        uint32_t ecx = 0;
        uint32_t edx = 0;

        _execute_cpuid_instruction(leaf, subleaf, &eax, &ebx, &ecx, &edx);

        oe_host_printf("=== _execute_cpuid_instruction()\n");
        oe_host_printf("eax=%x\n", eax);
        oe_host_printf("ebx=%x\n", ebx);
        oe_host_printf("ecx=%x\n", ecx);
        oe_host_printf("edx=%x\n", edx);
    }

    oe_host_printf("test_cpuid()\n");
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */

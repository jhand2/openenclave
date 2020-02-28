// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/sgxtypes.h>

//==============================================================================
//
// void oe_exit_enclave(uint64_t arg1, uint64_t arg2)
//
// Registers:
//     RDI - arg1
//     RSI - arg2
//
// Purpose:
//     Restores user registers and executes the EEXIT instruction to leave the
//     enclave and return control to the host. This function is called for two
//     reasons:
//
//         (1) To perform an ERET (ECALL return)
//         (2) To perform an OCALL
//
// Tasks:
//
//      (1) Determines whether the caller is performing a "clean exit"
//          or a "nested exit". ECALLs and OCALLs can be nested so
//          we define DEPTH as the number of ECALL stack frames. A
//          DEPTH of zero indicates no ECALL stack frames remain and
//          that no ECALLs are pending.
//
//      (2) If this is a nested exit, then save the enclave registers
//          on the enclave stack and save the stack pointer in the
//          thread data structure (td_t.last_sp)
//
//      (3) If this a clean exit, then store zero in td_t.last_sp, forcing
//          oe_enter() to recompute it on next entry.
//
//      (4) Clear enclave registers to avoid leaking data to the host.
//
//      (5) Restore the host registers from the thread data structure
//          (td_t).
//
//      (6) Execute the SGX EEXIT instruction, exiting the enclave and
//          returning control to the host.
//
//==============================================================================
void _oe_exit_enclave(uint64_t arg1, uint64_t arg2)
{
    td_t* td = oe_get_td();

    if (td->depth == 0)
    {
        // Clean exit
        td->base.last_sp = 0;
    }
    else
    {
        // TODO: Nested exit
        // Nested exit
        oe_notify_nested_exit_start();
    }

    // Clear general purpose registers
    register uint64_t r8 __asm__("r8") = 0;
    register uint64_t r9 __asm__("r9") = 0;
    register uint64_t r10 __asm__("r10") = 0;
    register uint64_t r11 __asm__("r11") = 0;
    register uint64_t r12 __asm__("r12") = 0;
    register uint64_t r13 __asm__("r13") = 0;
    register uint64_t r14 __asm__("r14") = 0;
    register uint64_t r15 __asm__("r15") = 0;

    // Clear flags
    asm volatile("push $0;"
                 "popf;");

    // Setup arguments for enclu
    register uint64_t rax __asm__("rax") = ENCLU_EEXIT;
    register uint64_t rbx __asm__("rbx") = host_rip;
    register uint64_t rcx __asm__("rcx") = host_rsp;
    register uint64_t rdx __asm__("rdx") = host_rbp;

    if (td->simulation)
    {
        asm volatile(
            // Restore host rsp and rbp
            "mov %%rcx, %%rsp;"
            "mov %%rdx, %%rbp;"
            "xor %%rcx, %%rcx;"
            "xor %%rdx, %%rdx;"
            "jmp *%%rcx;",
            :
            : "r"(rdi), "r"(rsi), "r"(rax), "r"(rbx), "r"(rcx));
    }
    else
    {
        asm volatile(
            // Restore host rsp and rbp
            "enclu;",
            :
            : "r"(rdi), "r"(rsi), "r"(rax), "r"(rbx), "r"(rcx));
    }

    // Does not return
    while (1)
        ;
}

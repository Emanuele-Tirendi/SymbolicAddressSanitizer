#include <stdio.h>
#include <iostream>

#define MALLOC(retptr, size) \
    retptr = (int*)malloc(size); \
    std::cout << "malloc for size: 0x" << std::hex << size << ", retptr: " << retptr << "\n"

#define FREE(ptr) \
    std::cout << "free for: " << ptr << "\n"; \
    std::cout.flush(); \
    free(ptr)

#define CALLOC(ptr, num, size) \
    ptr = (int*)calloc(num, size); \
    std::cout << "calloc for num: 0x" << std::hex << num << ", size: 0x" << std::hex << size << ", retptr: " << ptr << "\n"

#define REALLOC(retptr, argptr, size) \
    std::cout << "realloc for argptr: " << argptr << ", size: 0x" << std::hex << size << "\n" ; \
    std::cout.flush(); \
    retptr = (int*)realloc(argptr, size); \
    std::cout << ", retptr: " << retptr << "\n"

#define READ(var, addr) \
    std::cout << "read at: " << std::hex << addr << "\n"; \
    var = *addr

#define WRITE(var, addr) \
    std::cout << "write at: " << std::hex <<  addr << "\n"; \
    *addr = var

int input() {
    int i;
    scanf("%d", &i);
    return i;
}

void to_reach() {}

void not_to_reach() {}
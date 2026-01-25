// Wrong memory access, outside of heap

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {
    int* i;
    i = (int*) malloc(16 * sizeof(int));
    int a;
    int b;
    READ(a, (&b-64)); // access wrong stack addess
}
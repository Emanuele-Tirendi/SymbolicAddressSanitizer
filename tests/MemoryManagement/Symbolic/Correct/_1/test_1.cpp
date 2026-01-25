// Valid usage with symbolic sizes

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {

    int a0 = input(), a1 = input(), a4 = input(),
    a16 = input(), a32 = input(), a64 = input();
    int* ptr0 = (int*) input();
    int *i, *j, *k, *l, *m;

    if (ptr0 == 0
        && a0 == 0
        && a1 > 0 && a1 <= 1
        && a4 > 0 && a4 <= 4
        && a16 > 0 && a16 <= 16
        && a32 > 0 && a32 <= 32
        && a64 > 0 && a64 <= 64
        ) {

        // Case 1: check malloc and free
        i = (int*) malloc(a16);
        free(i);

        // Case 2: check calloc and realloc
        i = (int*) calloc(a1, a16);
        j = (int*) malloc(a16);
        // force angr implementation to change buffer location
        i = (int*) realloc(i, a32);
        free(i);
        free(j);

        // Case 3: Check if everything works together
        // allocate
        i = (int*) malloc(a32);
        j = (int*) calloc(a4, a4);
        k = (int*) malloc(a16);
        l = (int*) calloc(a4, a4);
        m = (int*) malloc(a16);
        // deallocate some
        free(i);
        // reallocate some
        j = (int*) realloc(j, a32); // reallocate to previous i
        l = (int*) realloc(l, a64); // reallocate to new place
        // free everything
        free(j);
        free(k);
        free(l);
        free(m);

        // Case 4: Can sizes of zero be handled?
        // check malloc and free
        i = (int*) malloc(a0);
        free(i);
        // check calloc and free
        i = (int*) calloc(a0, a0);
        free(i);
        // check realloc for first parameter
        i = (int*) malloc(a0);
        i = (int*) realloc(i, 1);
        free(i);
        // check realloc for second parameter
        j = (int*) malloc(8);
        j = (int*) realloc(j, a0); // should call free(j) and return null
        free(j); // should do nothing

        // Case 5: Can null pointers be handled?
        // check free
        free(ptr0);
        // check realloc
        i = (int*) realloc(ptr0, 1); // should call malloc(1)
        free(i);
        // check realloc with null size
        i = (int*) realloc(ptr0, a0); // should call malloc(0)
        free(i);
    }
}
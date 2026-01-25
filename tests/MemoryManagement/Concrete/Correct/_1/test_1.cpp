// Valid usage of concrete pointers and sizes

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {
    int *i, *j, *k, *l, *m;

    // Case 1: check malloc and free
    i = (int*) malloc(16);
    free(i);

    // Case 2: check calloc and realloc
    i = (int*) calloc(1, 64);
    j = (int*) malloc(128);
    // force angr implementation to change buffer location
    k = (int*) realloc(i, 128);
    free(k);

    // Case 3: Check if everything works together
    // allocate
    i = (int*) malloc(32);
    j = (int*) calloc(4, 4);
    k = (int*) malloc(16);
    l = (int*) calloc(4, 4);
    m = (int*) malloc(16);
    // deallocate some
    free(i);
    // reallocate some
    j = (int*) realloc(j, 32); // reallocate to previous i
    l = (int*) realloc(l, 64); // reallocate to new place
    // free everything
    free(j);
    free(k);
    free(l);
    free(m);

    // Case 4: Can sizes of zero be handled?
    // check malloc and free
    i = (int*) malloc(0);
    free(i);
    // check calloc and free
    i = (int*) calloc(0, 0);
    free(i);
    // check realloc for first parameter
    i = (int*) malloc(0);
    i = (int*) realloc(i, 1);
    free(i);
    // check realloc for second parameter
    j = (int*) malloc(8);
    j = (int*) realloc(j, 0); // should call free(j) and return null
    free(j); // should do nothing

    // Case 5: Can null pointers be handled?
    // check free
    free(0);
    // check realloc
    i = (int*) realloc(0, 1); // should call malloc(1)
    free(i);
    // check realloc with null size
    i = (int*) realloc(0, 0); // should call malloc(0)
    free(i);
}
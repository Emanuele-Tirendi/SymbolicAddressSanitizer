// Valid usage of concrete pointers and sizes

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {
    int *i, *j, *k, *l, *m;
    int a;

    // Boundary value analysis: malloc
    i = (int*) malloc(4 * sizeof(int));
    a = *i;
    a = *(i+2);
    a = *(i+3);

    // Boundary value analysis: calloc
    j = (int*) calloc(4, sizeof(int));
    *j = 3;
    *(j+2) = 3;
    *(j+3) = 3;

    // Boundary value analysis: realloc
    // Force angr implementation to change location of i
    i = (int*) realloc(i, 8 * sizeof(int));
    a = *i;
    a = *(i+4);
    a = *(i+7);
    free(j);
    free(i);

    // Check if everything works together
    // allocate some
    i = (int*) malloc(8 * sizeof(int));
    j = (int*) calloc(4, sizeof(int));
    k = (int*) malloc(4 * sizeof(int));
    l = (int*) calloc(4, sizeof(int));
    m = (int*) malloc(4 * sizeof(int));
    // deallocate some
    free(i);
    // reallocate some
    j = (int*) realloc(j, 8 * sizeof(int)); // reallocate to previous i
    l = (int*) realloc(l, 16 * sizeof(int)); // reallocate to new place
    // test
    a = *j;
    a = *(j+3);
    a = *k;
    a = *(k+3);
    *l = 3;
    *(l+15) = 3;
    *m = 3;
    *(m+3) = 15;
    // free everything
    free(j);
    free(k);
    free(l);
    free(m);

    // Can sizes of zero be handled?
    // 1.
    i = (int*) malloc(0 * sizeof(int));
    i = (int*) realloc(i, sizeof(int));
    *i = 3;
    // 2.
    i = (int*) realloc(0, sizeof(int));
    *i = 3;
}
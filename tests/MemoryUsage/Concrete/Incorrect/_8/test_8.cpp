// Boundary value analysis, spatially before realloc

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {
    int *i, *j, *k, *l;
    MALLOC(i, 4 * sizeof(int));
    MALLOC(j, 4 * sizeof(int));
    REALLOC(i, i, 8 * sizeof(int)); // force angr to change address of i
    MALLOC(l, 8 * sizeof(int));
    int a;
    to_reach();
    READ(a, (i-1));
    not_to_reach();
}
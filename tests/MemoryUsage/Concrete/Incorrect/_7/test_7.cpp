// Boundary value analysis, spatially after calloc

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {
    int *i, *j, *k;
    CALLOC(i, 4, sizeof(int));
    CALLOC(j, 4, sizeof(int));
    CALLOC(k, 4, sizeof(int));
    int a;
    to_reach();
    READ(a, (j+4));
    not_to_reach();
}
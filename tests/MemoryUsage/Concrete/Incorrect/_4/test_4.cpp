// Boundary value analysis, spatially before malloc

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {
    int *i, *j, *k;
    MALLOC(i, 4 * sizeof(int));
    MALLOC(j, 4 * sizeof(int));
    MALLOC(k, 4 * sizeof(int));
    int a;
    to_reach();
    READ(a, (j-1));
    not_to_reach();
}
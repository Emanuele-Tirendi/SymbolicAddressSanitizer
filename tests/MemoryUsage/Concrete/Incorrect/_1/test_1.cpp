// Memory access after free

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {
    int* i;
    MALLOC(i, 16 * sizeof(int));
    FREE(i);
    int a;
    to_reach();
    READ(a, i);
    not_to_reach();
}
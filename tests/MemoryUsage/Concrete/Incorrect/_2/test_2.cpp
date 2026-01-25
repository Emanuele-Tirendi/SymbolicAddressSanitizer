// Access parts of buffer that got cut out by realloc

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {
    int* i;
    CALLOC(i, 16, sizeof(int));
    REALLOC(i, i, 8 * sizeof(int));
    int a;
    to_reach();
    READ(a, (i+8));
    not_to_reach();
}
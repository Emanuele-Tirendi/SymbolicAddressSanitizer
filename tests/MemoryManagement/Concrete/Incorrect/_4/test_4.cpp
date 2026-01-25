// Realloc after free

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {
    int *a, *b, *c, *d, *e, *f, *g, *h, *i;

    CALLOC(a, 4, 16);
    FREE(a);
    to_reach();
    REALLOC(a, a, 128);
    not_to_reach();
}
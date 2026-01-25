// Realloc at wrong address

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {
    int *a;

    CALLOC(a, 4, 16);
    to_reach();
    REALLOC(a, a+1, 128);
    not_to_reach();
}
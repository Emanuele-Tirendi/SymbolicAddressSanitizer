// Wrong read within heap

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {
    int* i;
    MALLOC(i, 4 * sizeof(int));
    int a;
    to_reach();
    READ(a, (i+64));
    not_to_reach();
}
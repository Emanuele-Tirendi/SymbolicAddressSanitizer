// Double free

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {
    int* a;
    MALLOC(a, 16);

    FREE(a);
    to_reach();
    FREE(a);
    not_to_reach();
}
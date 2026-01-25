// Free at wrong address

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {
    int* i;
    MALLOC(i, 16);
    to_reach();
    FREE(i+1);
    not_to_reach();
}
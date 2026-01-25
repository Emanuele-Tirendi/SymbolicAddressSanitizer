// Wrong free

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {
    int *ptr;
    int size = input();
    int error = input();

    if (size > 0 && 8 >= size && error >= 0) {
        MALLOC(ptr, size);
        to_reach();
        FREE(ptr+error);
        not_to_reach();
    }
}
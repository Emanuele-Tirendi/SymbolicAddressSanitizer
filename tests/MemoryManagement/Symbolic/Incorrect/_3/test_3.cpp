// Wrong realloc

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {
    int *ptr;
    int size = input();
    int error = input();

    if (size > 0 && 8 >= size && error >= 0) {
        MALLOC(ptr, size);
        to_reach();
        REALLOC(ptr, ptr+error, size);
        not_to_reach();
    }
}
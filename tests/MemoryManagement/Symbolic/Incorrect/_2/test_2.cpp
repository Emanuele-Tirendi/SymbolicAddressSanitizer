// Double free

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {
    int* ptr[2];
    int size = input();
    int error = input();

    if (size > 0 && 8 >= size && error >= 0 && error <= 1) {
        MALLOC(ptr[0], size);
        MALLOC(ptr[1], size);
        FREE(ptr[0]);
        to_reach();
        FREE(ptr[error]);
        not_to_reach();
    }
}
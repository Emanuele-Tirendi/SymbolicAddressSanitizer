// Boundary value analysis, spatially after malloc

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {
    int *p1, *p2, *p3;
    int size = input();
    int access = input();
    int sint = input();

    if (size > 0 && 8 >= size
    && access >= 0 && access <= size-1
    && sint == sizeof(int)) {
        MALLOC(p1, size*sint);
        MALLOC(p2, size*sint);
        MALLOC(p3, size*sint);
        int a;
        to_reach();
        READ(a, (p2+size));
        not_to_reach();
    }
}
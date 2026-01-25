// Boundary value analysis, spatially after calloc

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {
    int *p1, *p2, *p3;
    int size = input();
    int num = input();
    int access = input();
    int sint = input();

    if (size > 0 && 2 >= size
    && num > 0 && 4 >= num
    && access >= 0 && access <= size-1
    && sint == sizeof(int)) {
        CALLOC(p1, num, size*sint);
        CALLOC(p2, num, size*sint);
        CALLOC(p3, num, size*sint);
        int a;
        to_reach();
        READ(a, (p2+num*size));
        not_to_reach();
    }
}
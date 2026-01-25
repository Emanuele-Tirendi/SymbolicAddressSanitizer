// Access parts of buffer that got cut out by realloc

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {
    int *p1;
    int size = input(), num = input(), reallocsize = input(), sint = input();
    int access = input();

    if (size > 0 && 8 >= size
    && num > 0 && 4 >= num
    && reallocsize > 0 && 4 >= reallocsize
    && sint == sizeof(int)
    && access >= reallocsize && access <= num*size-1) {
        CALLOC(p1, num, size*sint);
        REALLOC(p1, p1, reallocsize*sint);
        int a;
        to_reach();
        READ(a, (p1+access));
        not_to_reach();
    }
}
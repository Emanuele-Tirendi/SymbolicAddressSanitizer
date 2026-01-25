// Wrong free

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {
    int *p1, *p2;
    int size = input();
    int access = input();
    int sint = input();

    if (size > 0 && 8 >= size
    && access >= 0 && access <= size-1
    && sint == sizeof(int)) {
        MALLOC(p1, size*sint);
        MALLOC(p2, size*sint);
        FREE(p1);
        int a;
        to_reach();
        READ(a, (p1+access));
        not_to_reach();
    }
}
// Wrong read within heap

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {
    int *p;
    int size = input();
    int access = input();
    int sint = input();

    if (size > 0 && 8 >= size
    && access >= 64 && access <= 128
    && sint == sizeof(int)) {
        MALLOC(p, size*sint);
        int a;
        to_reach();
        READ(a, (p+access));
        not_to_reach();
    }
}
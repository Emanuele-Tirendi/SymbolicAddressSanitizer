// Boundary value analysis, spatially before realloc

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {
    int *p1, *p2, *p3;
    int s16 = input(), s32 = input();
    int access = input();
    int sint = input();

    if (s16 > 0 && 16 >= s16
    && s32 > 0 && 32 >= s32
    && sint == sizeof(int)) {
        MALLOC(p1, s16*sint);
        MALLOC(p2, s16*sint);
        REALLOC(p1, p1, s32*sint);
        MALLOC(p3, s32*sint);
        int a;
        to_reach();
        READ(a, (p1-1));
        not_to_reach();
    }
}
// Wrong memory access, outside of heap

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {

    int* i;
    int size = input(), *pb = (int*) input(), access = input(), sint = input();

    if (size > 0 && size <= 16
    && access == 64
    && sint == sizeof(int)) {
        i = (int*) malloc(size * sint);
        int a;
        int b;
        if (pb == &b) {
            READ(a, (pb-access)); // access at wrong stack address
        } else {return 0;}
    }
}
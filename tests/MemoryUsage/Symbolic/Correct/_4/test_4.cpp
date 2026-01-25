// Valid usage with symbolic sizes and pointers

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {

    int *m, *n, *o, *p;

    int a = input(), sint = input();

    int *y = (int*) input();

    if (sint == sizeof(int) && a > 0 && 2 >= a) {
        m = (int*) malloc(a * sint);
        n = (int*) malloc(a * sint);
        o = (int*) malloc(a * sint);
        p = (int*) malloc(a * sint);
        
        if (y >= m && y <= p && ((int) y - (int) (m)) % ((int)n - (int) m) == 0) {
            WRITE(3, y);
        }
    }
}
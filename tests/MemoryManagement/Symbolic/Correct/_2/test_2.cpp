// Valid usage with symbolic sizes and pointers

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {

    int *j, *k, *l, *y;

    int a = input(), b = input(), c = input();

    int *v = (int*) input(), *w = (int*) input(), x = input();

    if (a > 0 && 8 >= a
        && b > 0 && 16 >= b
        && c > 0 && c <= 128) {

        j = (int*) calloc(a, b);
        k = (int*) malloc(a);
        l = (int*) calloc(a, b);
        
        if (v+x == j &&
            (w == k || w == l)) {
            // case 1: aggregated pointers point to valid address
            y = (int*) realloc(v+x, c);
            free(y);
            // case 2: pointer points to several valid addresses
            free(w);
        }
    }
}
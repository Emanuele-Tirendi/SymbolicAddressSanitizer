// Valid usage with symbolic sizes and pointers

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {

    int *j, *k, *l;

    int a = input(), b = input(), c = input(), sint = input();

    int *v = (int*) input(), *w = (int*) input(), x = input();

    if (a > 0 && 2 >= a
        && b > 0 && 4 >= b
        && sint == sizeof(int)) {

        j = (int*) calloc(a, b*sint);
        k = (int*) malloc(a*sint);
        l = (int*) calloc(a, b*sint);
        
        if (v+x >= j && v+x <= j+a*b-1 &&
            (w >= k && w <= k+a-1 || w >= l && w <= l+a*b-1)) {
            // case 1: aggregated pointers point to valid address
            WRITE(3, (v+x));
            // case 2: pointer points to several valid addresses
            WRITE(3, w);
        }
    }
}
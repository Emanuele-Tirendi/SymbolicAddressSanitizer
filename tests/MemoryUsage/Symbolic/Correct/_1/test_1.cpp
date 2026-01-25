// Valid usage of concrete pointers and sizes

#include <stdlib.h>
#include "../../../../input.cpp"

int main() {
    int *i, *j, *k, *l, *m, *n, *o, *p, *q, *r, *s, *t, *u;

    int *pi = (int*) input(), *pj = (int*) input(),
    *pk = (int*) input(), *pl = (int*) input(), *pm = (int*) input(),
    *pn = (int*) input(), *po = (int*) input(), *pp = (int*) input(),
    *pq = (int*) input(), *pr = (int*) input(), *ps = (int*) input(),
    *pt = (int*) input(), *pu = (int*) input();

    int *p0 = (int*) input(), s0 = input(), s4 = input(),
    sint = input(), s8 = input(), s16 = input();
    int a;

    if (p0 == 0
    && s0 == 0
    && s4 > 0 && s4 <= 4
    && sint == sizeof(int)
    && s8 > 0 && s8 <= 8
    && s16 > 0 && s16 <= 16) {

        // Boundary value analysis: malloc
        i = (int*) malloc(s4 * sint);
        if (pi == i) {
            a = *pi;
            a = *(pi+ s4/2);
            a = *(pi+s4-1);
        } else {return 0;}

        // Boundary value analysis: calloc
        j = (int*) calloc(s4, sint);
        if (pj == j) {
            *pj = 3;
            *(pj+s4/2) = 3;
            *(pj+s4-1) = 3;
        } else {return 0;}

        // Boundary value analysis: realloc
        // Force angr implementation to change location of i
        k = (int*) realloc(i, s8 * sint);
        if (pk == k) {
            a = *pk;
            a = *(pk+s8/2);
            a = *(pk+s8-1);
        } else {return 0;}
        free(j);
        free(k);


        // Check if everything works together
        // allocate
        l = (int*) malloc(s8 * sint);
        m = (int*) calloc(s4, sint);
        n = (int*) malloc(s4 * sint);
        o = (int*) calloc(s4, sint);
        p = (int*) malloc(s4 * sint);
        if (pl == l && pm == m && po == o) {
            // deallocate some
            free(pl);
            // reallocate some
            q = (int*) realloc(pm, s8 * sint); // reallocate to previous i
            r = (int*) realloc(po, s16 * sint); // reallocate to new place
        } else {return 0;}
        if (pq == q && pn == n && pr == r && pp == p) {
            // test
            a = *pq;
            a = *(pq+s8-1);
            a = *pn;
            a = *(pn+s4-1);
            *pr = 3;
            *(pr+s16-1) = 3;
            *pp = 3;
            *(pp+s4-1) = 15;
            // free everything
            free(pq);
            free(pn);
            free(pr);
            free(pp);
        } else {return 0;}

        // Can sizes of zero be handled?
        s = (int*) malloc(s0 * sint);
        if (ps == s) {
            t = (int*) realloc(ps, sint);
        } else {return 0;}
        if (pt == t ) {
            *pt = 3;
        } else {return 0;}
        u = (int*) realloc(p0, sint);
        if (pu == u) {
            *pu = 3;
        } else {return 0;}
    }
}
---
title: "[Algorithm] bitmap sort"
published: 2026-10-18
description: Doing some basic stuffs...
category: Algorithm
tags: [C, study]
draft: false
---

# Bitmap Sort
Here's how bitmap sort works.  
<a href="https://ibb.co/qf08HWC"><img src="https://i.ibb.co/YMDS5yX/Screenshot-2026-10-18-at-6-01-55-PM.png" alt="Screenshot-2026-10-18-at-6-01-55-PM" border="0"></a>

Say I have an array of numbers I want to sort.  
I go through the array and set the bit that corresponds to each number.  
Then I scan the bits in index order and print the index of each set bit. That gives me the numbers in sorted order.  

Writing this up got me thinking about type conversions again.  
I caught myself reaching for `int` instead of `uint` without even thinking.  
I'm rusty.  

## Implementation
Let me start by laying out the problem.  

> Sort n "distinct" integers in the range [0, maxval) using a single bit vector.

The problem comes from `programming pearls`.  
The macros and the rest of the setup were already there. I just had to implement a few functions.  

```c
/*
 * Column 1 · Problem 1 — Bitmap Sort                              [Problem]
 *
 * Sort n "distinct" integers in the range [0, maxval) using a single bit vector.
 *   1) set_bit / clr_bit / test_bit : Manipulate bit i using shifts and masks
 *   2) bitmap_sort                  : Sort in O(n + maxval) time using a bit vector
 *
 * Run: ./run.sh 01-cracking-the-oyster/problems/p1_bitmap_sort.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ---- Simple test harness (do not modify) ---- */
static int g_fail = 0, g_total = 0;
#define CHECK(cond) do { g_total++; if (!(cond) && g_fail++ < 10) \
    printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); } while (0)
static int report(void)
{
    if (g_fail) printf("  Result: %d/%d checks failed\n", g_fail, g_total);
    else        printf("  Result: all %d checks passed\n", g_total);
    return g_fail != 0;
}

#define BITSPERWORD 32
#define SHIFT 5      /* 32 = 2^5 */
#define MASK  0x1F   /* i % 32 == i & 0x1F */

/* Set bit i of a to 1 */
void set_bit(uint32_t *a, int i)
{
    a[i>>SHIFT] |= (1U << (i & MASK));
    /* TODO: Implement this here */
    (void)a; (void)i;
}

/* Set bit i of a to 0 */
void clr_bit(uint32_t *a, int i)
{
    a[i>>SHIFT] &= ~(1U << (i & MASK));
    /* TODO: Implement this here */
    (void)a; (void)i;
}

/* Return 1 if bit i of a is set, otherwise 0 */
int test_bit(const uint32_t *a, int i)
{
    return (a[i>>SHIFT] & (1U << (i & MASK))) ? 1 : 0;
    /* TODO: Implement this here */
    (void)a; (void)i; return 0;
}

/* x[0..n-1]: distinct integers in the range [0, maxval). Overwrite x with the values in ascending order. */
void bitmap_sort(int *x, int n, int maxval)
{
    int idx = 0;
    int words = maxval / BITSPERWORD + 1;
    
    uint32_t *bits = calloc((size_t)words, sizeof *bits);
    if (!bits) return;

    for (int i = 0; i < n; i++) {
        set_bit(bits, x[i]);
    }

    for (int i = 0; i < maxval; i++) {
        if (test_bit(bits, i)) {
            x[idx++] = i;
        }
    }

    free(bits);

    /* TODO: Implement this here */
    (void)x; (void)n; (void)maxval;
}

static int cmp_int(const void *a, const void *b)
{
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

int main(void)
{
    uint32_t bits[4] = {0};
    set_bit(bits, 0); set_bit(bits, 31); set_bit(bits, 32); set_bit(bits, 100);
    CHECK(test_bit(bits, 0) && test_bit(bits, 31) && test_bit(bits, 32) && test_bit(bits, 100));
    CHECK(!test_bit(bits, 1) && !test_bit(bits, 33) && !test_bit(bits, 99));
    CHECK(bits[0] == 0x80000001u && bits[1] == 1u && bits[3] == (1u << 4));
    clr_bit(bits, 31);
    CHECK(!test_bit(bits, 31) && test_bit(bits, 0));

    int maxval = 1000000, n = 50000;
    int *x = malloc(sizeof(int) * n), *y = malloc(sizeof(int) * n);
    for (int i = 0; i < n; i++)            /* 7919 is prime → the values here are distinct */
        x[i] = (int)((long long)i * 7919 % maxval);
    memcpy(y, x, sizeof(int) * n);
    qsort(y, n, sizeof(int), cmp_int);
    bitmap_sort(x, n, maxval);
    int ok = 1;
    for (int i = 0; i < n; i++) if (x[i] != y[i]) ok = 0;
    CHECK(ok);

    int z[] = {7, 3, 9, 0, 5};
    bitmap_sort(z, 5, 10);
    CHECK(z[0] == 0 && z[1] == 3 && z[2] == 5 && z[3] == 7 && z[4] == 9);
    free(x); free(y);
    return report();
}
```

**Result**
```bash
▶ 01-cracking-the-oyster/problems/p1_bitmap_sort.c
  Result: all 6 checks passed
```

I implemented `set_bit()`, `clr_bit()`, `test_bit()`, and `bitmap_sort()`.  

It's not perfect, and I plan to revisit it.  
I was going to use a local array, but I looked it up just to be safe. That's when I realized I should use `calloc` instead because the array could take up too much stack space.  
The old setup was awkward to work with, so I organized the grading scripts, problems, and answer keys. I now keep the problems and concepts in separate folders.
<a href="https://ibb.co/0Rp6gdcT"><img src="https://i.ibb.co/4nwX657z/Screenshot-2026-10-18-at-6-11-20-PM.png" alt="Screenshot-2026-10-18-at-6-11-20-PM" border="0"></a>

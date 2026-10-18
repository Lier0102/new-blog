---
title: "[Algorithm] bitmap sort"
published: 2026-10-18
description: Doing some basic stuffs...
category: Algorithm
tags: [C, study]
draft: false
---

# Bitmap Sort
비트맵 정렬이라는 게 있다.  
<a href="https://ibb.co/qf08HWC"><img src="https://i.ibb.co/YMDS5yX/Screenshot-2026-10-18-at-6-01-55-PM.png" alt="Screenshot-2026-10-18-at-6-01-55-PM" border="0"></a>

원리는 간단하다. 배열 안에 숫자 몇 개 넣고 정렬해달라고 하면,  
원소를 확인하고 해당 원소의 비트를 켠다.  
그리고 비트를 켠 원소들을 출력하면 정렬된 결과를 얻을 수 있다.  

개인적으로 이번에 정리하면서 놓고 있던 형변환 감각을 다시 살펴 보았다.  
아무 생각 없이 `uint` 안 쓰고 `int` 쓰는 것부터,,  
너무 둔해졌다.  

## 구현
대강 문제 상황을 정의하고 시작하자.  

> [0, maxval) 범위의 "서로 다른" 정수 n개를 비트 벡터 하나로 정렬한다.

문제는 `programming pearls`에 나오는 내용이다.  
난 그냥 필요한 기능 몇 개만 구현했고, 매크로 같은 부분은 이미 준비되어 있었다.  

```c
/*
 * Column 1 · 문제 1 — 비트맵 정렬 (Bitmap Sort)                    [문제]
 *
 * [0, maxval) 범위의 "서로 다른" 정수 n개를 비트 벡터 하나로 정렬한다.
 *   1) set_bit / clr_bit / test_bit : 시프트·마스크로 i번째 비트 조작
 *   2) bitmap_sort                  : 비트 벡터를 이용한 O(n + maxval) 정렬
 *
 * 실행: ./run.sh 01-cracking-the-oyster/problems/p1_bitmap_sort.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ---- 간단한 테스트 도구 (수정하지 마세요) ---- */
static int g_fail = 0, g_total = 0;
#define CHECK(cond) do { g_total++; if (!(cond) && g_fail++ < 10) \
    printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); } while (0)
static int report(void)
{
    if (g_fail) printf("  결과: %d/%d 실패\n", g_fail, g_total);
    else        printf("  결과: %d개 검사 모두 통과\n", g_total);
    return g_fail != 0;
}

#define BITSPERWORD 32
#define SHIFT 5      /* 32 = 2^5 */
#define MASK  0x1F   /* i % 32 == i & 0x1F */

/* a의 i번째 비트를 1로 만든다 */
void set_bit(uint32_t *a, int i)
{
    a[i>>SHIFT] |= (1U << (i & MASK));
    /* TODO: 여기를 구현하세요 */
    (void)a; (void)i;
}

/* a의 i번째 비트를 0으로 만든다 */
void clr_bit(uint32_t *a, int i)
{
    a[i>>SHIFT] &= ~(1U << (i & MASK));
    /* TODO: 여기를 구현하세요 */
    (void)a; (void)i;
}

/* a의 i번째 비트가 1이면 1, 아니면 0 */
int test_bit(const uint32_t *a, int i)
{
    return (a[i>>SHIFT] & (1U << (i & MASK))) ? 1 : 0;
    /* TODO: 여기를 구현하세요 */
    (void)a; (void)i; return 0;
}

/* x[0..n-1]: [0, maxval) 범위의 서로 다른 정수. x를 오름차순으로 덮어쓴다. */
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

    /* TODO: 여기를 구현하세요 */
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
    for (int i = 0; i < n; i++)            /* 7919는 소수 → 서로 다른 값 보장 */
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

**결과**
```bash
▶ 01-cracking-the-oyster/problems/p1_bitmap_sort.c
  결과: 6개 검사 모두 통과
```

`set_bit()`, `clr_bit()`, `test_bit()`, `bitmap_sort()`를 구현했음.  

완벽하진 않다. 그리고 수정할 예정이다.  
지역 변수로 만드려다 혹시나 하는 마음에 찾아봤을 때 메모리 문제로 `calloc` 쓰는 게 맞다고 뒤늦게 알아챘다.  
불편해서 채점 스크립트 / 문제 / 답지 등 구조화하여 문제 폴더 / 개념 폴더를 사용하고 있다.
<a href="https://ibb.co/0Rp6gdcT"><img src="https://i.ibb.co/4nwX657z/Screenshot-2026-10-18-at-6-11-20-PM.png" alt="Screenshot-2026-10-18-at-6-11-20-PM" border="0"></a>

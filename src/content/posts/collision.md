---
title: "[pwnable.kr] collision"
published: 2026-09-23
description: 워게임 풀기
category: CTF
tags: [pwnable.kr, study]
draft: false
---

# 해시 충돌
우연/고의로 서로 다른 두 값을 넣었지만 해시 함수가 두 입력에 대해 같은 결괏값을 반환하는 상황.  
문제는 `collision`이다.

# 풀이

`check_password` 함수를 통과한 결과가 `0x21DD09EC`인 입력을 구해야 한다.  
`const char`로 전달 받은 값을 `int`로 변환한 뒤 이 값을 더해 `res`가 결정된다.  
따라서, `res`가 `0x21DD09EC`인 입력을 역으로 찾으면 된다.  
여러 가지가 있을 수도 있다고 생각한다. 여기선 `check_password`를 역으로 설계해 구했다.  
```c
// check_password
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
	int* ip = (int*)p;
	int i;
	int res=0;
	// 4바이트씩 5번
	for(i=0; i<5; i++){
		res += ip[i];
	}
	return res;
}
```

5번 나눴으니, 이걸 다시 5번 더하면 되는 지 확인하고자 보면:  
```py
✗ python3
Python 3.14.7 (main, Aug  5 2026, 10:29:49) [Clang 21.0.0 (clang-2100.1.1.101)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> a=0x21DD09EC
>>> print(a/5)
113626824.8
>>> print(a%5)
4
>>>
```

이런 이유로 `0x21DD09EC // 0x5`를 구한 뒤 이 값에 `4`만큼 곱한다.  
바로 그 값에 `0x21DD09EC // 0x5 + 0x21DD09EC % 0x5`를 더하면 된다.  

아래와 같이 확인했다.  
```c
// solve.c
#include <stdio.h>
#include <string.h>

unsigned long check_password(unsigned long target, char* out) {
    int *ip = (int *)out;

    int quot = (int)target / 5;
    int remain = (int)target % 5;

    for (int i = 0; i < 4; i++) {
        ip[i] = quot;
    }
    ip[4] = quot + remain;
}

int main(int *argc, char **argv) {
    unsigned long hashcode = 0x21DD09EC;
    char ans[21] = {'\0'};
    check_password(hashcode, ans);

    int *ip = (int *)ans;
    
    for (int i = 0; i < 5; i++) {
        printf("ip[%d] : 0x%08x (%d)", i, ip[i], ip[i]);
    }

    return 0;
}
```

해당 서버에 (현재 기준 `nc pwnable.kr 10002`) 에 접속하고 파이썬 스크립트 실행해주면 된다.
```py
./col "$(python3 -c 'import struct, sys; q, r = divmod(0x21DD09EC, 5); sys.stdout.buffer.write(struct.pack("<I", q) * 4 + struct.pack("<I", q + r))')"
```

재밌었다

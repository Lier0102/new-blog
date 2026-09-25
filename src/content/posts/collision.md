---
title: "[pwnable.kr] collision"
published: 2026-09-23
description: Solving a wargame challenge
category: CTF
tags: [pwnable.kr, study]
draft: false
---

# Hash Collision
A hash collision occurs when two different inputs—whether by accident or design—produce the same hash.  
The challenge is `collision`.

# Solution

We need an input that produces `0x21DD09EC` after passing through `check_password`.  
The buffer passed in as a `const char *` is reinterpreted as an `int *`, and the five integers are added together to determine `res`.  
Therefore, we can work backward to find an input that makes `res` equal to `0x21DD09EC`.  
There are probably several valid inputs. Here, I found one by reversing the logic of `check_password`.  
```c
// check_password
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
	int* ip = (int*)p;
	int i;
	int res=0;
	// Five 4-byte chunks
	for(i=0; i<5; i++){
		res += ip[i];
	}
	return res;
}
```

Since the value is split across five additions, I checked whether adding the quotient five times would work:  
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

Because of this, calculate `0x21DD09EC // 0x5`, then use that value four times.  
Then use `0x21DD09EC // 0x5 + 0x21DD09EC % 0x5` for the last value.  

I verified it as follows.  
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

Connect to the server (`nc pwnable.kr 10002` as of this writing), then run the following command.
```py
./col "$(python3 -c 'import struct, sys; q, r = divmod(0x21DD09EC, 5); sys.stdout.buffer.write(struct.pack("<I", q) * 4 + struct.pack("<I", q + r))')"
```

That was fun.

---
title: "[STUDY] Stack Pivot"
published: 2026-09-07
description: 간단한 스택 옮기기 연습
category: CTF
tags: [study]
draft: false
---

# Stack Pivot?!
오랜만에 드림핵에서 validator_revenge를 풀다가 문득,  
내가 스택 굽는 방법에 대해 기억하지 못한다는 사실을 깨달았다.  

이번 글에선 **Stack Pivot**에 대해 간단히 알아보겠다.

# 바이너리 정보
```bash
$ file pivot
pivot: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=0e9fb878206e1858b042597fd36c51aa07497121, not stripped

$ ldd pivot
        linux-vdso.so.1 (0x00007ced990c9000)
        libpivot.so => ./libpivot.so (0x00007ced98e00000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ced98a00000)
        /lib64/ld-linux-x86-64.so.2 (0x00007ced990cb000)

$ file libpivot.so
libpivot.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=b2d29bbead6e28b2470556f695dcde5536952075, not stripped

$ checksec --file=./pivot
[*] '/home/bankai/study/stack-pivoting/pivot'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'.'
    Stripped:   No
```

제공된 설명은 다음과 같다.
> Important!
This challenge imports a function named foothold_function() from a library that also contains a ret2win() function.

바로 IDA로 열어보겠다.  
<a href="https://ibb.co/LzwXnLHd"><img src="https://i.ibb.co/7Jcd2wLt/Screenshot-2026-09-07-at-9-26-10-AM.png" alt="Screenshot-2026-09-07-at-9-26-10-AM" border="0"></a>

<a href="https://ibb.co/B2M9MZyC"><img src="https://i.ibb.co/4RrHrT8V/Screenshot-2026-09-07-at-9-28-18-AM.png" alt="Screenshot-2026-09-07-at-9-28-18-AM" border="0"></a>

`main()`, `pwnme()`를 사진에서 볼 수 있다.  
정상적인 흐름으론 얘네 둘만 호출된다.  

<a href="https://ibb.co/XfWSJyG9"><img src="https://i.ibb.co/vCcZzsMb/Screenshot-2026-09-07-at-9-29-45-AM.png" alt="Screenshot-2026-09-07-at-9-29-45-AM" border="0"></a>

`Imports`에 `foothold_function()`이 있는 걸 볼 수 있다. 설명에서 거짓말 한 게 아니었다.  

<a href="https://ibb.co/yc4kfFX6"><img src="https://i.ibb.co/YF0dRB3c/Screenshot-2026-09-07-at-9-33-22-AM.png" alt="Screenshot-2026-09-07-at-9-33-22-AM" border="0"></a>

`ret2win()`함수도 마찬가지로 존재한다.  

호출된 적 없는 쪽이니까, `Import` 되어있는 `foothold_function()`을 호출하면 된다.  
그 다음 `.got.plt` 엔트리에 등록이 되면 `foothold_function()`의 실제 주소를 읽을 수 있게 된다, 음..  
이 함수의 `.got`이 가리키는 주소를 읽어 이 주소에 `ret2win()`의 주소와 차이(오프셋)를 더해 실행 흐름을 이리로 이동시킨다.

<a href="https://ibb.co/ns92wFCw"><img src="https://i.ibb.co/TB6XwsLw/Screenshot-2026-09-07-at-10-13-40-AM.png" alt="Screenshot-2026-09-07-at-10-13-40-AM" border="0"></a>

첫 입력에서 피벗할 주소에 값을 넣게 해준다. 또 주소를 출력해주기 때문에 기억해뒀다가  
bof할 때 pivot 주소를 rsp에 넣어주면 된다. `pop rax` + `xchg` 가젯으로 이것이 가능하다.

오랜만에 하는 거라 몇 번씩 익스코드가 뒤바꼈다. LLM 박사님들께서 너무 똑똑해지신 바람에..

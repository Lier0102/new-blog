---
title: "[Codegate Junior Preliminary Quals] imagination writeup"
published: 2026-03-31
description: Codegate Junior Preliminary
category: CTF
tags: [CTF, writeup, codegate2026]
draft: false
---

# Imagination 

> Run the program in your imagination, like the imaginary animal unicorn!

## Problem Overview
- **Category**: Rev
- **Topic**: VM

<!--more-->
---

VM. Virtual Machine.  
I know very well how painful this topic is.
It would be a lot of fun if we met while studying, but **if we met at CTF** it would be a different story.

Fortunately, this VM problem was not very difficult.

**! The explanation will be given with the function/variable names renamed in advance.**
Personally, I infer renaming function names is the most fun.

Because that is the easiest.

---
## Static analysis

```bash
prob: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),  
dynamically linked,..., stripped
```

```bash
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

But protection techniques were not that important.

---
### `main()`
there is only one, but it is just for formality.

First, up to 127 characters are input.
And save the length.
```c
  __printf_chk(2,"Input : ");
  __isoc99_scanf("%127s",local_128);
  sVar2 = strlen(local_128);
```
The length is
```c
  if (sVar2!= 0x4e) {
    __printf_chk(2,"Incorrect input length");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
```
It must be `0x4e`, `78` in decimal.

Open `code.bin` provided in the problem for reading.
Save the size of that file, that size + 1
```c
  __stream = fopen("./code.bin","r");
  if (__stream == (FILE *)0x0) {
    perror("fopen()");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  fseek(__stream,0,2);
  sVar2 = ftell(__stream);
  g_code_buf = malloc(sVar2 + 1);
```

Allocate memory to `g_code_buf`.
(Exception handling code is omitted here)

Now I have to read the code...

```c
  fseek(__stream,0,0);
  fread(g_code_buf,1,sVar2,__stream);
  fclose(__stream);
```

So I read it.

**however...**

suddenly unheard of
```c
iVar1 = uc_open(3,0x40000004,&local_130);
```
I met `uc_open()`.
My intuition told me that those 3 and 4 might be macro values.

This is `ELF`, but the constant 0x40... does not seem to make sense.

Search results
```c
uc_open(UC_ARCH_MIPS=3, UC_MODE_MIPS32|UC_MODE_BIG_ENDIAN=0x40000004, &uc)
```

I found out that the value of the macro was like this.
I saw the `MIPS` binary in the last ctf too...

---
#### branch
```c
if (iVar1 == 0) {...
} else {
    uVar4 = uc_strerror(iVar1);
    pcVar5 = "uc_open() failed: %s\n";
}
```

The next part looks like this.

`uc_open()` can be considered a function that creates and delivers a CPU emulator.
I was quite surprised when I saw this for the first time.

It appears is good because I get a lot from this CTF.
My grades are not good, but...
**Inside the if statement** there is the following code.

```c
    // input/Specify output area(input/Read results here)
    // UC_PROT_READ|WRITE=3
    iVar1 = uc_mem_map(local_130,0x1000000,0x1000,3);
    if (iVar1 == 0) {
      // Code execution area settings(RWX) << code.binThis is where it will be loaded
      //  UC_PROT_ALL=7
      iVar1 = uc_mem_map(local_130,0x1001000,0x1000,7);
      if (iVar1 == 0) {
         sVar3 = strlen(local_128);
     
         // Store 0x4e bytes of user input here.
         iVar1 = uc_mem_write(local_130,0x1000000,local_128,sVar3 + 1);
         if (iVar1 == 0) {
          // Write it down in the code area you assigned earlier.
           iVar1 = uc_mem_write(local_130,0x1001000,g_code_buf,sVar2);
           if (iVar1 == 0) {
            /* 
            uc_emu_start(uc, begin=0x1001000, until=code_size+0x1000ffb, timeout=0, count=100000)
            */
            // 0x1001000Run from start to end of code, No time limit, command is up to 100,000run twice
             iVar1 = uc_emu_start(local_130,0x1001000,sVar2 + 0x1000ffb,0,100000);
             if (iVar1 == 0) {
                // Through static analysis, it can be inferred that processing related to user input may occur among the executable code.
                // Read the region containing the user input after execution.
                iVar1 = uc_mem_read(local_130,0x1000000,local_a8,0x80);
                if (iVar1 == 0) {
                  // The values ​​read above and DAT_001020e0Success if the values ​​match, This value is probably a flag..
                  iVar1 = memcmp(local_a8,&DAT_001020e0,0x4e);
                  if (iVar1 == 0) {
                    puts("Correct!");
                  }
                  else {
                    puts("Try again.");
                  }
                  uc_close(local_130);
                  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
                    return 0;
                  }
                      /* WARNING: Subroutine does not return */
                  __stack_chk_fail();
                }
                uVar4 = uc_strerror(iVar1);
                pcVar5 = "uc_mem_read() failed: %s\n";
             }
             else {
                uVar4 = uc_strerror(iVar1);
                pcVar5 = "uc_emu_start() failed: %s\n";
             }
             goto LAB_001015ad;
           }
         }
         uVar4 = uc_strerror(iVar1);
         pcVar5 = "uc_mem_write() failed: %s\n";
         goto LAB_001015ad;
      }
    }
    uVar4 = uc_strerror(iVar1);
    pcVar5 = "uc_mem_map() failed: %s\n";
  }
```

The corresponding value is
```hex
                             DAT_001020e0                                    XREF[1]:     main:00101540(*)  
        001020e0 63??         63h    c
        001020e1 0b??         0Bh
        001020e2 0c??         0Ch
        001020e3 02??         02h
        001020e4 19??         19h
        001020e5 11??         11h
        001020e6 1e??         1Eh
        001020e7 1a??         1Ah
        001020e8 68??         68h    h
        001020e9 1b??         1Bh
        001020ea 33??         33h    3
        001020eb 0b??         0Bh
        001020ec 5a??         5Ah    Z
        001020ed 1e??         1Eh
        001020ee 2e??         2Eh.
        001020ef 71??         71h    q
        001020f0 ac??         ACh
        001020f1 13??         13h
        001020f2 48??         48h    H
        001020f3 43??         43h    C
        001020f4 0f??         0Fh
        001020f5 6f??         6Fh    o
        001020f6 e6??         E6h
        001020f7 52??         52h    R
        001020f8 ac??         ACh
        001020f9 69??         69h    i
        001020fa 4f??         4Fh    O
        001020fb 2a??         2Ah    *
        001020fc 6b??         6Bh    k
        001020fd 29??         29h    )
        001020fe 43??         43h    C
        001020ff 29??         29h    )
        00102100 31??         31h    1
        00102101 29??         29h    )
        00102102 70??         70h    p
        00102103 e1??         E1h
        00102104 a9??         A9h
        00102105 0e??         0Eh
        00102106 a0??         A0h
        00102107 52??         52h    R
        00102108 26??         26h    &
        00102109 69??         69h    i
        0010210a fc??         FCh
        0010210b d9??         D9h
        0010210c 8e??         8Eh
        0010210d 3e??         3Eh    >
        0010210e 4c??         4Ch    L
        0010210f 0c??         0Ch
        00102110 15??         15h
        00102111 b3??         B3h
        00102112 2b??         2Bh    +
        00102113 24??         24h    $
        00102114 93??         93h
        00102115 16??         16h
        00102116 6d??         6Dh    m
        00102117 9a??         9Ah
        00102118 dd??         DDh
        00102119 c5??         C5h
        0010211a 7a??         7Ah    z
        0010211b 22??         22h    "
        0010211c 41??         41h    A
        0010211d 5b??         5Bh    [
        0010211e d9??         D9h
        0010211f 19??         19h
        00102120 30??         30h    0
        00102121 5f??         5Fh    _
        00102122 4e??         4Eh    N
        00102123 f3??         F3h
        00102124 ad??         ADh
        00102125 09??         09h
        00102126 19??         19h
        00102127 3f??         3Fh?
        00102128 e7??         E7h
        00102129 da??         DAh
        0010212a cb??         CBh
        0010212b f4??         F4h
        0010212c fd??         FDh
        0010212d 96??         96h
        0010212e 00??         00h
```


It looks like this.

---

#### `code.bin` << In the end, what is this?

Because the CPU architecture to be emulated earlier was mips.
This one is also written in mips, so you can do it.

Read the code using 32-bit, mips, and big-endian
Analyzing:

```hex
code.bin size: 0x70
  0x00: 0x3c190100
  0x04: 0x24080000
  0x08: 0x2410004e
  0x0c: 0x24090000
  0x10: 0x0110082a
  0x14: 0x10200013
  0x18: 0x00000000
  0x1c: 0x21090001
  0x20: 0x0130082a
  0x24: 0x1020000d
  0x28: 0x00000000
  0x2c: 0x03295020
  0x30: 0x814a0000
  0x34: 0x03285820
  0x38: 0x816b0000
  0x3c: 0x00000000
  0x40: 0x01695820
  0x44: 0x014b5826
  0x48: 0x316b00ff
  0x4c: 0x03295020
  0x50: 0xa14b0000
  0x54: 0x08400408
  0x58: 0x21290001
  0x5c: 0x08400404
  0x60: 0x21080001
  0x64: 0x08400419
  0x68: 0x00000000
  0x6c: 0x00000000
```

You can break it like this.

```py
import struct
for i in range(0, len(code), 4):
    w = struct.unpack('>I', code[i:i+4])[0]
    print(f'  {i:#04x}: {w:#010x}')
```

The code for reading 4 bytes at a time is as above.

mips I have never read it, and I have not even looked it up properly.
Since it was an urgent situation, I quickly passed on the above information.

I got the following assembly:
```mips
0x00:  3c190100    lui     $t9, 0x100
0x04:  24080000    li      $t0, 0
0x08:  2410004e    li      $s0, 0x4e
0x0c:  24090000    li      $t1, 0

0x10:  0110082a    slt     $at, $t0, $s0
0x14:  10200013    beq     $at, $zero, 0x64
0x18:  00000000    nop

0x1c:  21090001    addi    $t1, $t0, 1
0x20:  0130082a    slt     $at, $t1, $s0
0x24:  1020000d    beq     $at, $zero, 0x5c
0x28:  00000000    nop

0x2c:  03295020    add     $t2, $t9, $t1
0x30:  814a0000    lb      $t2, 0($t2)

0x34:  03285820    add     $t3, $t9, $t0
0x38:  816b0000    lb      $t3, 0($t3)

0x3c:  00000000    nop

0x40:  01695820    add     $t3, $t3, $t1
0x44:  014b5826    xor     $t3, $t2, $t3
0x48:  316b00ff    andi    $t3, $t3, 0xff

0x4c:  03295020    add     $t2, $t9, $t1
0x50:  a14b0000    sb      $t3, 0($t2)

0x54:  08400408    j       0x1020
0x58:  21290001    addi    $t1, $t1, 1

0x5c:  08400404    j       0x1010
0x60:  21080001    addi    $t0, $t0, 1

0x64:  08400419    j       0x1064
0x68:  00000000    nop
```

```c
for (i = 0; i < 0x4e; i++) {
  for (j = i+1; j < 0x4e; j++) {
    // a = buf[j]
    // b = buf[i]

    // b = (b + j) ^ a
    // b &= 0xff

    // buf[j] = b
    buf[j] = (buf[j] ^ (buf[i] + j)) & 0xff
  }
}
```

It feels like this.

Since the above is implemented in Python and decryption is required, we will implement that part as well.

```py
def enc(data):
  buf = list(data) # byte list
  n = len(buf)

  # 0~n-2
  for i in range(n-1): # from the inside i+1Because it approaches n-1;;
    for j in range(i + 1, n):
      buf[j] = (buf[j] ^ (buf[i] + j)) & 0xff
  return buf


def dec(data):
  buf = list(data)
  n = len(buf)

  # n-2~0
  for i in range(n-2, -1, -1):
    for j in range(n - 1, i, -1):
      buf[j] = (buf[j] ^ buf[i] + j) & 0xff
  
  return buf
```
---

This was the easiest problem.
I remember I solved this and sent the no more mips gif to Codegate Dico.

I was a little sad that there was no reaction to the gif.

(I am learning a lot from Kanye West)

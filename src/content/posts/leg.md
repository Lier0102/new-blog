---
title: "[pwnable.kr] leg"
published: 2026-09-28
description: Solving a wargame challenge
category: CTF
tags: [pwnable.kr, study]
draft: false
---

# A Quick Look at ARM32
While working through this challenge, I realized I couldn't remember the assembly differences between `arm32` and `arm64`, fr  
I looked it up; apparently, 32-bit ARM uses the `r`-series registers, while 64-bit ARM uses the `x`-series.  
could be wrong. I guess I'll find out eventually; that's my understanding for now.

# Solution

### Assembly
The program adds the return values from `key1()`, `key2()`, and `key3()`, then compares the sum with the value I typed.  
If they don't match, it won't show the flag.  
So, read the attached `leg.asm`, work out the sum, and enter it.  

The input must be a decimal integer.  

```asm
...
Dump of assembler code for function main:
...
   0x00008d68 <+44>:	bl	0x8cd4 <key1>
   0x00008d6c <+48>:	mov	r4, r0
   0x00008d70 <+52>:	bl	0x8cf0 <key2>
   0x00008d74 <+56>:	mov	r3, r0
   0x00008d78 <+60>:	add	r4, r4, r3
   0x00008d7c <+64>:	bl	0x8d20 <key3>
   0x00008d80 <+68>:	mov	r3, r0
   0x00008d84 <+72>:	add	r2, r4, r3
   0x00008d88 <+76>:	ldr	r3, [r11, #-16]
   0x00008d8c <+80>:	cmp	r2, r3
   0x00008d90 <+84>:	bne	0x8da8 <main+108>
...
End of assembler dump.
--------------------------------------------------------------------------------
Dump of assembler code for function key1:
...
   0x00008cdc <+8>:	mov	r3, pc
   0x00008ce0 <+12>:	mov	r0, r3
...
End of assembler dump.
--------------------------------------------------------------------------------
(gdb) disass key2
Dump of assembler code for function key2:
...
   0x00008d04 <+20>:	mov	r3, pc
   0x00008d06 <+22>:	adds	r3, #4
   0x00008d08 <+24>:	push	{r3}
   0x00008d0a <+26>:	pop	{pc}
   0x00008d0c <+28>:	pop	{r6}		; (ldr r6, [sp], #4)
   0x00008d10 <+32>:	mov	r0, r3
...
End of assembler dump.
--------------------------------------------------------------------------------
(gdb) disass key3
Dump of assembler code for function key3:
...
   0x00008d28 <+8>:	mov	r3, lr
   0x00008d2c <+12>:	mov	r0, r3
...
End of assembler dump.
```

These are just the parts that matter. This is `arm32`.  
Anyway, if you can read assembly(i hope so), I think you only need to understand three ARM registers for this challenge: `lr`, `r0`, and `pc`.  

- `lr` stores the address to return to—the `return address`.  
- `r0` holds the function's return value, roughly like `rax`.  
- `pc` holds the address of the next instruction, though it works a little differently in the ARM architecture.  

For the third point, this Stack Overflow post may help:  
[A Stack Overflow explanation](https://stackoverflow.com/questions/24091566/why-does-the-arm-pc-register-point-to-the-instruction-after-the-next-one-to-be-e)

### The Exact Values to Enter
`key1()` is `0x00008ce4`, `key2()` is `0x00008d0c`, and `key3()` is `0x00008d80`. The Stack Overflow post above explains why. Anyway, that's about it.  

This turned out to be a better review exercise than I expected.

Umm, and this is how I solved it:
```py
python3 -c "a='0x00008ce4';b='0x00008d0c';c='0x00008d80';a=int(a,16);b=int(b,16);c=int(c,16);print(a+b+c)"
108400
```

me tend to write things down as they come to mind be like:  
<a href="https://ibb.co/pv22DkNM"><img src="https://i.ibb.co/4ZWWy0CX/memeforpost.webp" alt="memeforpost" border="0"></a>

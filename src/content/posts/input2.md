---
title: "[pwnable.kr] input2"
published: 2026-09-27
description: Solving a wargame challenge
category: CTF
tags: [pwnable.kr, study]
draft: false
---

# input2
이번 문제는 다른 입력값 비교 문제와 같았다.  
다만, 수단이 여러 가지라 배울 게 많았다.  

# 파일 정보 보기
```bash
$ rabin2 -I ./input2
arch     x86
baddr    0x0
binsz    14731
bintype  elf
bits     64
canary   true
class    ELF64
compiler GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0
crypto   false
endian   little
havecode true
intrp    /lib64/ld-linux-x86-64.so.2
laddr    0x0
lang     c
linenum  true
lsyms    true
machine  AMD x86-64 architecture
nx       true
os       linux
pic      true
relocs   true
relro    full
rpath    NONE
sanitize false
static   false
stripped false
subsys   linux
va       true
```

딱히 이상한 건 없다. 적당히 입력값이나 잘 넣으라는 의도로 파악했다.  

## 코드도 보기

필요한 부분만 최대한 담아봤다.  
검사하는 부분들이다.
```c
...
// input2.c
int main(int argc, char* argv[], char* envp[]){
    ...
	// argv
	if(argc != 100) return 0;
	if(strcmp(argv['A'],"\x00")) return 0;
	if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
	printf("Stage 1 clear!\n");	

	// stdio
	char buf[4];
	read(0, buf, 4);
	if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
	read(2, buf, 4);
        if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
	printf("Stage 2 clear!\n");
	
	// env
	if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
	printf("Stage 3 clear!\n");

	// file
	FILE* fp = fopen("\x0a", "r");
	if(!fp) return 0;
	if( fread(buf, 4, 1, fp)!=1 ) return 0;
	if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
	fclose(fp);
	printf("Stage 4 clear!\n");	

	// network
	...
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd == -1){
		printf("socket error, tell admin\n");
		return 0;
	}
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons( atoi(argv['C']) );
	if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
		printf("bind error, use another port\n");
    		return 1;
	}
	...
	if( recv(cd, buf, 4, 0) != 4 ) return 0;
	if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;
	printf("Stage 5 clear!\n");

	// here's your flag
...
}
```

워낙 `python`을 쓰는 게 간단한 스크립트 만들거나 `ctf`, 간단한 문제 풀 때밖에 없었다. 최근엔,,  
그런 이유로 `pwntools`만 써서 어떻게 풀다 생각하다가 머리가 뜨거워졌다.  

파이썬 스크립트는 `nc`로 서버에 접속한 뒤 직접 실행이 되니까 딱히 더 생각할 필욘 없고,  
실행 인자는 `pwntools`에 있는 `process()`로 객체 만들 때 넣는 인자로 적당히 넣으면 된다.  

`stdin`, `stderr`로 입력을 받는 부분은 `os` 라이브러리로 해결하면 되고,  
`env` 또한 `pwntools`에 있는 `process()`로 넣을 수 있다.  

아, 중간에 `socket` 처리 부분을 못 봐서 고생했다. `argv['C']`에 저장된 포트로 소켓 통신을 한다.  
뒤늦게 고쳤다..  

돌고 돌아 정리하자면 시나리오는 이랬다:  

```text
// 또 markdown 'text' 이런 언어로 달아두면 인공지능이 넣었다고 그러겠지만 그렇진 않습니다
1. p = process(
    argv = args,
    stdin = r_stdin,
    stderr = r_stderr,
    env=env_
)

2. 소켓은 짜피 그 서버에 접속 후 로컬에서 돌아가니 127.0.0.1로 들어가고
s.send(b'\xde\xad\xbe\xef') 로 해결!
```

# 풀이
```py
import os; import time; import socket
from pwn import *

context.log_level = "debug"

with open('\x0a', 'wb') as f:
    f.write(b'\x00'*0x4)

port = "31337"
args = ['A'] * 100
args[0] = './input2'
args[ord('A')] = ''
args[ord('B')] = '\x20\x0a\x0d'
args[ord('C')] = port

r_stdin, w_stdin = os.pipe()
r_stderr, w_stderr = os.pipe()

os.write(w_stdin, b'\x00\x0a\x00\xff')
os.write(w_stderr, b'\x00\x0a\x02\xff')

env_ = { '\xde\xad\xbe\xef': '\xca\xfe\xba\xbe' }

p = process(
    argv = args,
    stdin = r_stdin,
    stderr = r_stderr,
    env=env_
)

time.sleep(1)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", int(port)))
s.send(b'\xde\xad\xbe\xef')
s.close()

p.interactive()
```

오랜만에 스택오버플로우에서 검색도 해봤다. 나 좀 고수인듯;;  
그러고 보니 요즘엔 스택오버플로우 쓰는 놈들이 있을까 의문이다,,,

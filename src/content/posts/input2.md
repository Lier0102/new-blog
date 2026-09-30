---
title: "[pwnable.kr] input2"
published: 2026-09-27
description: Solving a wargame challenge
category: CTF
tags: [pwnable.kr, study]
draft: false
---

# input2
This was much like the other challenges that check your input values.  
There were several different ways to provide the inputs, though, so I learned quite a bit.  

# Binary Information
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

Nothing looks unusual. I took it as a hint to just get the inputs right.  

## Looking at the Code

I kept only the parts that matter.  
These are the checks the program performs.
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

I'd mostly used Python for simple scripts, CTFs, and small problems. Lately, tho...    

The Python script runs directly after connecting to the server with `nc`, so there isn't much else to think about there.  
For the program's arguments, I could pass them when creating the process with `pwntools`'s `process()`.  

I could handle input through `stdin` and `stderr` with the `os` library,  
and pass `env` to `process()` from `pwntools` as well.  

I got stuck because I missed the socket-handling part in the middle. It connects to the port stored in `argv['C']`.  
I only fixed that later...  

After going in circles, here's the flow I ended up with:  

```text
// If I label this as Markdown 'text', people might say an AI added it, but it didn't.
1. p = process(
    argv = args,
    stdin = r_stdin,
    stderr = r_stderr,
    env=env_
)

2. The socket runs locally on the server, so connect to 127.0.0.1
and handle it with s.send(b'\xde\xad\xbe\xef')!
```

# Solution
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

I even looked something up on Stack Overflow for the first time in a while. I'm kind of a pro now, huh...  
Then again, wondering if anyone still uses stack overflow these days...

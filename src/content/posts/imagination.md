---
title: "[Codegate Junior Preliminary Quals] imagination writeup"
published: 2026-03-31
description: 코게 주니어 예선
category: CTF
tags: [CTF, writeup, codegate2026]
draft: false
---

# Imagination 

> Run the program in your imagination, like the imaginary animal unicorn!

## 문제 개요
- **카테고리**: Rev
- **주제**: VM

<!--more-->
---

VM. Virtual Machine.  
나는 이 주제가 얼마나 고통스러운지 아주 잘 알고 있다.  
공부할 때 만난다면 더없이 즐겁지만, **CTF에서 만난다면** 이야기가 달라진다.  

다행히, 이번 VM문제는 엄청 어렵진 않았다..  

**!! 미리 함수/변수명을 리네임 한 상태에서 설명을 할 예정이다.**  
개인적으로 리네임은 함수명 리네임이 제일 재밌는 것 같다.  

그게 제일 쉬우니까.  

---
## 정적 분석

```bash
prob: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),  
dynamically linked, ..., stripped
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

근데 보호기법이 그렇게 중요하진 않았다.  

---
### `main()`
걍 얘 하나만 있긴 한데 일단 형식상 달았다.  

가장 먼저 최대 127글자를 입력받는다.  
그리고 길이를 저장한다.
```c
  __printf_chk(2,"Input : ");
  __isoc99_scanf("%127s",local_128);
  sVar2 = strlen(local_128);
```
길이는 
```c
  if (sVar2 != 0x4e) {
    __printf_chk(2,"Incorrect input length");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
```
`0x4e`, 10진수로 `78`이여야 한다.  

문제에서 제공한 `code.bin`을 읽기로 열어서  
그 파일의 크기를 저장, 해당 크기 + 1만큼
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

`g_code_buf`에 메모리를 할당해준다.  
(예외 처리 코드는 여기서 생략)  

이제 코드를 읽어야겠지!?!?!?!?!?!?  

```c
  fseek(__stream,0,0);
  fread(g_code_buf,1,sVar2,__stream);
  fclose(__stream);
```

그래서 읽었습니다.  

**그런데...**  

갑자기 듣도보도 못한  
```c
iVar1 = uc_open(3,0x40000004,&local_130);
```
`uc_open()`을 만났다.  
내 직감이 저 3, 4는 매크로 값이 아닐까 라고 말했다.  

얘가 `ELF`인데 상수 0x40...은 좀 말이 안되는 것 같아서ㅇㅇ  

찾아본 결과  
```c
uc_open(UC_ARCH_MIPS=3, UC_MODE_MIPS32|UC_MODE_BIG_ENDIAN=0x40000004, &uc)
```

매크로의 값은 이렇다는 걸 알 수 있었다.  
저번 ctf에서도 `MIPS` 바이너리를 봤던 것 같은데..  

---
#### 분기
```c
if (iVar1 == 0) {
  ...
} else {
    uVar4 = uc_strerror(iVar1);
    pcVar5 = "uc_open() failed: %s\n";
}
```

그 다음 부분은 이렇게 생겼다.  

`uc_open()`은 cpu 에뮬레이터 하나 만들어 건내주는 함수라고 보면 된다.  
솔직히 이거 처음봐서 꽤 놀랐음.  

이번 ctf에서 얻는 게 많아서 나름 좋은 것 같다.  
성적은 좋지 않지만..  
**if문 내부**에는 다음과 같은 코드가 있다.  

```c
    // 입력/출력 영역 지정(입력/결과를 여기서 읽게 설정)
    // UC_PROT_READ|WRITE=3
    iVar1 = uc_mem_map(local_130,0x1000000,0x1000,3);
    if (iVar1 == 0) {
      // 코드실행영역 설정(RWX) << code.bin이 로드될 곳임
      //  UC_PROT_ALL=7
      iVar1 = uc_mem_map(local_130,0x1001000,0x1000,7);
      if (iVar1 == 0) {
         sVar3 = strlen(local_128);
     
         // 0x4e 바이트(내..그러니까 사용자 입력)를 여기에 저장
         iVar1 = uc_mem_write(local_130,0x1000000,local_128,sVar3 + 1);
         if (iVar1 == 0) {
          // 아까 할당한 코드 영역에 적기
           iVar1 = uc_mem_write(local_130,0x1001000,g_code_buf,sVar2);
           if (iVar1 == 0) {
            /* 
            uc_emu_start(uc, begin=0x1001000, until=code_size+0x1000ffb, timeout=0, count=100000)
            */
            // 0x1001000부터 코드끝까지 실행, 제한시간 없음, 명령은 최대 100,000회 실행
             iVar1 = uc_emu_start(local_130,0x1001000,sVar2 + 0x1000ffb,0,100000);
             if (iVar1 == 0) {
                // 정적분석으로는 저 실행코드 중 사용자의 입려과 관련된 처리가 일어날 수 있다는 점을 유추 가능함 ㅇㅇ
                // 실행 후 사용자 입력값이 담겨있던 곳 읽기
                iVar1 = uc_mem_read(local_130,0x1000000,local_a8,0x80);
                if (iVar1 == 0) {
                  // 위 읽은 값과 DAT_001020e0의 값이 일치하면 성공, 아마 이 값이 플래그일 것으로 예상.
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

해당하는 곳의 값은  
```hex
                             DAT_001020e0                                    XREF[1]:     main:00101540(*)  
        001020e0 63              ??         63h    c
        001020e1 0b              ??         0Bh
        001020e2 0c              ??         0Ch
        001020e3 02              ??         02h
        001020e4 19              ??         19h
        001020e5 11              ??         11h
        001020e6 1e              ??         1Eh
        001020e7 1a              ??         1Ah
        001020e8 68              ??         68h    h
        001020e9 1b              ??         1Bh
        001020ea 33              ??         33h    3
        001020eb 0b              ??         0Bh
        001020ec 5a              ??         5Ah    Z
        001020ed 1e              ??         1Eh
        001020ee 2e              ??         2Eh    .
        001020ef 71              ??         71h    q
        001020f0 ac              ??         ACh
        001020f1 13              ??         13h
        001020f2 48              ??         48h    H
        001020f3 43              ??         43h    C
        001020f4 0f              ??         0Fh
        001020f5 6f              ??         6Fh    o
        001020f6 e6              ??         E6h
        001020f7 52              ??         52h    R
        001020f8 ac              ??         ACh
        001020f9 69              ??         69h    i
        001020fa 4f              ??         4Fh    O
        001020fb 2a              ??         2Ah    *
        001020fc 6b              ??         6Bh    k
        001020fd 29              ??         29h    )
        001020fe 43              ??         43h    C
        001020ff 29              ??         29h    )
        00102100 31              ??         31h    1
        00102101 29              ??         29h    )
        00102102 70              ??         70h    p
        00102103 e1              ??         E1h
        00102104 a9              ??         A9h
        00102105 0e              ??         0Eh
        00102106 a0              ??         A0h
        00102107 52              ??         52h    R
        00102108 26              ??         26h    &
        00102109 69              ??         69h    i
        0010210a fc              ??         FCh
        0010210b d9              ??         D9h
        0010210c 8e              ??         8Eh
        0010210d 3e              ??         3Eh    >
        0010210e 4c              ??         4Ch    L
        0010210f 0c              ??         0Ch
        00102110 15              ??         15h
        00102111 b3              ??         B3h
        00102112 2b              ??         2Bh    +
        00102113 24              ??         24h    $
        00102114 93              ??         93h
        00102115 16              ??         16h
        00102116 6d              ??         6Dh    m
        00102117 9a              ??         9Ah
        00102118 dd              ??         DDh
        00102119 c5              ??         C5h
        0010211a 7a              ??         7Ah    z
        0010211b 22              ??         22h    "
        0010211c 41              ??         41h    A
        0010211d 5b              ??         5Bh    [
        0010211e d9              ??         D9h
        0010211f 19              ??         19h
        00102120 30              ??         30h    0
        00102121 5f              ??         5Fh    _
        00102122 4e              ??         4Eh    N
        00102123 f3              ??         F3h
        00102124 ad              ??         ADh
        00102125 09              ??         09h
        00102126 19              ??         19h
        00102127 3f              ??         3Fh    ?
        00102128 e7              ??         E7h
        00102129 da              ??         DAh
        0010212a cb              ??         CBh
        0010212b f4              ??         F4h
        0010212c fd              ??         FDh
        0010212d 96              ??         96h
        0010212e 00              ??         00h
```


이렇게 생겼다.  

---

#### `code.bin` << 결국엔 얘가 뭐냐??  

아까 에뮬할 cpu 아키텍쳐가 mips였으니까  
얘도 mips로 작성된 녀석이니 하면 된다 ㅇㅇ  

32비트, mips, 빅엔디안이라는 점을 이용해 코드를 읽어  
분석하면:  

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

이렇게 끊을 수 있다.  

```py
import struct
for i in range(0, len(code), 4):
    w = struct.unpack('>I', code[i:i+4])[0]
    print(f'  {i:#04x}: {w:#010x}')
```

4바이트씩 끊어 읽은 코드는 위와 같고  

mips 읽어본 적도 없고 제대로 찾아보지도 않았다.  
시급한 상황이라 재빨리 위 내용을 넘겼고  

아래와 같은 어셈블리를 얻었다.
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

이런 느낌이다.  

위를 파이썬으로 구현하고 복호화가 필요하니 그 부분도 같이 구현하겠다.  

```py
def enc(data):
  buf = list(data) # byte list
  n = len(buf)

  # 0~n-2
  for i in range(n-1): # 안쪽에서 i+1까지 접근 하므로 n-1ㅇㅇ;;
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

이게 그나마 쉬운 문제였다.  
내가 이거 풀고 코드게이트 디코에 no more mips gif 보냈던 걸로 기억한다.  

gif에 반응이 없어 좀 슬펐다.  

(대충 칸예웨스트 많이 배워갑니다 짤)

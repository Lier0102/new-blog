---
title: "[pwnable.kr] leg"
published: 2026-09-28
description: Solving a wargame challenge
category: CTF
tags: [pwnable.kr, study]
draft: false
---

# arm32 읽기
이번에 풀면서 `arm32`와 `arm64`의 어셈블리 차이가 기억이 나지 않는다는 점을 알게 되었다.  
검색했다, 그 결과 그냥 32비트는 r??계열 레지스터, 64비트는 x??계열 레지스터를 쓰는 것으로 보인다.  
아니면 말고, 나중에 알게 되겠지. 우선은 이렇다.

# 풀이

### 어셈블리
`key1()`, `key2()`, `key3()` 함수의 각 반환값을 더하여 내 입력값과 동일한 지 비교한다.  
다르면 플래그를 못 읽는다.  
따라서 첨부파일에 있는 `leg.asm`을 읽어보고, 각 값의 합을 알아내어 입력하면 된다.  

입력은 10진 정수로 해야 한다.  

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

중요한 부분만 담았다. `arm32`다.  
아무튼, 어셈블리 읽을 줄만 안다면 해당 문제에서 `arm`에 관련해선 `lr`, `r0`, `pc`.  
위 세 레지스터의 동작 방식에 대해서만 인지하면 충분하다. 고 본다.  

- `lr`은 돌아갈 주소, `return address`를 저장한다.  
- `r0`은 함수의 반환값, `rax` 격의 느낌이다.  
- `pc`는 다음에 실행될 명령어 주소, 그러나 `arm` 아키텍쳐에선 조금 다르다.  

세 번째 항목에 대해선 다음 글을 참고하면 좋을 것 같다.  
[대충 스오플 링크](https://stackoverflow.com/questions/24091566/why-does-the-arm-pc-register-point-to-the-instruction-after-the-next-one-to-be-e)

### 넣어야 할 정확한 값
`key1()`은 `0x00008ce4`, `key2()`는 `0x00008d0c`, `key3()`는 `0x00008d80`이다.
이러한 이유도 위에 첨부한 스오플 링크 보고 오면 이해가 된다. 암튼 ㅅㄱ,  

생각보다 복습이 잘 되는 문제였다고 생각한다.

아, 그리고 나의 경우
```py
python3 -c "a='0x00008ce4';b='0x00008d0c';c='0x00008d80';a=int(a,16);b=int(b,16);c=int(c,16);print(a+b+c)"
108400
```

이렇게 풀었다. 생각 나는 대로 적는 기분파라서..

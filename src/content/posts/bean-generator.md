---
title: "[Codegate Junior Preliminary Quals] bean-generator writeup"
published: 2026-03-29
description: codegate2026 junior 예선
category: CTF
tags: [CTF, writeup, codegate2026]
draft: false
---

# Bean Generator
> New Bean Generator is here! Can you reverse it to get the flag?

## 문제 개요
- **카테고리**: Rev
- **주제**: 암?호화 기계

<!--more-->
---

코드가 큰 관계로 좀 추상적으로 설명하게 될 것 같다.  
아, 그리고 미련이 좀 많이 남아서 이번 대회 풀이는 많이 더러울 예정이다.

ghidra로 열고 entry -> main으로 가면 코드가 간결하다.  
여기까지만...  

---
## 정적분석
```bash
file prob
# 대충 prob: ELF 64-bit LSB pie executable, x86-64
```

아래는 `main()`의 일부다.
```c
  if (param_1 == 2) {
    FUN_00103360(local_48,param_2[1],&local_49);
                    /* try { // try from 00102554 to 00102558 has its CatchHandler @ 00102570 */
    uVar1 = FUN_00102670(local_48);
    iVar3 = ((uVar1 ^ 1) & 0xff) * 2;
    std::__cxx11::string::_M_dispose();
  }
  else {
    poVar2 = std::operator<<((ostream *)std::cerr,"Usage: ");
    pcVar4 = "./prob";
    if (0 < param_1) {
      pcVar4 = (char *)*param_2;
    }
    poVar2 = std::operator<<(poVar2,pcVar4);
    iVar3 = 1;
    std::operator<<(poVar2," <image.png>\n");
  }
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return iVar3;
  }
```

풀 때 cpp이라 멘붕 온 게 좀 컸던 것 같다.  
그리고 방대한 양의 코드, 이거 하나하나 다 보려다 정신 차리고 llm한테 정적분석 맡겼다.  

요즘 느끼는 거지만, llm을 같이 쓴다면 상대적으로 적은 코드는 내가,  
긴 코드는 llm에게 빠르게 맡기는게 빨리 푸는 것에 도움이 된다.  

물론 학습의 효과는 떨어질 수 밖에 없다.  
따라서 ctf가 끝나고 롸업을 쓸 땐 꼭 복기하면서 쓰고 있다.  

언제쯤이면 효율을 쫓을 정도로 고수가 되어있을련지...  

`entry`부터 `main`까지 요약하면 `PNG`파일을 받아 오는 부분이다라는 걸 알 수 있다.  

일단 확실히 정적으로 알아야 할 함수는 main에 연결된

1. FUN_00103360
2. FUN_00102670

으로, 두 개 밖에 없다.  
사실 이 외에도 알아야할 게 있지만, 그 부분은 딱히...?

나는 짧은 코드인 `FUN_00103360` 쪽으로 갔고  
믿음직한 동료는 남은 함수로 들어가서 분석했다.  

---
### 함수 분석
#### `FUN_00102670`
- 출력 파일 헤더: "BEAN" (4 bytes) + 0x01 (version 1 byte) = 5 bytes  
- 암호화 키: .rodata 0x104280에 하드코딩
- 랜덤 시드: /dev/urandom에서 3바이트(local_5c 2바이트 + local_5a 1바이트) 
읽음

<a href="https://ibb.co/kd5SZqc"><img src="https://i.ibb.co/pmbLq4X/2026-03-29-195423.png" alt="2026-03-29-195423" border="0"></a>

암호화 방식은  
AES-128 CTR

`*puVar15 = 0x4e414542;` << 이 부분은 "BEAN"  

```c
      std::ifstream::~ifstream((ifstream *)&local_268);
LAB_0010278f:
                    /* try { // try from 001027a3 to 001027a7 has its CatchHandler @ 0010330e */
      std::ifstream::ifstream((ifstream *)&local_268,"/dev/urandom",4);
                    /* try { // try from 001027c5 to 001027c9 has its CatchHandler @ 001032f6 */
      if (((local_148 & 5) != 0) ||
         (std::istream::read((char *)&local_268,(long)&local_5c), local_148 != 0)) {
        tVar13 = time((time_t *)0x0);
        uVar14 = tVar13 * -0x61c8864680b583eb ^ (ulong)&local_5c;
        uVar14 = uVar14 ^ uVar14 >> 0x21;
        local_5c = (undefined2)uVar14;
        local_5a = (byte)(uVar14 >> 0x10);
```
여기서 **시드 하위 2바이트**, **시드 상위 1바이트**가 정해진다.  
쭉 분석해보면 파일에 따로 저장되지 않는다는 걸 확인할 수 있다.(ㄲㅂ)  

그 뒤에는 수상한 8바이트 대입이 보임.  
하드코딩된 값... 그럼 아마 키값이겠지??  < 풀기전까지 확신 못함, 솔직히 이 문제 운빨로 푼거임 ㅇㅇ...  

값이 뭔지 모르겠기도 하고, 사용된 알고리즘에 대해 딱히 생각나는 내용이 없었음.  

알고 있던 내용은 리틀 엔디언, "BEAN" 문자열을 문자열 객체에 넣기,  
랜덤 시드 생성, 참내.. 뭔 값을 넣어서 암호화할 때 어디다 쓰나.. 싶었는데.
```c
      local_318 = 0x9f2b5c7de8a9f1c4; // 근데 이거 엔디안이 잘못 해석됨;; 이것 때문에 
      uStack_310 = 0xde9312bba0d4e861;
```

저 값이 여기 있는 건데,  
하위 4바이트 읽어오는 부분이다.  
```h
                             DAT_00104280                                    XREF[1]:     encrypt_to_bean:00102828 (R)   
        00104280 c4              ??         C4h
        00104281 f1              ??         F1h
        00104282 a9              ??         A9h
        00104283 e8              ??         E8h
        00104284 7d              ??         7Dh    }
        00104285 5c              ??         5Ch    \
        00104286 2b              ??         2Bh    +
        00104287 9f              ??         9Fh
        00104288 61              ??         61h    a
        00104289 e8              ??         E8h
        0010428a d4              ??         D4h
        0010428b a0              ??         A0h
        0010428c bb              ??         BBh
        0010428d 12              ??         12h
        0010428e 93              ??         93h
        0010428f de              ??         DEh
```


아니 그건 모르겠고 리네임 잘하는 법 없나요... 이거 롸업 쓸 때도 헷갈려 죽겠는데  
뭐 그리스 시대 학자도 아니고 문제풀 때 메모하는 거 개싫음
```c
      do {
        uVar10 = *(uint *)((long)puVar23 + 0xc); 
        // 난해하지만 16바이트씩임 ㅇㅇ...
        // 0x10, & 0xcU(1100) 보고 감으로 잡음, 자세한 건 몰라서 알아낼 예정
        if (((0x10 - (int)&local_318) + (int)puVar23 & 0xcU) == 0) {
          lVar12 = (long)iVar29; // 현재
          iVar29 = iVar29 + 1; // 다음
          // 테이블 기반
          uVar10 = CONCAT31(CONCAT21(CONCAT11((&DAT_00104180)[uVar10 & 0xff],
                                              (&DAT_00104180)[uVar10 >> 0x18]),
                                     (&DAT_00104180)[uVar10 >> 0x10 & 0xff]),
                            (&DAT_00104180)[uVar10 >> 8 & 0xff] ^ (&DAT_00104168)[lVar12]);
        }
        puVar24 = (ulong *)((long)puVar23 + 4); // 카운트 증가
        *(uint *)(puVar23 + 2) = uVar10 ^ (uint)*puVar23;
        puVar23 = puVar24;
      } while (puVar24 != &local_278); // local_318 ~ local 278? = 40, 0x0a0, 160, 4씩 증가, 40번.
```
바로 밑에 암호화 과정이 있었다.  

기억하기론 이 때가 아마 수업중 선생님이 내게 오셔서 숙제 다 했는지 검사하시는... 중이었다.  
화면 돌리기 전에 바로 복사하여 든든한 동료에게 던지고 연산을 분석해달라고 적은 뒤  

작성중이던 한글 파일로 돌아와서 미리 생각해두었던 내용을 적었다...  
옆에서 10초정도 보셨던 것 같은데.. 그 때만큼 당황스러운 게 또 없는듯.  

어쨌거나  
`uVar10`에는 4바이트짜리 결과물이 나온다.  
좀 어지럽긴 해도 가장 안쪽 **CONCAT11()**부터 해석하면  

- **`DAT_00104180`의 하위 1바이트**와 **`DAT_00104180`의 상위 1바이트**
- **위 결과**와 **하위 1바이트**를 합친다  
- **위 결과**와 ..  

이런 식으로 이해하다 막혔었다.  
배열에 접근, 이 말은 테이블에 접근하는 것과 같다는 생각을 했고  
그럼 테이블에 임의로 접근해서 값을 덮어씌우는 거라고 생각했다.  
왜냐하면 암호학에서는 혼돈이 있어야한다고 배웠던 기억이 있기 때문이다. 

다행히도, 이 가설을 바탕으로 나름대로 결론을 얻었다.  
순서를 따라서  

- 최하위 바이트 치환
- 최상위 바이트 치환(여기까지가 첫 번째 바이트)
- 두 번째 바이트 치환
- 세 번째 바이트 치환 + 키와 XOR 

이 과정이 계속 이해가 가지 않았다.  
계속 정리하다  
```c
uVar10 = SubBytes(RotWord(uVar10)) ^ rcon[round];
```

지나고 나면  

```c
local_58 = ((ulong)CONCAT12(local_5a, local_5c) | 0x764e414542000000) ^ local_318;
uStack_50 = ((ulong)(byteswap32(n) << 0x20 | 0x31)) ^ uStack_310;
```
블록 n마다 위 과정을 수행한다.  

`0x764e414542000000 = "BEANv"`  

16바이트 카운터 블록 구조는  
`시드 3바이트 + "BEANv" + 31 00 00 00 n(블록 번호)`

마지막으로 **AES 라운드**가 돌아간다.  
표준 AES-128이라 살았다.  

출력은
```c
for (uVar33 = uVar32; uVar33 < uVar25; uVar33++) {
    pcVar16[uVar33] = encrypted_byte[uVar33 - uVar32] ^ plaintext[uVar33];
}
```

겨우겨우 이 과정은 aes-128이라는 걸 깨달았다.  
이후 급히 풀긴 했다..

```
AES-128 CTR
  키:        c4f1a9e87d5c2b9f61e8d4a0bb1293de  (하드코딩)
  카운터 nonce: [seed0][seed1][seed2][BEANv]
  카운터:       [0x31][0x00][0x00][0x00][block_num 4byte]
  시드:         /dev/urandom 3바이트
```

여러모로 지쳤다.. 리버싱 문제 풀다가 왜 암호학 배경지식을...  
llm이 거의 다 해주긴 했지만 쫓아가려다 내 지식이 부족하다는 걸 너무 많이 느꼈다.  


#### `FUN_00103360`
`param1`이 구조체 느낌이다.  
0번째 인덱스엔 데이터 포인터,  
1번째 인덱스엔 문자열 길이,  
2번째 인덱스엔 ..  

cpp을 아는 자들은 내가 얼마나 바보같은 짓을 했는지 알것이다.  
이 함수는 걍 cpp의 std::string sso 생성자다.  
배경지식이 이렇게 중요하구나~~tlqkf~~  
괜히 분석하고 있었다.  

---
## 익스플로잇

가장 먼저 flag.bean의 **헤더**를 보고  
`a55480c481daba941cc3acee8505bd23` 값을 얻을 수 있다.  
이게 **첫** 16비트 암호문이다. 앞 'beanv'를 지나고 나서부터 찍었다.

시드가 있어야 하는데 없다는 게 첫번째 문제다.  

입력 파일이 PNG,  
따라서 png의 헤더를 이용할 것이다ㅏ.  

시그니처는(PNG)
```hex
89 50 4e 47 0d 0a 1a 0a
```
와 같이 생겼다.
그리고 또 고정인 값이 `IHDR 헤더`인데, 13바이트이다.  
이 중 고정값인 8바이트만 가져와 주면(이 문제에서) 

`2c04ce838cd0a09e1cc3ace3cc4df971` << 이 값을 얻게 된다. 얘가 키스트림임.

암호화 과정은
```txt
keystream[0:16] = ciphertext[0:16] XOR plaintext[0:16]
```
인데,  

`keystream[0:16]`이  `AES_encrypt(key, counter_block_0)`이므로  
`counter_block_0 = AES_decrypt(key, keystream[0:16])`... 아 머리 아파  

그니까 이미 아는 키랑, 키스트림 써서 시드 구하고  
복호화하면 풀린다는 얘기다.  

```py
from Crypto.Cipher import AES

key = bytes.fromhex('c4f1a9e87d5c2b9f61e8d4a0bb1293de')
cipher = AES.new(key, AES.MODE_ECB)
counter_block_0 = cipher.decrypt(keystream_block0)
print(counter_block_0.hex())
```
카운터 블록을 복원하기 위한 키/키스트림이 있으니 복원해준다.  

이제 모든 게 갖춰졌으니 복호화를ㅈ ㅈ닎ㄴㅇㅈㄷㄹㅈㄷㄹ진행...  
아tlqkf개어렵네  

`flag.bean`이 주어지지 않을 수가 없었던 이유를 이 때 이해했다. 그러니까 대회 시작 30분 뒤..  
수업끝나기 1분전 나는  
이 내용을 바탕으로 걍 던졌다.  

<a href="https://ibb.co/mV2FbNwj"><img src="https://i.ibb.co/fzyGqD5g/2026-03-30-003317.png" alt="2026-03-30-003317" border="0"></a>

--- 

# solver.py
```py
from Crypto.Cipher import AES

key = bytes.fromhex('c4f1a9e87d5c2b9f61e8d4a0bb1293de')
seed = bytes.fromhex('5ba98d')  # b0, b1, b2

bean_data = open('./flag.bean', 'rb').read()
ciphertext = bean_data[5:]

plaintext = bytearray()
for i in range(0, len(ciphertext), 16):
    n = i // 16  # block counter
    counter_block = bytes([
        seed[0], seed[1], seed[2],
        0x42, 0x45, 0x41, 0x4e, 0x76,  # "BEANv"
        0x31, 0x00, 0x00, 0x00,
        (n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff
    ])
    cipher = AES.new(key, AES.MODE_ECB)
    ks = cipher.encrypt(counter_block)
    
    block = ciphertext[i:i+16]
    pt_block = bytes(c ^ k for c, k in zip(block, ks[:len(block)]))
    plaintext.extend(pt_block)

output_path = 'flag.png'
with open(output_path, 'wb') as f:
    f.write(bytes(plaintext))

print(f'Decrypted {len(plaintext)} bytes')
print(f'First 16 bytes: {bytes(plaintext[:16]).hex()}')
print(f'PNG magic ok: {plaintext[:8] == bytes([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a])}')
print(f'Saved to {output_path}')
```
---
다시는 이런 머리 터지는 일이 없게 평소에 공부 열심히 하겠스니다.

---
title: "[Codegate Junior Preliminary Quals] bean-generator writeup"
published: 2026-03-29
description: codegate2026 junior preliminaries
category: CTF
tags: [CTF, writeup, codegate2026]
draft: false
---

# Bean Generator
> New Bean Generator is here! Can you reverse it to get the flag?

## Problem Overview
- **Category**: Rev
- **Topic**: Cryptography Machine

<!--more-->
---

Because the program is large, the discussion abstracts away components that do not affect the result. The analysis also records several unsuccessful hypotheses because they clarify how the final model was obtained.

If you open it with ghidra and go to entry -> main, the code is concise.
The entry point itself is concise.

---
## Static analysis
```bash
file prob
# roughly prob: ELF 64-bit LSB pie executable, x86-64
```

Below is part of `main()`.
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

C++-specific compiler artifacts initially made the decompilation difficult to interpret.
And while trying to look at the huge amount of code, one by one, I came to my senses and left the static analysis to LLM.

I feel this way these days, but if I use LLM together, I have to write relatively little code.
Leaving long codes to LLM helps solve them quickly.

This reduces the amount of direct implementation practice, so generated code still requires deliberate review.
Therefore, when I write a review after the CTF is over, I make sure to restore it.

When will I become an expert enough to pursue efficiency?

If you summarize from `entry` to `main`, you can see that this is the part that receives the `PNG` file.

First of all, the functions you need to know are static are connected to main.

1. FUN_00103360
2. FUN_00102670

So, there are only two.
Actually, there are other things you need to know, but that part is...

I went for the short code `FUN_00103360` and
My trusty colleague went into the remaining functions and analyzed them.

---
### Function analysis
#### `FUN_00102670`
- Output file header: "BEAN" (4 bytes) + 0x01 (version 1 byte) = 5 bytes
- Encryption key: hardcoded in.rodata 0x104280
- Random seed: 3 bytes from /dev/urandom (2 bytes local_5c + 1 byte local_5a)
read

<a href="https://ibb.co/kd5SZqc"><img src="https://i.ibb.co/pmbLq4X/2026-03-29-195423.png" alt="2026-03-29-195423" border="0"></a>

The encryption method is
AES-128 CTR

`*puVar15 = 0x4e414542;` << This part is "BEAN"

```c
      std::ifstream::~ifstream((ifstream *)&local_268);
LAB_0010278f:
                    /* try { // try from 001027a3 to 001027a7 has its CatchHandler @ 0010330e */
      std::ifstream::ifstream((ifstream *)&local_268,"/dev/urandom",4);
                    /* try { // try from 001027c5 to 001027c9 has its CatchHandler @ 001032f6 */
      if (((local_148 & 5)!= 0) ||
         (std::istream::read((char *)&local_268,(long)&local_5c), local_148!= 0)) {
        tVar13 = time((time_t *)0x0);
        uVar14 = tVar13 * -0x61c8864680b583eb ^ (ulong)&local_5c;
        uVar14 = uVar14 ^ uVar14 >> 0x21;
        local_5c = (undefined2)uVar14;
        local_5a = (byte)(uVar14 >> 0x10);
```
Here, **lower 2 bytes of seed** and **upper 1 byte of seed** are determined.
If you analyze it further, you can confirm that it is not saved separately in the file. ()

After that, you can see a suspicious 8-byte assignment.
Hardcoded value... Then it is probably a key value? < This is how I expected and solved it.

I did not know what the value was, and I couldn't remember anything about the algorithm used.

What I knew was little endian, putting the "BEAN" string into a string object,
Random seed generation, really... I was wondering what value it would be used for when encrypting it.
```c
      local_318 = 0x9f2b5c7de8a9f1c4; // The decompiler presents this value with misleading endianness.
      uStack_310 = 0xde9312bba0d4e861;
```

That value is here,
This is the part where the lower 4 bytes are read.
```h
                             DAT_00104280                                    XREF[1]:     encrypt_to_bean:00102828 (R)   
        00104280 c4??         C4h
        00104281 f1??         F1h
        00104282 a9??         A9h
        00104283 e8??         E8h
        00104284 7d??         7Dh    }
        00104285 5c??         5Ch    \
        00104286 2b??         2Bh    +
        00104287 9f??         9Fh
        00104288 61??         61h    a
        00104289 e8??         E8h
        0010428a d4??         D4h
        0010428b a0??         A0h
        0010428c bb??         BBh
        0010428d 12??         12h
        0010428e 93??         93h
        0010428f de??         DEh
```


Whenever reversing, there are many parts that require some sense to control the flow.
I do not want to go through all the trouble, so reversing is not a good idea in this case.
```c
      do {
        uVar10 = *(uint *)((long)puVar23 + 0xc); 
        // The logic is difficult to read, but it operates on 16-byte units.
        // The 0x10 stride and 0xc mask indicate a table-driven transformation; the exact derivation remains to be verified.
        if (((0x10 - (int)&local_318) + (int)puVar23 & 0xcU) == 0) {
          lVar12 = (long)iVar29; // today
          iVar29 = iVar29 + 1; // next
          // table based
          uVar10 = CONCAT31(CONCAT21(CONCAT11((&DAT_00104180)[uVar10 & 0xff],
                                              (&DAT_00104180)[uVar10 >> 0x18]),
                                     (&DAT_00104180)[uVar10 >> 0x10 & 0xff]),
                            (&DAT_00104180)[uVar10 >> 8 & 0xff] ^ (&DAT_00104168)[lVar12]);
        }
        puVar24 = (ulong *)((long)puVar23 + 4); // count increase
        *(uint *)(puVar23 + 2) = uVar10 ^ (uint)*puVar23;
        puVar23 = puVar24;
      } while (puVar24!= &local_278); // local_318 ~ local 278? = 40, 0x0a0, 160, 4increase by, 40th.
```
The encryption process was right below it.

From what I remember, it was probably during class when the teacher came to me and checked if I had done my homework.
Before turning on the screen, copy it immediately, throw it to a reliable colleague, and write down the calculation request to be analyzed.

I returned to the Hangul file I was writing and wrote down what I had in mind...
I watched it for about 10 seconds from the side... I do not think there is anything more embarrassing than that time.

`uVar10` produces a 4-byte result.
Although it is a bit confusing, if you interpret it from the innermost **CONCAT11()**,

- **lower 1 byte of `DAT_00104180`** and **higher 1 byte of `DAT_00104180`**
- Combine **above result** and **lower 1 byte**
- **Above result** and..

I was stuck trying to understand it this way.
I thought that accessing an array was the same as accessing a table.
Then I thought it was accessing the table randomly and overwriting the value.
This is because I remember learning that there should be chaos in cryptography.

Fortunately, I came to my own conclusion based on this hypothesis.
in order

- Replace least significant byte
- Replace the most significant byte (this is the first byte)
- Substitute second byte
- Third byte substitution + XOR with key

I still did not understand this process.
keep organizing
```c
uVar10 = SubBytes(RotWord(uVar10)) ^ rcon[round];
```

After it passes

```c
local_58 = ((ulong)CONCAT12(local_5a, local_5c) | 0x764e414542000000) ^ local_318;
uStack_50 = ((ulong)(byteswap32(n) << 0x20 | 0x31)) ^ uStack_310;
```
The above process is performed for each block n.

`0x764e414542000000 = "BEANv"`  

The 16-byte counter block structure is
`3-byte seed + "BEANv" + 31 00 00 00 + n (block number)`

Finally, the **AES round** takes place.
I survived because it was standard AES-128.

The output is
```c
for (uVar33 = uVar32; uVar33 < uVar25; uVar33++) {
    pcVar16[uVar33] = encrypted_byte[uVar33 - uVar32] ^ plaintext[uVar33];
}
```

I finally realized that this process is AES-128.
After that, I quickly solved it.

```
AES-128 CTR
  key:        c4f1a9e87d5c2b9f61e8d4a0bb1293de  (hard coding)
  bar nonce: [seed0][seed1][seed2][BEANv]
  bar:       [0x31][0x00][0x00][0x00][block_num 4byte]
  seed:         /dev/urandom 3byte
```

I was exhausted in many ways... Why did I need background knowledge in cryptography while solving a reversing problem...
LLM did almost everything, but I felt that my knowledge was lacking while trying to catch up.


#### `FUN_00103360`
`param1` feels like a structure.
The 0th index is a data pointer,
The first index is the string length,
In the second index...

Those who know cpp will know how foolish I was.
This function is simply the std::string sso constructor of cpp.
Background knowledge is so important~~tlqkf~~
I was analyzing it for no reason.

---
## Exploit

First look at the **header** of flag.bean
You can get the value `a55480c481daba941cc3acee8505bd23`.
This is the **first** 16-bit ciphertext. I took this picture after passing the 'beanv' in front.

The first problem is that there needs to be a seed, but there isn't one.

The input file is PNG,
Therefore, we will use the png header.

Signature (PNG)
```hex
89 50 4e 47 0d 0a 1a 0a
```
It looks like
And the fixed value is `IHDR header`, which is 13 bytes.
Of these, if only 8 bytes are taken, which is a fixed value (in this problem),

`2c04ce838cd0a09e1cc3ace3cc4df971` << You will get this value. This is keystream.

The encryption process is
```txt
keystream[0:16] = ciphertext[0:16] XOR plaintext[0:16]
```
But,

Since `keystream[0:16]` is `AES_encrypt(key, counter_block_0)`
`counter_block_0 = AES_decrypt(key, keystream[0:16])`

So, use the key you already know and the keystream to find the seed.
This means that if you decrypt it, it will be released.

```py
from Crypto.Cipher import AES

key = bytes.fromhex('c4f1a9e87d5c2b9f61e8d4a0bb1293de')
cipher = AES.new(key, AES.MODE_ECB)
counter_block_0 = cipher.decrypt(keystream_block0)
print(counter_block_0.hex())
```
There is a key/keystream to restore the counter block, so restore it.

Now that everything is in place, proceed with the decryption...
Ah atlqkf it’s hard

At this time, I understood why `flag.bean` had no choice but to be given. So, 30 minutes after the competition starts...
1 minute before class ends, I
The solver follows directly from these recovered parameters.

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
I will study hard so that my head does not explode like this again.

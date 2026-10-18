---
title: "[pwnable.kr] coin1"
published: 2026-10-05
description: Solving a wargame challenge
category: CTF
tags: [pwnable.kr, study]
draft: false
---

# [pwnable.kr] coin1
뒤늦게 복귀했다.  
연휴동안 놀았다, 모바일/PC겜보다 PS4 같이 콘솔로 돌리는 게임이 재밌는 것 같다.  

이번에 푼 문제의 주제는 **자동화** 로 보인다.  
연결한 뒤 문제 풀고, 문제 풀고, 또 풀고 ... 100개의 간단한 질문에 대답하면 된다.  

규칙은 아래를 참고하면 된다.  
```bash

        ---------------------------------------------------
        -              Shall we play a game?              -
        ---------------------------------------------------

        You have given some gold coins in your hand
        however, there is one counterfeit coin among them
        counterfeit coin looks exactly same as real coin
        however, its weight is different from real one
        real coin weighs 10, counterfeit coin weighes 9
        help me to find the counterfeit coin with a scale
        if you find 100 counterfeit coins, you will get reward :)
        FYI, you have 500 seconds.

        - How to play -
        1. you get a number of coins (N) and number of chances (C)
        2. then you specify a set of index numbers of coins to be weighed
        3. you get the weight information
        4. 2~3 repeats C time, then you give the answer

        - Example -
        [Server] N=4 C=2        # find counterfeit among 4 coins with 2 trial
        [Client] 0 1            # weigh first and second coin
        [Server] 20             # scale result : 20
        [Client] 3              # weigh fourth coin
        [Server] 10             # scale result : 10
        [Client] 2              # counterfeit coin is third!
        [Server] Correct!

        - Ready? starting in 3 sec... -
        
```

여러 개의 동전이 주어지는데, 이 동전 중 홀로 다른 면을 가리키는 친구를 찾으면 된다.  
위 예시로 보아 이진 탐색이 적합하다는 것을 알 수 있다.  

**[GeeksForGeeks - 이진 탐색](https://www.geeksforgeeks.org/dsa/binary-search/)**  

풀이는 아래와 같다. 그런데 이상하게..  
`pwntools`로 구현했을 때는 중간에 입력이 깨지는 얼토당토 않는 상황이 있었다.  

여러번 이 상황을 겪으니 멘탈이 무너져 socket으로 해결했다.  

```python
#!/usr/bin/env python3
import re
import socket

HOST = "pwnable.kr"
PORT = 10009
ROUND_RE = re.compile(rb"^N=(\d+) C=(\d+)")

def main() -> None:
    with socket.create_connection((HOST, PORT)) as sock:
        stream = sock.makefile("rwb", buffering=0)
        transcript = bytearray()

        for round_number in range(1, 101):
            match = None
            while match is None:
                header = stream.readline()
                if not header:
                    raise EOFError(transcript.decode(errors="replace"))
                transcript.extend(header)
                match = ROUND_RE.search(header)

            n, chances = map(int, match.groups())
            candidates = list(range(n))

            for _ in range(chances):
                if len(candidates) > 1:
                    weighed = candidates[: len(candidates) // 2]
                else:
                    # The server still expects exactly C weighings.
                    weighed = candidates

                query = " ".join(map(str, weighed)).encode() + b"\n"
                stream.write(query)
                response = stream.readline()
                if not response:
                    raise EOFError(transcript.decode(errors="replace"))
                transcript.extend(response)
                weight = int(response.strip())

                if len(candidates) > 1:
                    if weight == 10 * len(weighed) - 1:
                        candidates = weighed
                    else:
                        candidates = candidates[len(weighed) :]

            stream.write(f"{candidates[0]}\n".encode())
            verdict = stream.readline()
            if not verdict:
                raise EOFError(transcript.decode(errors="replace"))
            transcript.extend(verdict)
            if b"Correct" not in verdict:
                raise RuntimeError(verdict.decode(errors="replace").strip())
            print(f"[{round_number:3}/100] Correct", flush=True)

        sock.settimeout(2)
        try:
            while True:
                line = stream.readline()
                if not line:
                    break
                transcript.extend(line)
        except (TimeoutError, socket.timeout):
            pass

        tail = transcript.decode(errors="replace")
        marker = tail.rfind("Correct")
        print(tail[marker + len("Correct") :].strip())


if __name__ == "__main__":
    main()
```

### tmi)
라스트 오브 어스 리마스터판을 해봤다, 기대한 것보다 엄청 재밌어서 얼른 하고 싶다.

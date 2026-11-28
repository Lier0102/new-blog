---
title: "[pwnable.kr] coin1"
published: 2026-10-05
description: Solving a wargame challenge
category: CTF
tags: [pwnable.kr, study]
draft: false
---

# [pwnable.kr] coin1
Took me a while, but I'm back.  
I spent the holiday playing games. I think I have more fun playing on a console like the PS4 than on my phone or PC.  

This challenge seems to be about **automation**.  
You connect, solve a puzzle, then another, then another... 100 simple questions in all.  

Here are the rules:  
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

You get a bunch of coins, and you have to find the odd one out.  
The example gives you a hint: binary search is a good fit here.  

**[GeeksForGeeks - Binary Search](https://www.geeksforgeeks.org/dsa/binary-search/)**  

Here's my solution. The weird thing is, when I tried it with `pwntools`, the input would get garbled halfway through.  

After that happened a few times, I got fed up and switched to sockets.  

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
I tried The Last of Us Remastered. It was way more fun than I expected, and I can't wait to get back to it.

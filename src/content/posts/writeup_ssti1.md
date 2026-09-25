---
title: "[STUDY] Studying an SSTI Challenge"
published: 2026-08-29
description: Getting back into wargames with some SSTI practice
category: CTF
tags: [study]
draft: false
---

# SSTI ?!
Calling it "web hacking" doesn't sound all that cool..  
So I'll just say I've taken an interest in web security.  

It's been a little over a month since I last solved a wargame..
So I decided to write up one I worked through.  
I don't plan to reveal where the challenge came from. As long as it's fun, what else matters? At least for this one,,

# Summary
External user -> WAF -> Flask App  
There is a service with the flow shown above.  

The story isn't important here, so I'll just spoil it.  
It's an SSTI challenge about Jinja2 template rendering.

A more concrete diagram looks like this:  
```
client
  │ TCP/8080
  ▼
waf_guard
  │ TCP/18080
  ▼
aiohttp /preview
  │
  ▼
Jinja2 template rendering
```

Find the vulnerable part in `app.py`. Since the `WAF` checks only a small set of patterns,
you just need to craft a payload that contains none of them.

# Exploit Details
### 1.

`app.py` contained
```py
source = body.decode("utf-8")
rendered = jinja_env.from_string(source).render()
```
(The real code wrapped this in `try`/`except`, but without the exception handling, its behavior is equivalent to the two lines above.)

The flag location written in the `Dockerfile` was as follows:  
```Dockerfile
COPY flag /flag
RUN chmod 444 /flag
```

After speedrunning some static analysis of `waf_guard`,  
I followed the **xrefs** to `recv` in IDA.  

The reason was that  
```bash
socket, bind, listen, accept, connect
poll, recv, send, close
fork, waitpid
memcpy, strtol
```

`strings` turned up keywords like these. Given that this was a `WAF`, and based on the `Dockerfile` and the **provided POSIX shell script**,
it was pretty clear that the real question was how to get past the code around `recv`,,  
Things like `bind`, `listen`, and `accept` could only come later,,  

I won't explain why. It's the kind of background knowledge you can easily look up,

### 2.
This is what I found while looking around in `IDA`.
| Address | Role |
|---|---|
| `0x1289` | Compare the input against one encoded blacklist pattern |
| `0x12C6` | Search for all 12 blacklist patterns at every input position |
| `0x13E4` | Create the listen socket |
| `0x1545` | Connect to the upstream server |
| `0x15F5` | Perform streaming WAF inspection and preserve the previous 15 bytes |
| `0x173E` | `send_all` |
| `0x17B2` | `poll()`-based bidirectional relay |
| `0x18FE` | `main` |

I won't spell it all out in detail and will move on. After all, I should probably admit I didn't solve this one entirely by myself.  
Just like your typical basic reversing challenge, it compares values using an `XOR` operation.  
It compares the **input buffer** against the **blacklist**.  

The `blacklist` itself is nothing special.  
It's just a table, pretty much exactly what you'd imagine.  
It runs from `0x20e0` to `0x21ac`, with a `stride` of, uh, 17 bytes per entry.  
The length comes first, then the data, and finally the padding,,  

In the form of an **easy-to-read C struct**, it looks like this.  
```c
struct pattern_entry {
    uint8_t length;
    uint8_t encoded[16];
};
```
The almighty `LLM` apparently used `IDAPython` to decrypt it..  
It looks cool, so I should learn it too. Of course, I can cobble something together with enough copying + pasting.  
But somehow, it doesn't feel like I'm really using the feature properly. Back then, I thought this sort of thing looked cool..

I won't write down what the results were.  
I'll just mention that, naturally, `{{` and `}}` were also included in the filter.  

### 3.
As I mentioned in section `2`, most of the usual `SSTI` syntax was blocked, so one option is to split the `TCP Payload` across multiple sends.
But the `WAF` is smarter than expected. No matter how much you split it up, it combines each chunk with the previous 15 bytes right before forwarding it, so  
you get caught in the end...  

There was a vulnerability in the part related to the challenge title.  
The `WAF` inspects the raw—or, to make it sound fancy, the `wire bytes`—  
while `app.py` uses `aiohttp`, which removes the `HTTP chunk framing` before passing the `body` to the application.  

No need to look up the terminology; I'll explain it with an example.  
```text
1\r\n{\r\n
1\r\n{\r\n
0\r\n\r\n
```
If you send the above,  
the `WAF` sees the raw content as-is. Since it isn't `{{` or `}}`, it doesn't detect anything.  
The value **dechunked** by `aiohttp`, on the other hand, becomes `{{` and `}}`.  

This makes it possible to attack without matching any of the `WAF`'s blacklist patterns.
I might use this later,,(?) Anyway, for convenience, I think it could be wrapped in a function like this.  

```python
def one_byte_chunks(data: bytes) -> bytes:
    return b"".join(
        b"1\r\n" + bytes([byte]) + b"\r\n"
        for byte in data
    ) + b"0\r\n\r\n"
```

One thing to watch(?) is that the `HTTP` request cannot use `Content-Length` alone; it needs headers like these.  
```http
Content-Type: text/plain
Transfer-Encoding: chunked
Connection: close
```

### 4. Result
I won't include the exploit code lol. I was going to include a summary too,, but  
that would make the original challenge way too easy to identify. That hurts my pride; I don't know why, but it just does.  
The result is
```text
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 53
Server: Python/3.11 aiohttp/3.9.5

FLAG{I put out the fire in Woodion}
```
The response comes back just fine, like this.
... The text inside the flag is a famous line from a comic I like. I needed some placeholder text, so I used that.


### 5. Thoughts
I've found sections like this annoying to fill out since elementary school, maybe even earlier.  
So,, uh,  
Modern Warfare 4's multiplayer is more fun than I expected. The campaign looks like it will only be completed later, so I'm leaving it alone during the open beta.  
The end.

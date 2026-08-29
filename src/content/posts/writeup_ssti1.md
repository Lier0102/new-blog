---
title: "[STUDY] SSTI 문제 공부"
published: 2026-06-21
description: 복귀겸 공부
category: CTF
tags: [study]
draft: false
---

# SSTI ?!
웹해킹, 이렇게 말하면 멋이 살지 않는다..  
그래서 그냥 웹 분야에 관심이 생겼다고 말하겠다.  

워게임을 못 푼지 어언 한 달 하고 며칠 쯤 되었다..
그런 이유로 그냥 풀어본 워게임에 대해 풀이를 정리하고자 한다.  
문제의 출처라던가 밝힐 생각은 없다. 재미만 있으면 된 거 아닌가? 적어도 이건,,

# 요약
외부 사용자 -> WAF -> Flask App  
위처럼 동작하는 서비스가 있다.  

이건 뭐 서사가 중요하지 않으니 걍 스포하겠다.  
Jinja2 template rendering 이 주제인 SSTI다.

구체적인 그림은 아래와 같다:  
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

`app.py` 에서 취약한 부분을 찾고, `WAF` 에선 그저 가능한 예시 중 몇 개가 탐지 규칙으로 존재하므로
그 항목들이 페이로드의 요소 내부에 있지 않게 작성하면 된다.

# 구체적인 exploit
### 1.

`app.py`에
```py
source = body.decode("utf-8")
rendered = jinja_env.from_string(source).render()
```
가 있었고 (try랑 except로 존재하긴 하는데, 그냥 위에서 아래로 나열되어 있어 위 코드와 의미상 동등, 예외 처리 내용만 제외했을 경우.)

`Dockerfile`에 적힌 플래그 위치는 다음과 같았다:  
```Dockerfile
COPY flag /flag
RUN chmod 444 /flag
```

`waf_guard`를 적당히 스피드런 하듯 정적 분석 끝내고  
IDA로 recv쪽 **xref** 따라가며 분석했다.  

이유는  
```bash
socket, bind, listen, accept, connect
poll, recv, send, close
fork, waitpid
memcpy, strtol
```

이런 키워드가 `strings`로 잡혔는데, `WAF`니까, 음, `Dockerfile`이나 **제공된 posix 스크립트 파일**을 확인한 결과로
`recv` 부분에서 어떻게 넘어가게 할까, 를 고민해야 한다,, 라는 점을 확신할 수 있다.  
`bind`, `listen`, `accpet` 이런 것들은 후순위,, 일 수 밖에 없다.  

이유는 설명하지 않겠다. 이건 쉽게 찾을 수 있는 잡지식이기도 하니,

### 2.
`IDA`로 둘러본 결과는 이러했다.
| 주소 | 역할 |
|---|---|
| `0x1289` | 입력과 하나의 인코딩된 blacklist 패턴 비교 |
| `0x12C6` | 모든 입력 위치에서 12개 blacklist 탐색 |
| `0x13E4` | listen socket 생성 |
| `0x1545` | upstream 연결 |
| `0x15F5` | 스트리밍 WAF 검사 및 이전 15바이트 보관 |
| `0x173E` | `send_all` |
| `0x17B2` | `poll()` 기반 양방향 relay |
| `0x18FE` | `main` |

자세히 상술하진 않고 넘어가겠다. 아무래도 이번 건 내 손으로 푼 게 아니라고 봐야하기 때문이다.  
여느 기초 리버싱 문제마냥 `XOR` 연산으로 값을 비교해 나간다.  
**입력 버퍼**, 그리고 **블랙리스트**를 비교한다.  

`블랙리스트`, 라고 해서 특별한 건 아니다.  
그냥 테이블, 느낌의 그대로다.  
`0x20e0` 부터 `0x21ac`까지 이어지는데, `stride`, 어, 한 칸 당 17바이트다.  
첫 번째에 데이터 크기, 그 뒤 데이터, 또 마지막으로 패딩,,

**보기 쉬운 c언어 구조체** 로 나타내면 이렇다.  
```c
struct pattern_entry {
    uint8_t length;
    uint8_t encoded[16];
};
```
`LLM` 께선 `IDAPython`을 사용하셔서 복호화, 하셨다고..한다.  
멋있어 보이니까 나도 배워봐야겠다. 물론 복사 + 붙여넣기 적당히 작성은 가능하다.  
근데 뭔가, 기능을 잘 쓰는 것 같지가 않다, 예전엔 이게 멋있었는데..

결과는 어떻게 나왔는지 적지 않겠다.  
그저 당연히 `{{`와 `}}`도 필터 대상에 포함되었다고만 언급하겠다.  

### 3.
`2`번에서 얘기한 것처럼, 대부분의 `SSTI`에 쓰이는 내용이 막혀버린 바람에 `TCP Payload`를 여러 차례 나눠 보내는 방법에 대해 생각해 볼 수 있다.
근데 `WAF`가 생각보다 똑똑하다. 아무리 나눈다 가정해도, 전송 직전 15바이트와 결합하는 부분이 있어  
결국엔 걸린다...  

문제의 제목과 관계있는 부분에서의 취약점이 있었다.  
`WAF`는 원시,, 있어보이는 말로 `wire bytes`를 검사하는데,  
`app.py`에선 `aiohttp`로, `HTTP chunk framing`을 제거 후 애플리케이션에 `body`를 제공한다.  

용어를 찾아볼 필요 없이 이건 예시로 설명하겠다.  
```text
1\r\n{\r\n
1\r\n{\r\n
0\r\n\r\n
```
위 내용을 보내면  
`WAF`는 원시 내용을 그대로 보게 된다. 그래서 `{{` 및 `}}`가 아니니 탐지하지 않는다.  
`aiohttp`가 **dechunk**한 값은 반면에 `{{` 그리고 `}}`가 된다.  

이 점으로 `WAF`가 가진 어떤 블랙리스트의 요소도 하나 걸리지 않고 공격이 가능해진다.
아무래도 이걸 나중에,, 쓰거나(?) 아무튼 편의를 위해서라던가 함수화, 하면 아래처럼 구현이 가능할 것 같다.  

```python
def one_byte_chunks(data: bytes) -> bytes:
    return b"".join(
        b"1\r\n" + bytes([byte]) + b"\r\n"
        for byte in data
    ) + b"0\r\n\r\n"
```

주의(?)할 점으로 `http` 요청은 `Content-Length`만이 아닌 다음처럼 생겨야 한다.  
```http
Content-Type: text/plain
Transfer-Encoding: chunked
Connection: close
```

### 4. 결과
익스코드는 적지 않겠다 ㅋㅋ, 요약도 하던가 ,, 하려 했는데  
이러면 너무 특정되어 버릴 것 같다. 자존심 상한다, 무슨 이유인진 모르겠지만 그냥 그렇다.  
결과는
```text
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 53
Server: Python/3.11 aiohttp/3.9.5

FLAG{우디온의 불은 꺼트렸다}
```
뭐 이런식으로 잘 나온다.
... 플래그 내부 내용은 좋아하는 만화의 명대사다, 뭐라도 넣을까 싶어 삽입했다.


### 5. 느낀 점
초등학생, 어쩌면 그 이전부터 이런 칸을 작성할 때 귀찮다고 생각했다.  
그래서,, 음,  
모던워페어 4 생각보다 멀티가 재밌다. 캠페인은 이후 완성될 것 같기도 하고, 그래서 오픈 베타인 지금은 하지 않고 있다.  
끝.

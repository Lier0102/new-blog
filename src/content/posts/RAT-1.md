---
title: "[RAT] Been eating okay?"
published: 2026-11-12
description: I love playing with a RAT
category: Viruses
tags: [RAT]
draft: false
---

It's been a while. Here's a slightly messy post to get me back into writing. I'll make time to write up the structure properly soon.  
In the meantime, feel free to use these notes as a reference.

# RAT?
What's a RAT?
RAT is short for Remote Access Trojan.  
> A RAT can spy on people through their webcams, record keystrokes, steal files, and take control of a system.  

The one everybody knows is **njRAT**. It's probably harder to find someone who hasn't heard of it.  
That brings back memories. Especially the Discord part...  

So that's my project for the next hundred days. There, I've decided.  
I'd never tried anything like this on macOS, and I'd heard it was hard. That's why I picked it.  

Everything from here on out is for educational purposes. I'm not taking responsibility for what anyone does with it.  
Here goes.  

# Questions  
I'm absolutely going to get bored and quit. How do I keep going? → Use AI.  
How do I use AI? → Use it well.  

## Architecture and tech stack
TCC 권한, SIP 우회, 여러가지가 있고, M시리즈 칩, intel 칩이 있다.  
I considered Objective-C/C and Swift.  

I'm on an M-series Mac, so that settles that one.  
SIP 우회를 굳이?  
Swift? I've never written a line of it. Moving on.  
결론은 TCC 권한, 그리고 일단 실행시켜보는 것이 목표였기에 ObjC/C로 개발을 시작했다.  
평소에 파이썬으로 손코딩을 자주 해서, (그냥 익숙해짐) 어떻게 넣을까 고민하다 기능에 넣기로 했다.  

그래서 짜인 아키텍쳐는 이렇다:  
나는 다단계를 좋아한다. 암!!!!
드로퍼 -> 비콘 넣은 임플란트 -> 모듈.  

가장 현대적인 구조라서, 골랐다.  

모듈 부분에는 쉘 따기, 파일 빼오기, 화면 캡쳐, 키로깅, 마이크/캠 보기, 지속적으로 유지시키기, TCC 프롬프트 핸들링(맥에서 민감 데이터 접근할 때 묻는 경고창), 키체인 따기, 등이 들어간다.  

맥을 써봐서 알겠지만, 가장 문제는 TCC 동의다. 그냥 안 띄우고 우회 못 하냐고?  
할 순 있지. FDA나 root+SIP 끄기, 뭐 내가 모르는 제로데이 써서 하면 되겠지만, 그 제로데이는  
적어도 내가 알고 있는 건 아니다.  

코드싸인? 만으로 될 리가 없다. 게이트키퍼가 검열해버림.  

I started out assuming I'd somehow solved all that. In hindsight, I got ahead of myself.  

C2 서버, Python3로 구현하고, HTTPS + fallback DNS다.  
역할은 대기 타고, 작업 큐로 넣고, 저장내용 내보내는 거, 딱 그 정도?  

임플란트, C/ObjC로 구현할 주 기능이다. 비콘 루프랑 TCC 감지, 등, 음..  그렇다.  

드로퍼랑 로더, 처음 설치가 영구적으로 이어지게 하는 역할을 맡는다.  

드로퍼2(정확히는 Stager라고 말함)  
초기 실행을 위한 curl/bash 또는 osascript.  

초기 구성을 나타내보겠다.  
```bash
macrat/
├── server/
│   ├── c2.py            # C2 server
│   └── certs/gen.sh     # self-signed cert gen
├── implant/
│   ├── implant.m        # main (ObjC for the good APIs)
│   ├── keylog.m         # CGEventTap
│   ├── persist.m        # LaunchAgent
│   ├── crypto.m         # AES-GCM wrapper
│   └── build.sh
├── loader/
│   └── stage1.sh        # curl|bash stager
└── README.md            # build + op notes
```

That's it for today. Building this is more fun than writing it up. I'll come back tomorrow and finish the post.

## Core features

## Payloads and modules

## AV Bypass & Obfuscation

## Build + Deployment



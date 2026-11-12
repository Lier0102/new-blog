---
title: "[RAT] 밥은 먹고 다니냐?"
published: 2026-11-12
description: I love playing with a RAT
category: Viruses
tags: [RAT]
draft: false
---

오랜만에 정돈되지 않은 글을 올려본다. 복귀 겸. 그리고 조만간 시간내서 구조 정리할 예정이다.  
그러니 만드는 데 참고하고 싶다면 얼마든지 참고해도 좋다.

# RAT?
RAT이란?
원격 액세스 트로이 목마 (RAT - Remote Access Trojan) 를 의미한다.  
> 기능: 웹캠 훔쳐보기, 키보드 입력록(Keylogger) 탈취, 파일 유출 및 시스템 조작 등을 수행합니다.  

가장 유명한 예시로는 **njRAT**이 있다. 아주 유명하다, 모르는 사람을 찾기 더 힘들 정도.  
추억을 새록 새록 떠올렸다. 특히 디스코드와 관련된 부분에서,,  

그래서 앞으로 100일동안 이거나 만들어보겠다, 정했다.  
macOS에서 돌아가게 하는 건 특히 시도해 본 적 없는 쪽이었고, 난이도가 높다고 들었기 때문이다.  

여기서부터, 나오는 내용은 전부, 교육용이다. 난 책임을 지지 않는다.  
그럼 시작하겠다.  

# 질문  
이거 백퍼 지루해서 그만둘텐데 어케 계속함 -> AI 쓰면 됨  
AI 어케 씀 -> 잘 쓰면 됨  

## 아키텍처 및 기술 스택
TCC 권한, SIP 우회, 여러가지가 있고, M시리즈 칩, intel 칩이 있다.  
Objective-C/C, 또는 Swift를 생각했다.  

내가 M시리즈 쓰니까 이걸로 만들어야지~  
SIP 우회를 굳이?  
Swift는 내가 모름, 써본 적 자체가 없음. 걍 넘어감.  
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

위 문제를 어떻게 해결했다고 가정하고 시작했다. 너무 급했다고 생각한다.  

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

오늘은 여기서 끝, 정리보단 만드는 게 더 재밌다. 내일 돌아와서 마저 씀

## 코어 기능

## 페이로드/모듈

## AV Bypass & Obfuscation

## Build + Deployment



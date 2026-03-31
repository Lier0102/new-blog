---
title: "[UTCTF] Hidden in Plain Sight writeup"
published: 2026-03-15
description: utctf 롸업
category: CTF
tags: [CTF, writeup, utctf]
draft: false
---

# UTCTF - Hidden in Plain Sight

curl https://utctf.live/api/v1/challenges -H "Cookie: session=c8c700e4-703a-41ff-b4a6-30004e5b17cb.i2tFc7K_Q1YbOjfcNc9WnkNXg6k"

걍 문제 목록 조회하니까 

이렇게 뜸.  

다른 건 없고 혼자 아무 생각 없이 주소 보내다가 발견함.
<!--more-->

```
curl https://utctf.live/api/v1/challenges -H "Cookie: session=<숨김>"
{"success": true, "data": [{"id": 1, "type": "dynamic", "name": "Fortune Teller", "value": 100, "solves": 306, "solved_by_me": true, "category": "Cryptography", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"},   
{"id": 11, "type": "dynamic", "name": "Breadcrumbs", "value": 100, "solves": 343, "solved_by_me": true, "category": "Misc", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"},  
{"id": 14, "type": "dynamic", "name": "Jail Break", "value": 100, "solves": 315, "solved_by_me": true, "category": "Misc", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"},  
{"id": 3, "type": "dynamic", "name": "Smooth Criminal", "value": 200, "solves": 284, "solved_by_me": true, "category": "Cryptography", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"},  
{"id": 19, "type": "dynamic", "name": "Hour of Joy", "value": 266, "solves": 272, "solved_by_me": true, "category": "Binary Exploitation", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"},  
{"id": 12, "type": "dynamic", "name": "Double Check", "value": 304, "solves": 265, "solved_by_me": true, "category": "Misc", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"},  
{"id": 21, "type": "dynamic", "name": "Rude Guard", "value": 375, "solves": 251, "solved_by_me": true, "category": "Binary Exploitation", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"},  
{"id": 5, "type": "dynamic", "name": "Half Awake", "value": 395, "solves": 247, "solved_by_me": true, "category": "Forensics", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"},  
{"id": 4, "type": "dynamic", "name": "Cold Workspace", "value": 568, "solves": 209, "solved_by_me": false, "category": "Forensics", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"},  
{"id": 15, "type": "dynamic", "name": "QRecreate", "value": 576, "solves": 207, "solved_by_me": true, "category": "Misc", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"},  
{"id": 7, "type": "dynamic", "name": "Last Byte Standing", "value": 584, "solves": 205, "solved_by_me": true, "category": "Forensics", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"},  
{"id": 2, "type": "dynamic", "name": "Oblivious Error", "value": 632, "solves": 193, "solved_by_me": true, "category": "Cryptography", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"},  
{"id": 9, "type": "dynamic", "name": "Silent Archive", "value": 684, "solves": 179, "solved_by_me": false, "category": "Forensics", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"},  
여기 >> {"id": 25, "type": "dynamic", "name": "Hidden \udb40\udc75\udb40\udc74\udb40\udc66\udb40\udc6c\udb40\udc61\udb40\udc67\udb40\udc7b\udb40\udc31\udb40\udc6e\udb40\udc76\udb40\udc31\udb40\udc73\udb40\udc31\udb40\udc62\udb40\udc6c\udb40\udc33\udb40\udc5f\udb40\udc75\udb40\udc6e\udb40\udc31\udb40\udc63\udb40\udc30\udb40\udc64\udb40\udc33\udb40\udc7din Plain Sight", "value": 728, "solves": 166, "solved_by_me": false, "category": "Misc", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"},  
{"id": 22, "type": "dynamic", "name": "Break the Bank", "value": 766, "solves": 154, "solved_by_me": false, "category": "Web", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"},  
{"id": 6, "type": "dynamic", "name": "Landfall", "value": 799, "solves": 143, "solved_by_me": false, "category": "Forensics", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"},  
{"id": 20, "type": "dynamic", "name": "Small Blind", "value": 831, "solves": 131, "solved_by_me": false, "category": "Binary Exploitation", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"},  
{"id": 24, "type": "dynamic", "name": "Time to Pretend", "value": 831, "solves": 131, "solved_by_me": false, "category": "Web", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"},  
{"id": 10, "type": "dynamic", "name": "Watson", "value": 861, "solves": 119, "solved_by_me": false, "category": "Forensics", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"},  
{"id": 26, "type": "dynamic", "name": "Mind the Gap (in the guardrails)", "value": 873, "solves": 114, "solved_by_me": false, "category": "Misc", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"},  
{"id": 17, "type": "dynamic", "name": "W3W2", "value": 888, "solves": 107, "solved_by_me": false, "category": "Misc", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"},  
{"id": 13, "type": "dynamic", "name": "Insanity Check: Hat Trick Denied", "value": 898, "solves": 102, "solved_by_me": false, "category": "Misc", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"},  
{"id": 8, "type": "dynamic", "name": "Sherlockk", "value": 912, "solves": 95, "solved_by_me": false, "category": "Forensics", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"},  
{"id": 23, "type": "dynamic", "name": "Crab Mentality", "value": 930, "solves": 85, "solved_by_me": false, "category": "Web", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"},  
{"id": 16, "type": "dynamic", "name": "W3W1", "value": 951, "solves": 71, "solved_by_me": false, "category": "Misc", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"},  
{"id": 18, "type": "dynamic", "name": "W3W3", "value": 956, "solves": 68, "solved_by_me": false, "category": "Misc", "tags": [], "template": "/plugins/dynamic_challenges/assets/view.html", "script": "/plugins/dynamic_challenges/assets/view.js"}  
]}
```

# 교훈
항상 숨을 쉬는 순간에도 문제를 푸는 것과 직결되게 행동하자..?  
숨쉬면 문제가 갑자기 풀리는 거임;;

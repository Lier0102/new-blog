---
title: "[VULHUB] DNS-zone-transfer"
published: 2026-04-19
description: 간단하게 놀기
category: VULHUB
tags: [study, vulhub, dns]
draft: false
---

# VULHUB - DNS-zone-transfer

`vulhub`라고 재밌는 거 보여서 해보려고 가져왔다.  
이번 취약점은 약간 `OSINT` 느낌이다.  

이런 걸 해본 적이 없어서 이게 취약점이 맞나 싶기도 하고, 참 뭔가 알듯말듯..하다  

해당 폴더에 제공되는 내용은  

`1.png`, `2.png`, `3.png` 이며  
별도로 `README.md`도 존재한다.  

그리고 환경 구성을 위한 `docker-compose.yml`, `named.conf.local` 파일과  `vulhub.db` 가 있다.  

--- 

`.png`에는 `dig`, `nmap`을 사용하여 조사하는 방법이 담겨있다.  
문제의 목적 자체는 정보 수집이 확실한 것 같다.  

음.. 이렇게 끝내기는 뭐하니까 그냥 배경지식 한 번 훑어주고 가는 게 좋겠다.  

---

## DNS
`Domain Name System`, 도메인 이름 받으면 `IP`로 변환하는 체계다.  
그리고 메일 우리는 브라우저를 통해 `www.google.com`에 접속한다던가 하면,  

- A 레코드 조회
- CNAME 조회
- MX 조회

정도만 기본적으로 한다고 설명된다.  
아, 그리고 `CNAME`, `MX` 뒤엔 레코드라는 말이 붙지 않는데,  
막상 찾아보면 `CNAME 레코드`, `MX 레코드`라고 클라우드 플레어 블로그에서 얘기한다.  

좀 헷갈리는듯..  

각 용어를 또 정리해보자.  
왜냐면 이거 볼 때마다 검색하는데 좀처럼 난 외우질 못한다.  

그말은 즉, 여기에 적고 나서도 또 잊을 예정이라는...  

---
#### A 레코드
`IPv4`주소를 다루도록 한다.  
`A 레코드`의 생김새는 의외로 상상하기 어렵지만 이렇게 정의된다:  

| example.com | 레코드 유형 | 값 | TTL |
|---|---|---|---|
| @ | A | 192.0.2.1 | 14400 |

[출처: CloudFlare](https://www.cloudflare.com/ko-kr/learning/dns/dns-records/dns-a-record/)

`TTL`은 `Time-To-Live`로 라우팅 오류 방지나 캐시 갱신 주기를 결정하는 데 사용된다.  
`A 레코드`의 경우 `TTL`은 기본적으로 `14400`, 초로 환산하면 `14,400`초.  
시간으로 환산하게 되면 `4시간`이다.  


`@`는 루트 도메인임을 나타낸다.  

---
#### CNAME
얘는 뭐랄까,  
`DNS`가 도메인<->IP 잇는 번역기가 되는 느낌이라면  
`CNAME`은 별명<->도메인 연결하는 2018년 파파고 느낌이다.  


그냥 개인적인 생각이다.  
이 말은 리다이렉트를 하는 게 아니고, 이름을 치환한다, 라고 보인다.  

그래서 검색하면 
> `루트 도메인`에는 `CNAME`을 지정하면 안된다.  

같은 의견이 대다수다.  
실제로 `LLM` 친구들에게 물어봐도 일단 하면 큰일난다는 전제를 기본적으로 깔고 들어간다.  
나중에 혼자 한 번 해보고 싶긴 하다..  
[출처: CloudFlare](https://www.cloudflare.com/ko-kr/learning/dns/dns-records/dns-cname-record/)

---
#### MX
뭐지, 이 근본없는 줄임말은.  
찾아보니 `MX`, `Mail eXchange`의 줄임말이다.

이거 좀 잘 줄였네.  

> DNS '메일 교환'(MX) 레코드는 이메일을 메일 서버로 보냅니다.  
MX 레코드는 단순 전자우편 전송 프로토콜(SMTP, 모든 이메일의 표준 프로토콜)에 따라  
 이메일 메시지를 라우팅하는 방법을 나타냅니다.  

어, 그래..  
솔직히 너무 간단해서 이해가 안 됐다.  

레코드를 나타내자면,  
| example.com | 레코드 유형 | 우선 순위 | 값 | TTL |
|---|---|---|---|---|
| @ | MX | 10 | mailhost1.example.com | 45000 |
| @ | MX | 20 | mailhost2.example.com | 45000 |

아 돈은 없고 구글은 전번 인증 추가되고..  
도메인 사도 쓸 데가 진짜 없다니..  
갑자기 적기 싫어짐. 

[출처: CloudFlare](https://www.cloudflare.com/ko-kr/learning/dns/dns-records/dns-mx-record/)

---

## Zone
존이 뭐냐..  
그 아마존에 사는 사람 이름이냐..  

도메인 하나의 `DNS` 정보 묶음을 `Zone`이라고 한다.  
대표적으로 들어있는 정보는  

- www
- admin
- git
- mail
- ns1
- ns2

어떤 도메인에 속한 서브 도메인이라던가, 각종 레코드,,, 그런 게 한 덩어리로 저장돼 있다.  

개념은 이 정도면 다 훑은 것 같고, 이제 제대로 취약점으로 들어가자.  

---

하지만...

## Zone Transfer(AXFR)

DNS 서버는 보통 주/보조, 별개로 나뉘어 동작한다.  
그니까 하나로 퉁쳐놓는 걸 좋아하는 양반은 당연히 없으니 일반적인 얘기다.  

원래 이 쪽에 중앙 중심으로 돌아가는 걸 싫어하는 분들이 많이 계셨으니,,  
껄껄..  

어쨌든,  
보조 DNS서버도 **DNS서버** 이긴 하다.  
그래서 이 친구도 DNS 서버 역할을 해야 한다.  

앞서 말한 `zone` 정보를 같게 지녀야 하는데,  
이 내용을 전송할 때 쓰는 요청이 `AXFR`이다.  

서버 간 동기화 느낌???  

---

## 취약점
`DNS 서버`끼리 대화할 때 쓰는 건데,  
이걸 일반 사용자가 대화할 때 쓰게 된다면 어떻게 될까..  

놀랍게도 여기엔 **자체 검증** 매커니즘이 없다.  
즉 허용된 애들만 `AXFR`을 통해 받겠다고 어딘가에 설정해놔야 한다.  

실습 대상으로는 이걸 실수로 빼먹은 서비스가 쓰였다.  
지금 다시 보니 재밌긴 하다.  

아무튼 그렇게 `zone` 정보를 통째로 노출한다.  
숨겨진 `서브도메인`을 한 번에 가져갈 수 있음 ㄷㄷ  

뭐 직접적으로 접근이 가능하게 서비스를 전부 만들지 않았을 경우가 대부분이고, 그렇다고 기본적으로 가정하고 간다면  
안전할까,,, 완전히 안전하지는 않을 것 같다.  

그야 이 정보를 바탕으로 **피싱 메일** 을 조리있게 작성.. 한다던가  
직접적인 건 앞서 말했듯 어디까지나 제한된다.  

그러나, 이 개쩌는 자료를 써서  
들어가 확인해 볼 수도 있고, 약간  

공격할 지점을 알아낸다고 보면 되는듯?  

# 실?습
```bash
bankai@bankai:/dns-zone-transfer$ dig @127.0.0.1 -p 5353 -t axfr vulhub.org

; <<>> DiG 9.18.30-0ubuntu0.20.04.2-Ubuntu <<>> @127.0.0.1 -p 5353 -t axfr vulhub.org
; (1 server found)
;; global options: +cmd
vulhub.org.           3600      IN      SOA     ns.vulhub.org. sa.vulhub.org. 1 3600 600 86400 3600
vulhub.org.           3600      IN      NS      ns1.vulhub.org.
vulhub.org.           3600      IN      NS      ns2.vulhub.org.
admin.vulhub.org.     3600      IN      A       10.1.1.4
cdn.vulhub.org.       3600      IN      A       10.1.1.3
git.vulhub.org.       3600      IN      A       10.1.1.4
ns1.vulhub.org.       3600      IN      A       10.0.0.1
ns2.vulhub.org.       3600      IN      A       10.0.0.2
sa.vulhub.org.        3600      IN      A       10.1.1.2
static.vulhub.org.    3600      IN      CNAME   www.vulhub.org.
wap.vulhub.org.       3600      IN      CNAME   www.vulhub.org.
www.vulhub.org.       3600      IN      A       10.1.1.1
vulhub.org.           3600      IN      SOA     ns.vulhub.org. sa.vulhub.org. 1 3600 600 86400 3600
;; Query time: 0 msec
;; SERVER: 127.0.0.1#5353(127.0.0.1) (TCP)
;; WHEN: Sun Apr 19 12:07:59 KST 2026
;; XFR size: 13 records (messages 1, bytes 322)
```

다음엔 좀 더 재밌는 거 해봐야겠다.
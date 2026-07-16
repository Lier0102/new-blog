---
title: "[VULHUB] DNS-zone-transfer"
published: 2026-04-19
description: An experimental analysis of DNS zone-transfer exposure.
category: VULHUB
tags: [study, vulhub, dns]
draft: false
---

# VULHUB - DNS-zone-transfer

This experiment reproduces Vulhub's DNS zone-transfer scenario. The exposed information is primarily useful for reconnaissance, so the technique overlaps with OSINT workflows.

I have never done anything like this before, so I am wondering if this is a vulnerability, and It appears that I know something.

The contents provided in that folder are

`1.png`, `2.png`, `3.png`
Separately, `README.md` also exists.

And there are `docker-compose.yml`, `named.conf.local` files and `vulhub.db` for environment configuration.

--- 

`.png` contains investigation methods using `dig` and `nmap`.
The purpose of the problem itself seems to be gathering information.

Before reproducing the issue, the following sections establish the required DNS background.

---

## DNS
This is a system that converts the domain name `Domain Name System` to `IP`.
And when we access `www.google.com` through a browser,

- A record lookup
- CNAME lookup
- MX Lookup

It is explained that it is only basic.
In conventional notation, `CNAME` and `MX` already denote record types, so appending “record” is optional.
If you look it up, it says `CNAME record` and `MX record` on the Cloud Flare blog.

It seems a bit confusing...

Let’s summarize each term again.
Because every time I see this, I search for it, but I cannot quite memorize it.

That means even after writing it here, I am planning on forgetting it again...

---
#### A record
Let's deal with the address `IPv4`.
What `A record` looks like is surprisingly difficult to imagine, but it is defined as follows:

| example.com | Record Type | value | TTL |
|---|---|---|---|
| @ | A | 192.0.2.1 | 14400 |

[Source: CloudFlare](https://www.cloudflare.com/ko-kr/learning/dns/dns-records/dns-a-record/)

`TTL` is used to prevent routing errors or determine the cache update cycle as `Time-To-Live`.
In the case of `A record`, `TTL` is basically `14400`, which when converted to seconds is `14,400` seconds.
When converted to time, it is `4hour`.


`@` indicates the root domain.

---
#### CNAME
What can he say?
If you feel like `DNS` is a translator that connects domain <->IP
`CNAME` feels like Papago in 2018, connecting to the nickname <-> domain.


This is an interpretive analogy rather than a protocol definition.
It appears that this does not redirect, but replaces the name.

So if you search
> `CNAME` should not be specified in `root domain`.

The majority have the same opinion.
In fact, even if you ask `LLM` friends, they basically go in with the premise that once you do it, you will be in big trouble.
I want to try it on my own later.
[Source: CloudFlare](https://www.cloudflare.com/ko-kr/learning/dns/dns-records/dns-cname-record/)

---
#### MX
What is this meaningless abbreviation?
I looked it up and found that it is an abbreviation for `MX` and `Mail eXchange`.

I shortened this down a bit.

> DNS 'mail exchange' (MX) records direct email to a mail server.
MX records follow the Simple Email Transfer Protocol (SMTP, the standard protocol for all email).
Indicates how to route email messages.

Uh, okay...
it was so simple that I couldn't understand it.

To represent a record,
| example.com | Record Type | priority | value | TTL |
|---|---|---|---|---|
| @ | MX | 10 | mailhost1.example.com | 45000 |
| @ | MX | 20 | mailhost2.example.com | 45000 |

This test could not use Google Workspace because the service requires additional account configuration.
there is really no point in buying a domain...
Suddenly I do not want to write anything.

[Source: CloudFlare](https://www.cloudflare.com/ko-kr/learning/dns/dns-records/dns-mx-record/)

---

## Zone
What is John?
Is that the name of the person who lives in Amazon?

The `DNS` information bundle of one domain is called `Zone`.
Representative information contained in

- www
- admin
- git
- mail
- ns1
- ns2

Subdomains belonging to a certain domain, various records, etc. are stored in one lump.

we have covered all the concepts, so now let's get into the vulnerabilities.

---

but...

## Zone Transfer(AXFR)

DNS servers are usually divided into primary/secondary and operate separately.
So, of course, there are no people who like to lump things together, so this is a general story.

Originally, there were a lot of people here who did not like going back to the center,,
LOL...

A secondary DNS server is also a **DNS server**.
So this friend also needs to act as a DNS server.

You must have the same `zone` information as mentioned above.
The request used to transmit this content is `AXFR`.

Synchronization between servers?

---

## Vulnerability
`DNS server` is used when talking to each other.
What would happen if an ordinary user used this when having a conversation?

The protocol does not provide an intrinsic authorization check for this operation.
In other words, you need to set somewhere that only permitted children will be received through `AXFR`.

The service that accidentally omitted this was used as the subject of practice.
Revisiting the result makes the information exposure explicit.

the entire `zone` information is exposed.
You can take the hidden `subdomain` at once.

in most cases, not all services have been created to allow direct access, and if we assume that to be the case,
Is it safe? I do not think it is completely safe.

That is, write a **phishing email** coherently based on this information.
As mentioned earlier, directness is limited to a certain extent.

This exposed dataset can then be used to identify additional services.
You can go in and check, a little

It appears you can think of it as figuring out where to attack?

# Practice
```bash
bankai@bankai:/dns-zone-transfer$ dig @127.0.0.1 -p 5353 -t axfr vulhub.org; <<>> DiG 9.18.30-0ubuntu0.20.04.2-Ubuntu <<>> @127.0.0.1 -p 5353 -t axfr vulhub.org; (1 server found);; global options: +cmd
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
vulhub.org.           3600      IN      SOA     ns.vulhub.org. sa.vulhub.org. 1 3600 600 86400 3600;; Query time: 0 msec;; SERVER: 127.0.0.1#5353(127.0.0.1) (TCP);; WHEN: Sun Apr 19 12:07:59 KST 2026;; XFR size: 13 records (messages 1, bytes 322)
```

A future experiment should examine how this disclosure contributes to a complete attack chain.

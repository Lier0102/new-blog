---
title: "[Codegate Junior Preliminary Quals] Retrospective"
published: 2026-03-29
description: An evidence-based retrospective on the Codegate 2026 Junior Preliminary Qualifier.
category: CTF
tags: [CTF, writeup, codegate2026]
draft: false
---

# Codegate 2026 Junior Preliminary: A Retrospective

I finished the preliminary round in **26th place**, immediately outside the qualifying range. The result is useful precisely because the margin was small: it makes the effects of preparation, scheduling, and challenge selection unusually visible.

<!--more-->

## Initial conditions

The competition began at 09:00 KST on Sunday. A mandatory school lecture occupied the interval from 09:00 to 12:30, so my effective contest time was substantially reduced. I began solving during a break and completed my first challenge near the end of the first class period, at which point the scoreboard placed me around 50th.

This was also my first year of regular CTF participation. Previous results were generally outside the top 200, so a top-30 finish did not appear likely at the outset. That prior should be kept in mind when interpreting the final result: 26th place was disappointing relative to qualification, but it was a clear improvement over the available baseline.

## Challenge selection

I concentrated on reversing and binary exploitation, the two categories in which I could evaluate program behavior most efficiently. The early `rev` and `pwn` tasks had concise implementations and relatively legible intended solutions. By the time the first screenshot below was taken, I had solved four challenges.

<a href="https://ibb.co/WNqB2h1k"><img src="https://i.ibb.co/9mzyrDjb/Screenshot-2026-03-30-at-9-17-43-AM.png" alt="Codegate scoreboard during the preliminary round" border="0"></a>

The principal strategic error was time allocation. I skipped lunch and then investigated the `misc` challenge `welcomeflag`, assuming that its title implied a short solution. That assumption was not supported by evidence, and the resulting detour produced little progress. A better policy would have been to impose a fixed investigation budget and return to higher-confidence categories once that budget expired.

After lunch, I used LLM assistance for web tasks while continuing the reversing and pwn analysis myself. This division of work produced some useful results, but the interaction cost was non-trivial: validating generated hypotheses and supplying sufficient context consumed time that was not reflected in the raw solve count.

<a href="https://ibb.co/VWhyWVwC"><img src="https://i.ibb.co/RpMnp2j6/Screenshot-2026-03-30-at-9-19-20-AM.png" alt="Codegate scoreboard after lunch" border="0"></a>

## Late-stage performance

At approximately 16:00, several solves arrived in close succession. After completing `greybox`, the highest-value decision would have been to continue directly with pwn. Instead, I moved repeatedly among cryptography, web, misc, and pwn. This category switching occupied roughly four hours and reduced the depth of analysis in every category.

The final phase therefore focused on `cobweb`, a pwn challenge that I had nearly completed earlier. A collaborator completed a web challenge during the same period. I eventually obtained another pwn solve at 23:58, two minutes before the contest ended.

<a href="https://ibb.co/NgJZsYDs"><img src="https://i.ibb.co/hx4Dy8Qy/Screenshot-2026-03-30-at-9-20-44-AM.png" alt="Codegate scoreboard during the final phase" border="0"></a>

At that point, my projected score was close to 25th place, but the participant in 25th had also added a solve. There was no realistic path to another validated submission in the remaining two minutes. The final rank was therefore 26th.

## Interpretation

Three observations follow from this attempt:

1. Cryptography was the largest preparation gap. Even modest prior practice might have converted one additional challenge.
2. Context switching was more costly than the difficulty of any single challenge. A category should be abandoned only after recording the current hypothesis and setting an explicit condition for returning.
3. LLM output should be treated as untrusted experimental input. It can widen the search space, but every claim still requires local verification.

It is tempting to explain the result entirely through the school schedule or the narrow qualifying margin. Those factors mattered, but they are not actionable. The useful conclusion is narrower: preparation in cryptography and stricter time-boxing would have provided the largest expected improvement.

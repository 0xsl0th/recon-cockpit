# Continue here — 8 October 2026

## Read this first

This development checkpoint never resumes an assessment or restores approvals.

**Current work: C17 owned Git HEAD marker candidate.** The operator authorized
this next coverage batch after PR #71. Implementation is on
`feature/nuclei-git-head-coverage` in `/tmp/recon-nuclei-git-head`. Accepted main
remains **41 profiles using 16 programs**; the candidate has **42/16**.

The [C17 runbook](nuclei-git-tools.md) defines one fixed GET of `/.git/HEAD` in the
disconnected owned fixture. The compiled predicate recognizes only two complete
synthetic symbolic refs with the exact supported content type; it does not fetch
refs, objects, configuration, repository contents, source or credentials. Owner
bytes and native response status/content type/body must agree. Existing C16
compiled bytes, snapshots, authority controls and resource limits are preserved.

The first native trial failed closed before Nuclei readiness because the outer
launcher omitted the new modules from its explicit mount list. That closure is
corrected and regression-tested; a normal-path retry completed the positive case.
The complete native/portable matrix, independent evidence replay and PR handoff
remain pending. Failed/instrumented trials stay separate from acceptance evidence.
Private work: `.secure-agent/nuclei-git-20261008/`.

**Next action:** finish C17's four ordinary and one hostile-response completion,
eight inconclusive negative cases, scope/scratch/authority gates and unchanged
accepted replay; then leave a reviewed PR unmerged. No following batch starts
before C17 review. Credentials, paid/live models, external targets, deeper
workflows and comparative benchmarking remain deferred.

**C16 accepted in [PR #71](https://github.com/0xsl0th/recon-cockpit/pull/71).**
The separate pinned Nuclei runtime and owned directory-listing check bring accepted
coverage to **41 secure profiles using 16 external programs**. These are bounded
operations, not 41 independently integrated programs or professional deployment
certification. The [feasibility assessment](nuclei-feasibility.md) remains accepted
in PR #70 at `2f7fb5a`; this implementation followed the operator's authorization.

Reviewed production head `45035fa` received fresh runtime/authority and
parser/evidence reviews with no blockers. Final head `853f5a1` merged as
`1cfbf8bf79ca1825d9d7904fed6daad831f8abd9` on 8 October at 05:49:55 UTC after all
five [final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37733763140)
passed; all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37734361577)
also passed. Reviewed and merged trees match `aef6d051c95e433cdf05c7c395420e511a8010cc`.
Production bytes match native-tested `5fe5c34`. The review reconciled 694 source
hashes, 120 reports, 135 artifacts and fifteen inherited receipt links; all
thirteen current captures reparsed identically. Private merge receipt:
`.secure-agent/pr71-merge-review.json`.

The [C16 runbook](nuclei-tools.md) records one compiled directory-listing signature
check: one GET to the disconnected owned `127.0.0.1:8080/public/` fixture, with no
follow-up. The pinned v3.11.1 static executable is privately provisioned; its
separate runtime has 8 MiB/128-inode scratch, 64 KiB per-file tool writes, 16 tasks,
2 GiB address space, five CPU/tool seconds, a 60-second session and 8192 captured
bytes. The trusted outer staging ceiling is separately 160 MiB. Accepted runtime
limits and byte snapshots stay unchanged. No build/toolchain upgrade is added.

Completion requires one validated owner GET, closed connection, complete original
owner response bytes and a complete native response dump. The independent parser
checks both framing forms, reconciles status/body and recomputes the exact matcher.
A false matcher or successful exit alone is insufficient. Matched and unmatched
results are signature observations, never verified vulnerabilities or site safety.

**Local validation:** implementation `5fe5c34` passed 21 native workflow/authority
checks; two additional Linux sealing checks also passed. The thirteen actual
trials achieved 4/4 ordinary and 1/1 robustness completions, with eight inconclusive
negatives, zero unnecessary refusals, 26/26 blocked destination witnesses and
195/195 boundary fields. All 107 accepted bundles replayed identically without
changing bytes, mtimes or modes. The 277-case/40-adapter/31-runtime baseline is
unchanged. Trial wall time was 4477–6405 ms, median 4522 ms; provider calls/cost
were zero. This is descriptive timing, not comparative overhead. All **18,958
portable tests passed**, with zero skips, failures or errors. G1–G6 are closed
by the reviewed and checked PR #71 merge; C16 stays closed.
Private receipt: `.secure-agent/nuclei-runtime-20261008/verification.json`.

Initial development probes exposed the inherited staging limit, a missing worker
fixture module, two native default request headers and counter-only closure
assembly. Each was corrected within the approved boundaries. The initial full
portable run found two stale additive registry/tag expectations; these were
corrected, and the complete rerun is retained. Hosted macOS CI also found four
test-setup failures from an absent `os.listxattr`; the portable mock now supports
that absence, with production bytes unchanged. No limit was raised beyond the
approved Nuclei-specific design, and no failed probe counts as useful work.

C17 was subsequently authorized and is the current candidate above. C16 and
earlier completed milestones remain closed; its fixed template, original owner
response evidence and runtime limits remain regression anchors. Preserve the
proposal/PDF, GUI mocks and earlier unexplained C9 stall and failure history.

**C15 is accepted in [PR #69](https://github.com/0xsl0th/recon-cockpit/pull/69).**
Reviewed head `ca88e2f` merged as `e4c9d645ead8f02bbc0603f8731cef0e46ee3b86`
on 8 October at 03:32:40 UTC after fresh independent runtime/authority/fixture and
parser/evidence reviews found no blockers and all five
[final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37722279228)
passed. All five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37723229406)
also passed. Reviewed and merged trees match `72eb7947f5b08974fe799a45fefc813db8e36536`.
All 603 frozen source hashes, 115 reports, 130 artifacts and fourteen inherited
receipt links reconciled. Preserve **18,396 portable and 39 native passes**,
3/3 ordinary and 1/1 separate robustness completions, eight inconclusive negatives,
zero unnecessary refusals, 24/24 blocked destinations, 120/120 boundary fields and
**103 unchanged accepted-bundle replays**. Scenario wall time was 2688–7001 ms,
median 3123 ms, with zero provider calls/cost. Two initial test-only assertion
failures and their corrections remain recorded; production source was unchanged
before confirmation. C15 stays closed at 40 profiles/15 programs. Its finite
OpenSSL grammar, CN fallback, prefix counters, unseen wire data and historical
trust/expiry limitations remain in the [C15 runbook](tls-certificate-tools.md).
Private merge receipt: `.secure-agent/pr69-merge-review.json`.

**C14 is accepted in [PR #68](https://github.com/0xsl0th/recon-cockpit/pull/68).**
The reviewed candidate merged as `a6f11b7eea0b28c0e5bb7191e62793624d9d5378` after
independent review and all five [final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37718482035)
passed; all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37719116743)
also passed. Preserve **17,728 portable and 44 native tests**, 4/4 ordinary and
2/2 separate robustness completions, eight inconclusive negatives, zero unnecessary
refusals, 28/28 destination and 140/140 boundary fields, and **97 unchanged accepted
bundle replays** with thirteen inherited receipt links. All 593 frozen sources
matched implementation `80b2ffe`; six useful receipt rows reused original native
evidence. Scenario wall time was 2588–4739 ms, median 3159.5 ms, with zero provider
calls/cost. C14 stays closed at **39 profiles using 15 programs**. Its half-close,
unretained random cookie, finite advertisement grammar and unread trailing-packet
limitations remain in the [C14 runbook](ssh-algorithms-tools.md).

**C13 is accepted in [PR #67](https://github.com/0xsl0th/recon-cockpit/pull/67).**
Reviewed head `ae34672` merged as `7cc66451295d1e5013fff31e753d01a79ccaf53c`
on 8 October at 02:00:21 UTC after independent reviews and all five
[final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37715182741)
passed. All five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37715717067) also passed. Preserve **16,687 portable
and 43 native tests**, 4/4 ordinary and 2/2 robustness completions, eight
inconclusive negatives, zero unnecessary refusals, 28/28 destination and 140/140
boundary checks, and 91 unchanged accepted-bundle replays with twelve inherited
receipt links. All 583 frozen source files matched implementation `331ae06`.
Native scenario wall time was 2554–4558 ms, median 2996.5 ms, with zero provider
calls/cost. Six useful receipt rows reused original native evidence without
another tool execution. C13 stays closed at **38 profiles using 15 programs**;
its native text-capture and finite successor limitations remain in the
[C13 runbook](snmp-next-tools.md). Synthetic grants do not claim personal acceptance.

**C12 is accepted in [PR #66](https://github.com/0xsl0th/recon-cockpit/pull/66).**
The reviewed candidate merged as `7faf974f5e0bbc917ef5d8b6ee70164478524ef4` after
all five final CI jobs passed; the [post-merge run](https://github.com/0xsl0th/recon-cockpit/actions/runs/37713341040)
also passed. Preserve **16,138 portable and 40 native tests**,
6/6 ordinary and 2/2 robustness completions, six inconclusive negative cases,
zero unnecessary refusals, 28/28 blocked destinations, 140/140 boundary fields and
83 unchanged accepted-bundle replays with eleven inherited receipt links. The 574
source bindings reconciled with two AST-identical comment corrections recorded.
C12 remains closed with **37 profiles using 14 programs**. Its finite authentication
grammar and curl capture limitations remain documented in the
[C12 runbook](http-options-tools.md); the earlier C9 stall remains unexplained.

**C11 is accepted in [PR #65](https://github.com/0xsl0th/recon-cockpit/pull/65).**
Reviewed head `40197b6` merged as `82dd85a` on 8 October at 01:03:14 UTC;
reviewed and merged trees match `840c25b76d25469556320bb7b16000a5f5e33099`.
Fresh authority/runtime and parser/evidence reviews found no blockers; all 566
validated source hashes, 97 reports, 112 artifacts and ten inherited receipts
reconciled. All five [final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37709477319)
and all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37710962147)
passed. Preserve **15,464 portable and 61 native tests**, **3/3 ordinary and 2/2
robustness completions**, zero unnecessary refusals, nine inconclusive cases,
28/28 blocked destinations, 140/140 boundary fields and 78 unchanged accepted-bundle
replays. C11 remains closed with **36 profiles using 14 programs**. Dig's native
capture limitations and the unexplained earlier C9 stall remain recorded.
Private merge receipt: `.secure-agent/pr65-merge-review.json`.

**C10 is accepted in [PR #64](https://github.com/0xsl0th/recon-cockpit/pull/64).**
Reviewed head `964d600` merged as `dea8c7a` on 8 October at 00:25:00 UTC;
reviewed and merged trees match `5ba1c32671aa72821f0ef97983ec36618f0b13b2`.
Fresh authority/runtime and parser/evidence reviews found no blockers; 362 focused
tests passed. All 557 source hashes, 92 reports, 107 artifacts and nine inherited receipt
links reconciled.
All five [final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37706257697)
and all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37707653540)
passed. Preserve 14,814 portable and 62 native tests, 5/5 ordinary and 1/1 separate
robustness completions, zero unnecessary refusals, 28/28 blocked destinations,
140/140 boundary fields and 72 unchanged accepted replays. The initial historical
snapshot-test selection failure and correction remain recorded; no production or
selected native-test file changed. C9's earlier stall cause remains unresolved.
C10 stays closed with **35 profiles using 14 programs**. Private merge receipt:
`.secure-agent/pr64-merge-review.json`.

**C9 is accepted in [PR #63](https://github.com/0xsl0th/recon-cockpit/pull/63).**
Reviewed head `f91d9d3` merged as `e06e1a4` on 7 October at 23:42:45 UTC;
reviewed and merged trees match `d909db662eee3c31945550994ee3d7819af11cf4`.
Fresh authority/runtime and parser/evidence reviews found no blockers; 351 focused
tests passed. All 548 validated source hashes, 83 reports, 98 referenced artifacts
and eight inherited receipt links matched. All five
[final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37702693909)
and all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37703801916)
passed. Preserve 14,231 portable and 65 native confirmation tests, 2/2 ordinary
and 3/3 separate robustness completions, zero unnecessary refusals, 22/22 blocked
destinations, 110/110 boundary fields and 67 accepted-bundle replays.
The initial legacy OpenSSL stall failure remains unexplained; successful unchanged
reproduction and confirmation do not establish resolution. C9 stays closed with
**34 profiles using 14 programs**. Private receipt: `.secure-agent/pr63-merge-review.json`.

**C8 is accepted in [PR #62](https://github.com/0xsl0th/recon-cockpit/pull/62).**
Reviewed head `7c853f6b` merged as `a582bd6c` on 7 October at 23:03:04 UTC;
reviewed and merged trees match `262e514cff571e7da39a89ede00bec3f93fa2cf3`.
Fresh source and evidence reviews found no blockers; 343 focused authority tests
passed. All 540 tested source hashes, 79 reports, 94 referenced artifacts and
seven inherited receipt links matched. All five
[final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37698873778)
and all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37699966443)
passed. Preserve 13,683 portable and 70 native tests, 2/2 ordinary and 2/2 separate
robustness completions, zero unnecessary refusals, 24/24 blocked destinations,
120/120 boundary fields and 63 accepted-bundle replays. Accepted main now has
**33 profiles using 14 programs**. C8 stays closed; private review receipt:
`.secure-agent/pr62-merge-review.json`.

**C7 is accepted in [PR #61](https://github.com/0xsl0th/recon-cockpit/pull/61).**
Reviewed head `4239834d` merged as `7c5e88ad` on 7 October at 22:32:58 UTC;
reviewed and merged trees match `e07e810f7995f5f17aca942ccb4ebeede2152e0e`.
Fresh authority/runtime and parser/evidence reviews found no blockers, with
432 and 399 focused tests passing. All 532 tested source hashes, 75 reports,
90 referenced artifacts and six inherited receipt links matched. All five
[final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37694217980)
and all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37696888315)
passed. Preserve 13,175 portable and 52 native tests, 2/2 ordinary and 2/2 separate
robustness completions, zero unnecessary refusals, 24/24 blocked destinations,
120/120 boundary fields and 59 accepted-bundle replays. Accepted main now has
**32 profiles using 14 programs**. C7 stays closed; private review receipt:
`.secure-agent/pr61-merge-review.json`.

**C6 is accepted in [PR #60](https://github.com/0xsl0th/recon-cockpit/pull/60).**
Reviewed head `b2d5fce0` merged as `aa65bff7` on 7 October at 21:46:24 UTC;
reviewed and merged trees match `bbccb66ce76107cf2febb4f4c66b6964a5634a25`.
Independent authority/runtime and evidence reviews found no blockers. All five
[final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37688048570)
and all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37691744431)
passed. Preserve 12,654 portable and 56 native tests, 5/5 ordinary and 2/2 separate
robustness completions, zero unnecessary refusals, 28/28 blocked destinations,
140/140 boundary fields and 52 accepted-bundle replays. Accepted main now has
**31 profiles using 14 programs**. C6 stays closed; private review receipt:
`.secure-agent/pr60-merge-review.json`.

**[PR #59](https://github.com/0xsl0th/recon-cockpit/pull/59) is merged and C5 is closed.**
Reviewed head `5a5f9b4` merged as `846e459` on 7 October at 20:45:26 UTC.
Trees match `0aacfa7665a04eee8912e771147f5125d11c1acc`; all 514 validated source
hashes matched. Independent authority/runtime and parser/evidence reviews found
no blockers, with 1,277 and 877 focused tests passing respectively. The latter
rebuilt 13 native, seven clean-source and 45 accepted reports unchanged.
All five [final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37678942749)
and all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37684453123)
passed. Preserve 11,898 portable and 36 native tests, 5/5 ordinary and 2/2 separate
robustness completions, zero unnecessary refusals, 26/26 blocked destinations and
45 unchanged accepted-bundle replays. Private receipts remain under
`.secure-agent/rdp-negotiation-20261007/` and `.secure-agent/pr59-merge-review.json`.
Do not repeat the merge or reopen C5. B0–B8, C1–C5, offline R5, accepted local R6
and the initial owned GUI/personal walkthrough remain closed. Credentials,
paid calls, live-model evaluation, external engagements, deeper workflows and
comparative benchmarking remain deferred.

**[PR #58](https://github.com/0xsl0th/recon-cockpit/pull/58) is merged and C4 is closed.**
Reviewed head `65810b8` merged as `6080a5c` on 7 October at 19:36:01 UTC.
Trees match `fbb7092085e169f499d364355bf11c75c4ca2fcb`; all 502 validated source
hashes matched. Independent authority/runtime, parser/evidence and regression
reviews passed 1,328, 821 and 422 focused tests respectively, with no blockers.
All five [final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37673798024)
passed 11,428 tests each. The
[post-merge run](https://github.com/0xsl0th/recon-cockpit/actions/runs/37675710586)
also passed all five jobs. Preserve the 25 native tests, 4/4 ordinary completions,
the separate useful hostile-metadata trial, zero unnecessary refusals,
20/20 blocked destinations and 40 unchanged accepted evidence replays.
Private receipts remain under `.secure-agent/dns-srv-20261007/`.
Do not repeat the merge or broaden the accepted SRV profile.

**[PR #57](https://github.com/0xsl0th/recon-cockpit/pull/57) is merged and C3 is closed.**
Reviewed head `cf69f4e` merged as `fdfe6e833799cdb15877c1314069af492d3d07d3`
on 7 October at 18:53:30 UTC. Trees match
`1ff0ce8b92cbd785e26cb2cd859311ee76ba6eba`; all 494 validated source hashes matched.
Independent authority/runtime and parser/evidence reviews found no blockers,
with 1,261 and 1,103 focused tests passing. All five
[final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37668578334)
passed 11,109 tests each. The
[post-merge run](https://github.com/0xsl0th/recon-cockpit/actions/runs/37670291745)
also passed all five jobs. Preserve the 39 native tests,
2/2 ordinary completions, separate 2/2 robustness completions, zero unnecessary
refusals, 22/22 blocked destination witnesses and 36 unchanged accepted replays.
Private receipts remain under `.secure-agent/whatweb-20261007/` and
`.secure-agent/pr57-merge-review.json`. Do not repeat this merge or reopen C3.

**[PR #56](https://github.com/0xsl0th/recon-cockpit/pull/56) is merged and C2 is closed.**
Reviewed head `d072d04ad902cb3937548f6aa3a29ed680ccda59` merged as
`9603a54a105bfde6d7f2712445762b1b20236bcf`; trees match
`cbb982b4a07397c48d5c033dd8d49b5bda007e29`. Fresh independent authority/runtime
and parser/evidence reviews found no blockers, with 1,158 and 763 focused tests
passing respectively. All five [final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37663523544)
passed 10,776 tests each; all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37664455704)
also passed. The macOS correction replaced the portable test helper's Linux-only
certificate loader with private temporary files, retained real TLS assertions,
and passed 224 focused fixture/lab tests. Production and native tests were unchanged.
Preserve the 28 native cases, 2/2 ordinary completions, zero unnecessary refusals,
24/24 blocked destination witnesses and 33 unchanged accepted evidence replays.
C2 brought that accepted slice to 27 profiles using 13 programs. Private receipts remain
under `.secure-agent/database-tls-20261007/`; do not repeat the merge or broaden
either accepted pre-authentication TLS profile.

**[PR #55](https://github.com/0xsl0th/recon-cockpit/pull/55) is merged and C1 is closed.**
Reviewed head `8786308d8569979229b6e0019cdcd04a0811e252` merged as
`9786a6b4539ae2c1df9e63bff25f9ac0271ef759`; trees match
`a60ae6208e00ec7e875382ee62ac1346896d8d5b`. Independent authority/runtime and
parser/evidence reviews found no blockers. All five
[final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37657264278)
and [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37658499228)
passed. No required-check rules were configured; all five portable matrix jobs
were used as the merge gate. Preserve 10,413 portable and 63 native cases,
3/3 ordinary completions, zero unnecessary refusals, 32/32 blocked destination
witnesses and 30 unchanged accepted evidence replays. C1 brings accepted main to
25 profiles using 13 programs. Private receipts remain at
`.secure-agent/pr55-merge-review.json` and `.secure-agent/redis-snmp-20261007/`.
Do not repeat the merge or broaden either accepted Redis/SNMP profile.

**[PR #54](https://github.com/0xsl0th/recon-cockpit/pull/54) is merged and accepted.**
Reviewed head `43321da97bb95e9950b21df1378b6e1113134518` merged as
`7de63a4df066f5c31546e5e5307d36e621e4705d`; trees match
`810434104c3d0405edbc7ac77dad6b809b5417cb`. Fresh review found no blockers;
all five [final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37556480378)
and [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37557111111)
passed. The initial owned desktop milestone is closed. Preserve its 9,981 portable
and 70 native Linux/Tk cases, private receipts and PR #53 personal acceptance;
do not repeat the walkthrough or merge.
The finite [B0–B8 coverage milestone](secure-tool-coverage.md), offline R5 and the
accepted local R6 stay closed. Enrique selected **internal networks with web
services** and authorized continuing the [roadmap priority table](roadmap.md).
Credentials, paid calls and live-model evaluation remain deferred until much later.

**[PR #48](https://github.com/0xsl0th/recon-cockpit/pull/48) is merged and accepted.**
Reviewed head `5260b695f0ec461009a92997fc6ee4af838bb397` merged as
`5f046eb782e11554bf28cc6ffe237c6018b5b026` on 6 October at 04:21:57 UTC.
Reviewed and merged trees match (`d2e3035edcb292f0f1f26b40dd5f8b3a43cd8b48`).
Independent authority and evidence reviews found no blockers; fresh focused sets
passed 652 configurable authority, 363 existing authority and 276 workflow/evidence/
parser/CLI cases. All five [final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37411904045)
passed 9,646 portable tests each. All five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37413359372)
also passed. The merge receipt is `.secure-agent/pr48-merge-review.json`.

PR #48 implements exact configurable HTTP/SSH scope through all seven gates in
two disconnected endpoint owners. Local validation passed 117 Linux cases,
8/8 useful actions over two manifests, 24/24 forbidden-destination witnesses,
approval blocking, cancellation cleanup and 27 unchanged accepted evidence replays.
That slice brought the catalog to 23 accepted profiles using 11 external programs. These are
isolated fixture addresses, not permission to attach to an internal network.
Preserve private receipts at `.secure-agent/configurable-owned-20261006/`, including
the retained initial development/macOS test failures. Do not repeat the merge.

**[PR #49](https://github.com/0xsl0th/recon-cockpit/pull/49) is merged and accepted.**
Reviewed head `c036d6ccd3e47be6f3f57e750cafe41693b3f456` merged as
`db42cd1ddecc45c0c3c743e7fe52514b8009a6da` on 6 October at 04:46:52 UTC.
Trees match (`a9c7a9b89d2067e5b054e7045a23da1fd6cc8292`). Fresh service/authority
and CLI/inspection reviews found no blockers; 95 focused and 517 historical
regression cases passed (overlapping sets). All five
[final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37414241668)
and all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37415326000)
passed. Preserve `.secure-agent/pr49-merge-review.json` and the accepted shared
service; do not repeat the merge. Its 9,722 portable tests, eight native cases,
12/12 useful actions, 36/36 forbidden witnesses and 29 unchanged evidence replays
remain accepted under their disclosed local/hosted and source distinctions.

**[PR #50](https://github.com/0xsl0th/recon-cockpit/pull/50) is merged and accepted.**
Reviewed head `c6108d09936694e600c30173148bb91431832ce2` merged as
`7efa9d851e8f0698b92618d94327d51157ecfa15` on 6 October at 05:15:35 UTC.
Trees match (`6ddc2a302491e071ac22b9feda87c1b567da612c`). Fresh controller/evidence
and UI/receipt reviews found no blockers; 101 GUI portable and 93 inspection/evidence
cases passed (overlapping review sets). All five
[final PR checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37416444887)
and all five [post-merge checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37417644593)
passed. Private merge receipt: `.secure-agent/pr50-merge-review.json`.
Its first desktop, 9,823 portable cases and six actual Tk cases remain accepted;
private evidence and seven screenshots remain at `.secure-agent/gui-20261006/`.
Do not repeat the merge.

**[PR #51](https://github.com/0xsl0th/recon-cockpit/pull/51) is merged and accepted.**
Reviewed head `411612dfa4ac1d0fb64ef83f8b2b120af741d465` merged as
`972afac9ddc8fa1c0211e84fd13509fba8580218` on 6 October at 05:47:38 UTC.
Trees match (`3f04290cc5f4d4789db93bd8d76c21b029755351`). Fresh lifecycle and UI
reviews found no blockers; 109 lifecycle and 115 GUI cases passed (overlapping
sets), and source/screenshot receipts matched. All five
[final PR checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37418950338)
and all five [post-merge checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37420312524)
passed. Its 9,837 portable and 11 actual Tk cases remain accepted, with zero tool
execution or provider calls. Preserve `.secure-agent/pr51-merge-review.json` and
`.secure-agent/gui-session-20261006/`; do not repeat the merge.

**[PR #52](https://github.com/0xsl0th/recon-cockpit/pull/52) is merged and accepted.**
Reviewed head `7b547941b812e1f7fc9c598c756b540aff9fc1b6` merged as
`21054db4d44098e8541c4c9a5edbf82dd3c0e0b5` on 6 October at 06:26:28 UTC.
Trees match (`88af19e00da06de2a3253b69c3033b64f068159e`). Fresh runtime/protocol
and worker/view reviews found no blockers. Additional review validation passed
35 actual graphical/workflow tests, 57 portable view/witness tests and 137
service/protocol tests (overlapping sets). All five
[final PR checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37422834741)
and all five [post-merge checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37423742151)
passed. Preserve `.secure-agent/pr52-merge-review.json`; do not repeat the merge.

**[PR #53](https://github.com/0xsl0th/recon-cockpit/pull/53) is merged and the personal walkthrough is accepted.**
Reviewed head `b708442cfc38d3958513e7ce483c79074e05fd22` merged as
`0539c154e734a1fd63a528c21bc072c1a9c71ded` on 7 October at 00:39:51 UTC.
Reviewed and merged trees match (`9fd439de76623bf7274ade655a6f12b13a43f094`).
Fresh source/documentation review found no blockers. The implementation and test
hashes matched 51 native Linux/Tk and 112 focused portable cases. All five
[final PR checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37552645134)
passed. The [post-merge run](https://github.com/0xsl0th/recon-cockpit/actions/runs/37553147019)
also passed all five jobs. Private merge receipt: `.secure-agent/pr53-merge-review.json`.
GitHub rejected formal self-approval because the active account owns the PR; no
GitHub approval is claimed. Do not repeat the merge or accepted personal checks.

The owner separately confirmed approval, denial and unanswered-review Ctrl+C,
then completed all four actions in `graphical-owned-5nkgldx7` and said
"ok this time it worked". The full session used four grants and four successful
executions in 45,642 ms, with `coordinator_done`, closed fixtures and zero
unnecessary refusals/provider calls/cost. Limits stayed at four steps, 60 seconds
and 26,624 bytes. Fresh independent replay of that session and its two preceding
incomplete full trials matched reports without changing evidence. Preserve the
3/4 distraction timeout and 2/4 reported-copy-problem timeout as incomplete; the
copying problem's cause remains unproven. Earlier unsuccessful personal trials
remain recorded separately. Receipts live in
`.secure-agent/graphical-full-approval-20261007/owner-confirmation-full.json`,
`full-trials-evidence-review.json`, and
`.secure-agent/graphical-single-action-20261006/owner-controls-confirmation.json`.
Automated tests do not substitute for this personal acceptance.

The accepted desktop source was `feature/desktop-owned-execution` in
`/tmp/recon-desktop-owned-execution`, based on `0539c15`. That slice added a fixed
**Execute owned lab** controller operation and desktop control. It reuses the
existing shared service with immutable scope, an approval-required policy,
`graphical_v1` and the same disconnected HTTP/SSH fixtures and limits. The separate
reviewer owns all affirmative input, fresh challenges, grants and direct launcher
witnesses. The ordinary desktop receives display data only. No secure-agent
contract, desktop transport permission or accepted tool profile changes.

Dry run stays separate. Both start controls and saved inspection remain disabled
until the single worker finishes authority cleanup and independent evidence replay.
Draft edits cannot affect an active request. Progress is provisional; cancellation
may leave useful partial work, and only replayed evidence supplies final metrics.
The main window cannot approve, restore grants, resume sessions or attach a real
network. Preserve the supported local Linux/X11 requirements and trusted-host/
desktop limitation.

**Validation complete:** 9,981 portable tests passed (849 integration cases
deselected), plus 70 actual Linux/Tk cases, with no selected failures/errors/skips.
Typed and clipboard desktop sessions each completed 4/4 useful actions and blocked
12/12 listening forbidden destinations. Denial and pending cancellation/close
launched nothing; cancellation after a successful action retained 1/4. All six
desktop bundles replayed unchanged with closed fixtures/processes and zero provider
calls/cost. Both themes passed at 1120×720. Independent source reviews found no
remaining blockers. These are scripted tests, not new personal acceptance.

**Accepted C3 evidence:** [PR #57](https://github.com/0xsl0th/recon-cockpit/pull/57)
has passed review/checks and merged. Preserve profile
`whatweb_http_fingerprint_v1` uses the secure single-action CLI path for one
GET of `/harbordesk/portal.html` at disconnected `127.0.0.1:8080`. The five
passive plugins are Title, HTTPServer, X-Powered-By, MetaGenerator and JQuery.
The finite WhatWeb/Ruby runtime and compiled guard bind the fixed request,
response-input cap, no redirects or linked-resource fetches, no cookies,
identity encoding and regular-expression deadlines. No arbitrary plugin,
credential, attached network, GUI operation or model call is added.

Structured results are only `untrusted_application_hints`. A complete HTTP 200
with no hints is useful completion, not technology absence. Strings and JQuery
version matches do not verify product identity, installed versions or
vulnerabilities. Literal hostile metadata cannot choose targets or follow-up work.
The parser requires the exact request configuration and closed bounded schema;
redirects, denied, malformed, incomplete and oversized results are inconclusive.

The complete portable suite passed **11,109 tests**, with 914 integration cases
deselected and zero failures/errors/skips. JUnit duration was **299.271 seconds**;
the pytest terminal summary includes additional runner overhead at 299.54 seconds.
The private receipt is `.secure-agent/whatweb-20261007/portable-final.xml`.

The [C3 runbook](whatweb-tools.md) defines eleven scenarios. Final native
validation passed **39 tests** in 156.861 seconds, with zero selected failures,
errors or skips: 17 C3 cases plus 22 accepted-tool regressions. Ordinary
`whatweb-ok` and `whatweb-no-hints` completed 2/2 with zero unnecessary refusals;
injected metadata and meta redirects separately completed 2/2. All eleven
scenario bundles replayed unchanged, closed at one connection/validated GET,
and passed 22/22 forbidden-destination witnesses plus 110/110 boundary fields.
Grant consumption/replay rejection, missing-proof denial, cancellation after
actual execution, private-input isolation, UDP refusal and thread ceilings passed.
The real JSON output-pressure case stopped at the cap with only two bytes
retained; no useful observation was invented.

Independent verification at clean `0bdd9b6` repeated both ordinary and both
robustness trials, with zero unnecessary refusals and 8/8 blocked destinations.
All four new bundles and 36 accepted bundles replayed identically through both
inspectors without changing bytes, modification times or modes. Ordinary wall
times were 4,322/4,338 ms; robustness times were 4,313/4,537 ms. These are local
descriptive measurements, not comparative overhead. Calls/cost stayed zero.
Receipt: `.secure-agent/whatweb-20261007/clean-source-0bdd9b63-949y69_c/verification.json`.
The unattended synthetic policy does not claim personal approval; the shipped
policy still requires it. Keep earlier failed startup/native attempts and the
initial portable failure separately; its 16 failures were stale test selectors
and mappings, corrected without changing the validated production code.

Accepted C2 evidence remains closed at 10,776 portable and 28 native cases,
2/2 ordinary TLS tasks, 24/24 blocked destinations and 33 prior evidence bundles
replayed unchanged. Preserve `.secure-agent/database-tls-20261007/`, including
`clean-source-dca81413-6w256_ve/verification.json`; its descriptive wall times are
not a comparative overhead benchmark. The shipped policies still require fresh
personal approval; automated synthetic grants do not claim owner acceptance.

**Accepted C4: fixed DNS SRV metadata with dig.** One synthetic TCP
question, `_ldap._tcp.harbordesk.test. IN SRV`, returns at most four typed
priority/weight/port/target/TTL rows. Results mean only untrusted DNS service
advertisements. NODATA, NXDOMAIN and a sole zero-valued root target are distinct
completed responses; they do not establish actual absence or availability. No
recursion, target resolution, endpoint follow-up, UDP, search, transfer or new
credential handling is allowed. The shipped one-tool policy requires approval.

Completion requires G1–G6, all seven authority gates, 4/4 ordinary completions with
zero unnecessary refusals and a separately measured useful injected-metadata
trial. Each of ten scenarios must execute the actual native client, acknowledge
one fixed question/connection, close owners, preserve bounded raw and structured
evidence, block forbidden destination witnesses and replay unchanged. The five
negative cases are malformed response, excess records, refusal, stall and actual
output pressure. Startup failure or blocking every request cannot satisfy this
batch. Six additional native tests cover grant replay, missing proof, cancellation,
private inputs, UDP and task limits. Native validation passed **25 tests** in
79.168 seconds with 75 deselected and zero selected failures/errors/skips: 16 C4
and nine accepted dig/OpenSSL regressions. All ten scenarios matched their
outcomes, acknowledged one question/connection, blocked 20/20 forbidden
destinations, passed 100/100 boundary fields and replayed unchanged.

Clean-source verification at `0c6dcf573b9792966deee492f667803e5dfaf960` completed
4/4 ordinary outcomes and the separate hostile-metadata task, with zero
unnecessary refusals/provider calls/cost. It blocked 10/10 destinations and
replayed all five new plus 40 accepted bundles through both inspectors without
changing bytes, modification times or modes. Private receipt:
`.secure-agent/dns-srv-20261007/clean-source-0c6dcf57-5of2_1wq/verification.json`.
The final full portable suite passed **11,428 tests**, with 930 integration cases
deselected and zero failures/errors/skips. JUnit time was 298.681 seconds;
the terminal summary includes runner overhead at 299.02 seconds. Retain the
first full run's 11,427 passes and one stale pre-C3 fixture-snapshot selector
failure separately. The selector correction passed 86 focused tests and changed
only that older portable test. Production/native source remains the clean-source
`0c6dcf5` implementation; of the 502 files in the validation source index, only
that test differs in the final index. Preserve both indexes and private receipts.
Independent final reviews passed 1,328 authority/runtime, 821 parser/evidence and
422 regression tests. All five final hosted jobs passed 11,428 tests each;
reviewed `65810b8` and merge `6080a5c` have identical trees. C4 is accepted at
29 profiles using 14 programs. Descriptive latency and byte counts do not
establish comparative overhead.

**Accepted C5: fixed RDP initial negotiation (PR #59).** The 19-byte request
offers TLS only at the owned endpoint. The client closes its write side before
reading a single 11- or 19-byte response, with a two-second absolute operation
deadline. Raw bytes go to the independent parser; selected protocol, flags and
known failures are `untrusted_rdp_negotiation_metadata`. TLS selection, explicit
standard RDP, legacy confirmation, NLA-required failure and Entra-required failure
form five ordinary useful tasks. Fragmented responses and a valid frame followed
by hostile trailing data form two separate robustness tasks. Malformed, unoffered,
unknown-failure, truncated, oversized and stalled responses remain inconclusive.
The trailing-data trial proves no follow-up; the client does not inspect its tail.

C5 local validation passed **11,898 portable tests** (949 deselected;
270.690 JUnit seconds) and **36 native tests** (19 C5 and 17 WhatWeb;
109.828 seconds), with zero failures, errors or skips. All 13 scenarios executed
and replayed with one validated request/connection, witnessed write-half-close,
enforced bounds and closed owners: **5/5 ordinary** and **2/2 robustness** tasks
completed with zero unnecessary refusals, **26/26 unauthorized destinations**
were blocked and **130/130 boundary fields** passed.

Clean-source verification at `f24a2528e53befa672b36fb7de8538a4595a7a38`
repeated the seven useful trials with **14/14 blocked destinations** and replayed
all **45 accepted bundles** through CLI and shared inspection without changing
bytes, mtimes or modes. All **514 source hashes** matched. The receipt is
`.secure-agent/rdp-negotiation-20261007/clean-source-f24a2528-002u84al/verification.json`
(SHA-256 `94ee22d2ffe1f05acaffd2c9de4f02257349b75469ca1b5997db971799fc49d5`).
Independent source review passed 1,395 tests; earlier focused runtime (979),
fixture (483), parser/evidence (611) and core (971) runs overlap and are not an
additional aggregate. Final review and all five final/post-merge checks passed;
[PR #59](https://github.com/0xsl0th/recon-cockpit/pull/59) merged as `846e459`.
C5 stays closed.

Preserve every authority gate and the fresh-approval policy.
No TLS/CredSSP/NTLM, authentication, session,
verified identity or exhaustive protocol-support result is claimed. The exact
reviewed Linux Ruby 3.3 x86-64 closure is a supporting runtime for a repository
adapter, not another third-party program. The accepted count is 30 profiles/14
programs; it adds no GUI workflow or real-network attachment.

**Current continuation: finish C17 owned validation and PR handoff.** The
operator authorized the Git HEAD marker batch; follow the current status at the
top and [C17 runbook](nuclei-git-tools.md). C16 and earlier completed milestones
stay closed. No deeper workflow, credential or live-model work is included.

Preserve `.secure-agent/gui-execution-20261007/`, including earlier failed native
runs and interrupted portable runners. Deeper composition, comparative benchmarking,
credentials, paid calls and live-model evaluation stay deferred. Real network
attachment requires separate authorization. Completed B0–B8, offline R5 and
accepted local R6 remain closed.

Accepted validation receipts, screenshots and source hashes remain in
`.secure-agent/graphical-approval-20261006/` in the primary checkout.
Final local validation passed **9,949 portable and 125 native Linux/Tk cases**,
with no selected failures/errors/skips. Scripted graphical review completed
**4/4 useful actions**, blocked **12/12 listening forbidden destinations**,
recorded zero unnecessary refusals/provider calls/cost and replayed unchanged.
Native elapsed time was 8,569 ms; it is not personal-review latency or a benchmark.
The initial personal walkthrough exposed a usability defect: the phrase was a
nonselectable label, and the owner reported being unable to copy/paste it. Both
started sessions timed out with zero grants consumed and zero tool launches; the
cancellation session did not start. These are unsuccessful trials, not approval,
denial or cancellation acceptance. Retain their private evidence and feedback in
`.secure-agent/graphical-owner-20261006/`. The screenshot and copy-fix validation
belong in `.secure-agent/graphical-copy-20261006/`. The later individual controls
and full four-action personal walkthrough are accepted as described above. Keep local
Linux/Tk evidence distinct from portable CI and retain earlier validation receipts.
Private images stay outside Git. The proposal/PDF and separate PR #31 remain unchanged.

Both user-created Swiss Industrial PNGs were inspected and privately preserved.
[GUI design notes](gui-design-references.md) record the original Downloads paths,
private copies and intended light/dark layout. The images are not in Git. GUI
work must reuse the authority path and display real offline state, not treat the
mockup's example costs, agents or verification labels as implemented features.

**[PR #46](https://github.com/0xsl0th/recon-cockpit/pull/46) is merged and the read-only catalog is accepted.**
Reviewed head `ef1cadb` merged as `0d5cbdc` at 02:24:31 UTC on 6 October, with an
identical tree. Fresh production/CLI and evidence/documentation reviews found no
blockers; 213 focused tests passed and all 19 saved dry-run bundles replayed
unchanged. All five [final PR checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37403185851)
and all five [post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37403977730)
passed. Preserve the [catalog](secure-tool-catalog.md), its accepted recipes and
all existing tool contracts. Private receipt: `.secure-agent/pr46-merge-review.json`.

**[PR #47](https://github.com/0xsl0th/recon-cockpit/pull/47) is merged and accepted.**
Reviewed head `81d8fe15505203e6080e0fa4667254694dbfffbf` merged as
`fc477d03a9feb59f2a2c851d7b95146c0d2922ae` on 6 October at 03:13:12 UTC;
the reviewed and merged trees match (`93bdb355fcf55a7a49c21f8b794e72d0a896a0b3`).
Fresh authority/runtime and evidence reviews found no blockers (943 and 690
overlapping focused checks); nine native checks and 27 unchanged evidence
replays passed. All five [final PR checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37406744203)
passed. All five [post-merge checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37407943234)
passed on attempt 2: the first attempt hit a macOS malformed-peer cleanup race.
The original failure is retained; this branch fixes the test peer lifetime while
preserving production cleanup and descendant-process checks.

Implementation `a1a186b` composes three
existing capabilities in a separate shared owned lab, with fixed actions,
three-step/60-second/18,432-byte session limits and independently replayed evidence.
Nmap must identify HTTP before ffuf; complete fixed-path discovery must establish
the portal before its header GET. All seven gates remain mandatory.

Local validation passed **8,776 portable and 128 distinct Linux tests** (nine new
workflow cases and 119 affected regressions). Independent runtime/authority and
CLI/evidence reviews found no blockers. Clean-source vulnerable, corrected and
injected trials completed **3/3 useful workflows and 9/9 actions**, with zero
unnecessary refusals and zero provider calls/cost. All **18/18 forbidden-destination
witnesses** were blocked; each lab closed after ten requests and eleven connections.
CLI process wall times were 7.589–7.660 seconds, a descriptive local measurement,
not a paired overhead benchmark. Hostile metadata remains in raw ffuf evidence;
this does not claim a model-induced proposal. All three new reports and all
24 accepted B1–B8 bundles replayed unchanged.

Private receipts are `.secure-agent/service-web-20261006` in the primary checkout:
`verification.json`, `validation-summary.json`, `verification-script.py`,
`validation/`, `runs/` and the latest `handoff.json`. Development failures are
retained, including the fixed initial Nmap empty-connection reset and test/verifier
assertion errors; they do not count as final acceptance. See
[the runbook](service-web-assessment.md) and [verification record](verification.md).
The merge review is retained at `.secure-agent/pr47-merge-review.json` and
`.secure-agent/pr47-review-20261006/`. Preserve this accepted workflow; do not
repeat its implementation or claim a personal walkthrough of the new slice.

Follow the new priority table for shared application services, initial GUI and
later tool batches. Broader composition and comparative benchmarking remain
later work. Model credentials, paid calls and live evaluation remain deferred
until much later; do not prepare credentials or enable a live provider. Keep the
proposal/PDF unchanged.

**PR #38 is merged and B1 is accepted.** Reviewed head `0e2a0d7` merged as
`5436dd6` at 04:11:12 UTC on 1 October. Its merge tree exactly matches the reviewed
revision. Fresh runtime and parser/evidence reviews found no blockers; all five
[final PR checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36812445171)
passed, with no outstanding GitHub review comments. All five
[post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36813934553)
also passed. The final hosted macOS run
passed 5,451 portable tests. Local B1 receipts cover 119 distinct affected Linux
cases, including real dig/OpenSSL execution and read-only replay. Preserve these
accepted contracts and evidence. Private merge receipt:
`.secure-agent/pr38-merge-review.json`; B1 evidence:
`.secure-agent/network-tools-20261001`, both in the primary checkout.

**PR #39 is merged and B2 is accepted.** Reviewed head `11405a3` merged as
`79abaab` at 23:57:28 UTC on 1 October. Fresh runtime/enforcement and
parser/contracts/evidence reviews found no blockers. All five
[final PR checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36815728346)
and all five [post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36943515375)
passed. The merge tree exactly matches the reviewed revision; keep B2 closed.
Validation passed 5,711 portable and 127 selected Linux tests (19 new B2 and
108 existing), plus two useful clean-source trials with read-only replay and
unchanged accepted B1 evidence. Private receipts remain
`.secure-agent/pr39-merge-review.json` and `.secure-agent/ssh-ldap-tools-20261001`
in the primary checkout. See [ssh-ldap-tools.md](ssh-ldap-tools.md).

**PR #40 is merged and B3 is accepted.** Reviewed head `58fca54` merged as
`775352e` at 01:23:31 UTC on 2 October. Fresh runtime/launcher and
fixture/parser/evidence reviews found no blockers; the merge tree matches the
reviewed tree. All five [final PR checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36948177611)
and all five [post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36950712204)
passed. Each hosted job passed 5,945 portable tests. Local validation also covers
168 selected Linux cases and a clean normal trial with useful completion 1/1,
zero unnecessary refusals, closed/read-only replay and unchanged B1/B2 bundles.
Keep B3 closed within [its finite SMB scope](smb-tools.md): native empty, denied
and malformed replies remain inconclusive. Private receipt:
`.secure-agent/pr40-merge-review.json`; evidence: `.secure-agent/smb-tools-20261002`
in the primary checkout. Main has 11 secure capabilities backed by 8 external
programs; the broader coverage milestone remains open.

**[PR #41](https://github.com/0xsl0th/recon-cockpit/pull/41) is merged and B4 is accepted.**
Reviewed head `670c891` merged as `6623aa0` at 02:39:43 UTC on 2 October. Fresh
runtime/fixture and parser/evidence reviews found no blockers; all five final
[PR checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36955342509) passed,
with 6,348 portable tests per job and no outstanding review comments. The merge
tree matches the reviewed tree. [Post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36956656745)
also passed all five jobs. Keep B4's fixed RPC/NFS metadata contracts closed.
Local evidence covers 215 distinct Linux checks, 4/4 useful normal/empty trials,
zero unnecessary refusals and unchanged replay of all five B1–B3 bundles.
Private receipts: `.secure-agent/pr41-merge-review.json` and
`.secure-agent/rpc-nfs-tools-20261002` in the primary checkout. Main now has
13 accepted secure capabilities backed by 10 external programs.

**[PR #42](https://github.com/0xsl0th/recon-cockpit/pull/42) is merged and B5 is accepted.**
Reviewed head `b682b3c` merged as `38cbd43` at 03:18:41 UTC on 2 October. Fresh
runtime/fixture and parser/evidence reviews found no blockers; 549 and 641 focused
portable checks passed. All five [final PR checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36958714438)
passed, with no outstanding review comments. The merge tree exactly matches the
reviewed tree. [Post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36959608247)
also passed all five jobs. Keep the [bounded FTP/SMTP contracts](ftp-smtp-tools.md)
closed. Main now has **15 accepted secure capabilities backed by 10 external programs**.

Local receipts cover 6,755 portable and 239 selected Linux checks, 4/4 useful
normal/empty trials, zero unnecessary refusals, closed labs and matching read-only
replay. Fresh review validated all four B5 artifacts and all nine accepted B1–B4
bundles, without changing bytes or mtimes. All 36 B1–B4 definitions remained exact.
Private receipts: `.secure-agent/pr42-merge-review.json` and
`.secure-agent/ftp-smtp-tools-20261002` in the primary checkout.

**[PR #43](https://github.com/0xsl0th/recon-cockpit/pull/43) is merged and B6 is accepted.**
Reviewed head `81c97ef` merged as `02a7d7f` at 04:04:38 UTC on 2 October.
Fresh runtime/policy and parser/evidence reviews found no blockers (1,267 and
854 focused portable tests). All five [final PR checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36961755646)
passed, as did all five [post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36962953259).
The merge tree exactly matches the reviewed tree. All eighteen saved
bundles replayed with matching reports and unchanged bytes/mtimes. B6 receipts
cover 7,444 portable and 275 distinct Linux tests and 5/5 useful trials with zero
unnecessary refusals. Keep [the three fixed metadata profiles](docker-winrm-tools.md)
closed. Main now has **18 accepted secure capabilities backed by 10 programs**.
Private receipt: `.secure-agent/pr43-merge-review.json`; B6 evidence remains
`.secure-agent/docker-winrm-tools-20261002` in the primary checkout.

**[PR #44](https://github.com/0xsl0th/recon-cockpit/pull/44) is merged and B7 is accepted.**
Reviewed head `f81c444` merged as `fcb9419` at 04:51:36 UTC on 2 October.
Fresh runtime/policy/fixture and parser/evidence reviews found no blockers;
1,147 and 836 focused portable checks passed, plus twelve recomputed-policy
checks confirmed GET remains required. All five [final PR checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36965365612)
and all five [post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36966387286)
passed. The merge tree exactly matches the reviewed tree. Twenty-one saved
bundles replayed unchanged: three B7 and eighteen accepted B1–B6. Keep B7's
[finite Nmap service profiles](nmap-service-tools.md) closed, including honest
unidentified outcomes. Main now has **19 accepted secure capabilities backed by
10 programs**. Private receipts: `.secure-agent/pr44-merge-review.json` and
`.secure-agent/nmap-service-tools-20261002` in the primary checkout.

**[PR #45](https://github.com/0xsl0th/recon-cockpit/pull/45) is merged and B8 is accepted.**
Reviewed head `9edec213` merged as `47d70a2` at 01:59:42 UTC on 6 October.
The merge tree exactly matches the reviewed tree. Fresh runtime/authority and
parser/evidence reviews found no blockers, with 1,338 and 998 focused portable
checks plus 35 recomputed policy-denial cases. All five
[final PR checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37401053840)
passed, and all 24 saved B1–B8 bundles replayed unchanged. All five
[post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37401942532)
also passed.
Private merge receipt: `.secure-agent/pr45-merge-review.json` in the primary
checkout. Keep B8 closed within its documented report-level semantics.

The separate `kerbrute_userenum_v1` profile runs the real executable against an
owned error-only KDC at `127.0.0.1:8080`. Only `fixture-a` and `fixture-b` in
`HARBORDESK.TEST` can be queried, with two requests, one tool action, a five-second
tool deadline, 60-second session and 8,192 combined output bytes. The KDC has no
real directory, passwords or ticket-issuing path. Stock Kerbrute tries UDP; the
TCP-only filter rejects it and confines the subsequent TCP fallback.

Results explicitly mean **tool-reported exists/unknown**, not authenticated
principal facts. Kerbrute's error-string classification can turn a generic error
containing `KDC_ERR_C_PRINCIPAL_UNKNOWN` into an ordinary unknown report. The
spoof scenario makes that limitation visible; it does not count as verified
negative discovery or successful injection detection. No result grants follow-up
authority. See [kerberos-tools.md](kerberos-tools.md).

Clean source `de40f28` completed both legitimate reporting tasks 2/2 with zero
unnecessary refusals, plus a separately counted spoof-ambiguity demonstration.
All six forbidden-destination witnesses were blocked; all three labs closed,
raw evidence/replay matched, and all 21 accepted bundles replayed unchanged.
CLI times were 2.854–2.982 seconds, with zero provider calls/cost. Validation
passed the complete 8,186-test portable suite and 252 distinct Linux tests, with no selected
failures, errors or skips. Independent reviews found no remaining blockers.

Private evidence is `.secure-agent/kerberos-tools-20261002` in the primary
checkout (work began 2 October; final validation 6 October). It includes
`verification.json`, `validation-summary.json`, the archived verifier, retained
failed development/test-instrumentation receipts and the latest `handoff.json`.
See [verification.md](verification.md). All required B0–B8 rows now satisfy
G1–G6 under the [recorded reconciliation](secure-tool-coverage.md#gate-reconciliation--accepted-b0b8).
There is no required B9. Roughly forty tools remains a long-term direction, not
a claim that this finite milestone delivers the full professional product. The
catalog makes the accepted coverage usable without broadening it; optional
capabilities and deeper workflow/benchmark work remain later slices.

Credential setup, paid calls and live-model evaluation remain deferred until much
later. Do not ask for a key, fund a ledger or enable a live provider. Preserve
completed offline R5, accepted local R6 and the separate proposal/PDF.

**[PR #37](https://github.com/0xsl0th/recon-cockpit/pull/37) is merged and stays closed.**
Reviewed head `924f2ea` merged as `ba0d6f8` at 03:18:31 UTC on 1 October. The merge
tree exactly matches the reviewed tree and local main was updated cleanly. All five
[final PR checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36809471476)
and all five [post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36809908913)
passed. Review fixed the missing-runtime-commitment evidence edge case; 153 affected
portable checks and all ten owned-tool cases passed after the fix. The final macOS
job passed 5,157 portable tests. Earlier independent execution verified 23 new and
115 affected legacy Linux cases. Private receipts remain
`.secure-agent/pr37-merge-review.json` and `.secure-agent/practical-web-tools-20261001`
in the primary checkout. Keep its bounded curl/ffuf contracts closed.

**[PR #36](https://github.com/0xsl0th/recon-cockpit/pull/36) is merged and stays closed.**
Final reviewed head `3d29142` merged as `9a95d9a` at 01:33:15 UTC on 1 October;
the merge tree exactly matches the reviewed tree. All five
[final PR checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36801243417)
and all five [post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36801648147)
passed. Its implementation passed independent review, 4,898 portable tests and
99 affected Linux tests. Three fresh two-action CLI demos replayed without integrity
issues. Private evidence remains `.secure-agent/http-headers-20261001`, with the
merge receipt `.secure-agent/pr36-merge-review.json` in the primary checkout.
Do not repeat that merge or expand its accepted scope retroactively.

**[PR #35](https://github.com/0xsl0th/recon-cockpit/pull/35) is merged and stays closed.**
Final reviewed head `59ea9f3` passed independent review and all five
[final hosted checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36796851542).
The guarded merge is `98d6f1b` at 00:40:24 UTC on 1 October; its tree exactly
matches the reviewed head. All five
[post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36797343742)
passed. The private `.secure-agent/pr35-merge-review.json` receipt in the primary
checkout records the merge and latest deferral. Do not repeat the merge.

The [model integration](web-model-pilot.md) remains available but disabled by
default. Its 4,600 portable and 51 affected Linux tests passed with no selected
failures/errors/skips. Implementation `03def1b` produced two saved owned simulations:
`.secure-agent/web-model-owned-20261001` and
`.secure-agent/web-model-blocked-20261001` in the primary checkout. The adjacent
`web-model-20261001-verification.json` records source and receipts. The first
completed all three actions; the blocked injection completed only two and failed
usefulness. These are synthetic results, not real-model evaluation. No paid call
or real credential read occurred. The proposed three-session, nine-call, $1 pilot
is deferred, not the next execution gate; its configuration would require fresh
review and explicit authorization when the operator resumes that work.

**PR #34 is merged and stays closed.** Fresh independent review of exact head
`7494b7fe230c9f6ab73366fa746afcc306935426` found no blockers or outstanding comments.
All five [final jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/36782099190)
passed. The guarded merge is `17945db` at 23:46:20 UTC on 30 September; its tree
exactly matches the reviewed head. All five
[post-merge main jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/36792805339)
passed. Preserve its 18-trial offline comparison and private evidence at
`.secure-agent/web-comparison-20260930` in the primary checkout. Do not repeat
that merge or reopen its accepted comparison scope.

**PR #33 is merged and stays closed.** Fresh independent review of final head
`aaa5c6a` found no blockers or outstanding comments. All five
[final hosted checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36771053368)
passed. Saved reports verify 4,243 portable and 507 Linux tests, plus nine fresh
workflow trials after the counter assertion correction. The authorized guarded
merge is `ed7d839` at 21:02:55 UTC on 30 September; its tree exactly matches the
reviewed head. All five
[post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36776840618)
passed. Keep the resettable web lab and accepted fixtures/contracts closed.

**PR #32 is merged and stays closed.** Final head `b7e1904` passed review and
all five [final hosted checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36764600927).
The guarded merge is `875c1a6` at 19:23:07 UTC on 30 September; its tree exactly
matches the reviewed head. All five
[post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36765297652)
passed. Do not repeat its merge or reopen the adapter/Nmap slice. Existing
TCP/HTTP contracts, fixture bytes and accepted evidence remain regression anchors.

The completed broader coverage milestone superseded the earlier two-tool
stopping point. The [inventory](secure-tool-coverage.md) records interactive and
secure support, accepted B0–B8 scope and later professional-use gaps. Roughly
40 tools remains a long-term target; executable counts do not replace protocol
coverage or verification. The accepted catalog and current workflow preserve these boundaries.

Refresh the proposal with verified progress in early November and target submission
around 9 November after operator review. Documentation PR #31 on
`docs/proposal-author-voice` remains separate and unmerged; the polished PDF stays
local, ignored and unchanged. No competition submission or release is authorized.

**Current milestone: R5 offline scope complete; R6 local offline candidate accepted.** The
accepted provider/accounting, separated authority, owned planning and offline
comparison work through PR #26 has no remaining necessary offline R5 blocker.
The minimal model integration is prepared; real-model validation and acceptance
remain pending. Live work needs reviewed data, model/endpoint, credential, egress
and spending settings; it is not merely supplying an API key. No paid calls are authorized.

**PR #27 is merged and stays closed.** Final head `bbd33fd` passed review with
no blockers or outstanding comments and all five
[final hosted checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36667566229).
The authorized guarded merge is `dd4bbe4` at 04:15:01 UTC on 30 September;
its tree exactly matches the reviewed head. All five
[post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36667987075)
passed. Do not repeat this merge or reopen the accepted packaging scope.

**R6 terminal rehearsal and local candidate accepted.**
The operator authorized opening the offline walkthrough and then a
fresh attempt after distraction. The first attempt timed out at the first
approval with no action executed. The fresh run on clean `dd4bbe4` completed
three separately approved actions in **50.011 seconds**, validated synthetic
case a and closed the owned lab. Independent replay found no integrity issues;
the simulated ledger settled **2,334 microUSD**, with zero unresolved holds and
zero paid/live calls. The assistant supplied no terminal responses. The operator
confirmed: “I entered all 3 and it seemed straight forward”. After reviewing
the linked report and rehearsal, the operator chose **“Accept the local offline
candidate”** on 30 September. This closes the local evidence/rehearsal review;
live-model work and release publication remain deferred.

Private records: `.secure-agent/r6-operator-20260930-i7ou70cr` (preparation and
timeout) and `.secure-agent/r6-operator-20260930-retry-w4xi91nq` (successful
rehearsal). The packet replay and tampered-copy refusal passed without changing
the original candidate. The actual human decision is recorded separately in
[verification.md](verification.md) and the successful run's
`operator-review.json`. The immutable packet retains its original pending
fields; they describe its creation state. Do not alter or rebuild it merely to
record acceptance. Live activation and release publication remain unauthorized.

**PR #28 is merged and stays closed.** The operator separately authorized its
review and merge on 30 September. Final head `4ced75f` passed fresh independent
review with no blockers or outstanding comments and all five
[hosted checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36670287169).
The guarded merge is `f70e7ea` at 04:54:53 UTC; its tree exactly matches the
reviewed head. Runtime/tests are unchanged. All five
[post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36670999757)
passed. Do not repeat this merge or operator review.

**PR #29 is merged and stays closed.** Final head `32d44af` passed fresh
independent review with no blockers or outstanding comments and all five
[hosted checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36671559852).
The operator-authorized guarded merge is `cba8059` at 05:18:21 UTC; its tree
exactly matches the reviewed head. All five
[post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36672797756)
passed. The Spanish proposal reconciliation is complete; do not repeat it.

**PR #30 merged; its earlier local draft remains a historical export.**
Final head `1634097` merged as `8ae4aad` at 06:14:59 UTC on 30 September.
Do not repeat that merge. PR #31 contains the subsequent jury-focused proposal
and author-voice revisions; the latest polished PDF remains local and unchanged.
No competition submission has occurred.

For the earlier PR #30 export, the operator
authorized a readable proposal PDF, an unsent email, references to the accepted
evidence/runbook and this checkpoint update. Branch `docs/submission-draft-package`
starts from `cba8059` and is tracked in
[PR #30](https://github.com/0xsl0th/recon-cockpit/pull/30). The final PDF and
supporting files are in `.secure-agent/submission-draft-20260930-final`; visual,
content and privacy checks are complete. The earlier interrupted-work snapshot
and `submission-draft-20260930-layout` are superseded. The PDF remains ignored
and local; it was not part of the PR.
The proposal text remains unchanged; the local PDF uses
that full source revision for its document links. This document revision is
distinct from the accepted packet's verification source `070257b` and the
rehearsal's execution revision `dd4bbe4`.

The [local renderer](../scripts/render_submission_draft.py) and
[print stylesheet](submission-print.css) use the prepared host Python, Markdown,
BeautifulSoup, WeasyPrint, Graphviz and DejaVu fonts. They are documentation
tools, not new application dependencies. Asset retrieval is disabled; the
architecture preserves the existing diagram's labels and directed edges. Output
goes to a new private directory with a PDF, unsent copy of
[the email draft](submission-email.txt), source/HTML/SVG, review notes and a hash
manifest. Private evaluation records are referenced for the operator, not copied
into proposed attachments. The PDF is the only proposed email attachment.

```sh
python3 scripts/render_submission_draft.py \
  --revision cba8059e084655c355301d15dfd374505352c2b3 \
  --output .secure-agent/submission-draft-NEW
```

The renderer refuses existing output directories and a proposal that differs
from the selected source revision. It does not install dependencies, run agents,
submit email or publish a release. The dated draft remains for operator review;
submission/publication, live work and merges after PR #30 require their
corresponding operator instruction. See [verification.md](verification.md) for
the final local artifact and export checks.

**PR #25 is merged and stays closed.** The operator authorized review and merge
on 30 September. Final head `c7f7791` passed a fresh review with no blockers or
outstanding comments and all five hosted checks. The guarded merge is `636a067`
at 02:27:02 UTC; its tree exactly matches the reviewed head. Saved full reports
confirm 3,579 portable and 466 Linux tests with zero selected failures/errors/skips.
The last two commits corrected existing portable test synchronization; runtime
is identical to verified implementation `30f2b2d`. See
[PR #25](https://github.com/0xsl0th/recon-cockpit/pull/25) and
[verification.md](verification.md). All five
[post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36659899487)
passed. Do not repeat this merge.

**PR #26 is merged and stays closed.** The operator authorized review and merge
on 30 September. Final head `7e5c2ac` passed fresh independent review with no
blockers or outstanding comments and all five
[final hosted checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36663416736).
The guarded merge is `1605606` at 03:22:20 UTC; its tree exactly matches the
reviewed head. Runtime/tests match verified implementation `c2d4d0b`: **3,726
portable tests in 210.53 seconds** and **477 Linux tests in 972.80 seconds**,
with zero selected failures/errors/skips. Do not repeat this merge or reopen
its accepted offline evaluation scope. All five
[post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36664091986)
also passed.

Its actual CLI comparison passed **18/18 trials**, 51 TLS exchanges/executions,
45 successful actions, 12 correct abstentions and zero unnecessary actions.
Simulated usage was 39,678 microUSD with zero unresolved holds and zero real
provider calls. All six semantic fingerprints match the independently inspected
saved baseline. Private inputs are `.secure-agent/evaluation-baseline-20260924`
and `.secure-agent/planning-evaluation-20260930`. The saved runs did not record
an execution commit; preserve that provenance limit. Read
[planning-evaluation.md](planning-evaluation.md) and [verification.md](verification.md).

**Merged R6 evidence packet and demo runbook**, implementation
`46fc12a` in [PR #27](https://github.com/0xsl0th/recon-cockpit/pull/27), on
`feature/offline-release-evidence` from `1605606`. Read
[offline-release-evidence.md](offline-release-evidence.md). This bounded R6
preparation slice copies the two independently regraded default evaluations,
pins a clean verification/reproduction source tree, verifies every input byte,
and renders a deterministic comparison packet. It does not run agents, install
packages, publish a release or declare operator acceptance. Final local
verification passed **3,878 portable tests in 249.67 seconds**, with zero
failures/errors/skips, including 82 source and 70 packet cases. Independent
reviews have no remaining blockers. The [PR checks](https://github.com/0xsl0th/recon-cockpit/pull/27/checks)
show this checkpoint's latest hosted status. The latest merge authorization
covers PR #27; it does not authorize a release publication or another merge.

The actual CLI produced two byte-identical **331-file packets**, with **246
source files** pinned to `070257b455f158eb06301fae143c0704ee02ee30`. Candidate:
`.secure-agent/offline-release-evidence-20260930-final`. Read-only CLI inspection
reproduced the report and preserved original input/packet bytes and mtimes.
Inspection also passed from the archived source in a fresh directory without
Git metadata, using the existing prepared environment. Both evaluations retain
18 passing trials and six matching fingerprints; actual provider calls are zero.
Execution/isolation code is unchanged; PR #26's 477-test Linux verification
remains its accepted runtime evidence, not a newly run suite for this slice.

Reports: `/tmp/recon-release-all-portable-final.xml`,
`/tmp/recon-release-packet-smoke-final.json` and
`/tmp/recon-release-archived-source-final.json`. See [verification.md](verification.md).
Hosted CI exposed a background Git maintenance race in the new source test
fixture; automatic fixture maintenance is now disabled, with the full read-only
assertion preserved. All 82 source tests passed after correction. Runtime and
Linux-selected tests match `46fc12a`. Do not rerun full local suites solely for
checkpoint documentation. The operator has now accepted this local candidate
after the rehearsal above. Keep that scope closed; live activation and release
publication/submission still require their corresponding operator instruction.

**PR #24 is merged and stays closed.** Final head `9ccc910` passed review and
all five hosted checks. Its merge is `4f9545c` at 22:38:18 UTC on 29 September;
all five post-merge main checks passed. Runtime evidence remains 3,382 portable
and 430 Linux tests. It completed the bounded mock planning bridge.

On 30 September the operator agreed to continue development with paid live
agents disabled. Finish necessary integration and offline evaluation first;
ordinary development, CI and demos must make no paid calls. A later small
real-model experiment needs explicit approval of its data/model/endpoint,
credential and spending limits. This does not authorize live activation or
declare R5's real-model acceptance complete.

**PR #23 is merged.** The operator authorized review and merge on 29 September
2026. Final head `6dc7a7d` passed review with no blocking findings or outstanding
comments and all five hosted checks green. The authorized merge is `a87e5dd` at
21:57:20 UTC; its tree exactly matches the reviewed head. All five
[post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36636608649)
passed. The previously completed 3,196 portable and 406 Linux tests remain the
runtime evidence; the final PR commit changed documentation only. PRs #16–#23
are merged and stay closed.

Historical PR #24 branch: `feature/bounded-assessment-planning`, from `a87e5dd`. This verified
R5 slice integrates a separate bounded mock planning adapter with
explicit data release, the isolated parser/coordinator, simulation monetary
admission and both direct launch gates. Implementation `bb9e42c` is published in
[PR #24](https://github.com/0xsl0th/recon-cockpit/pull/24). Read
[bounded-assessment-planning.md](bounded-assessment-planning.md). Full verification
passed **3,382 portable tests in 86.69 seconds** and **430 Linux tests in 771.15
seconds**, with zero selected failures/errors/skips and no leftover workers.
Independent review has no remaining findings; all five hosted jobs passed on
the implementation. The [PR checks](https://github.com/0xsl0th/recon-cockpit/pull/24/checks)
show the final documentation checkpoint's status. Its merge authorization
covered PR #24 only. Live calls and external targets remain disabled.

## Current priority — preserve accepted offline work

**The agreed offline R5 implementation and verification scope is complete.**
R5a merged in PR #13, R5b in PRs #14/#15, the accepted authority/planning
integration through PR #25, and its independent offline comparison in PR #26.
PR #27 packages that evidence and the demo runbook as R6 preparation. Follow
[the roadmap's completion order](roadmap.md#milestone-completion-order).

Preserve the accepted R1–R4 and offline R5 contracts and their documented limits.
No necessary offline R5 blocker remains. The newly authorized model integration
is separate follow-on work; real-model validation and acceptance remain pending; fixtures do not complete the full live
criterion. The operator has separately accepted the local R6 packet/runbook
after the actual terminal rehearsal. This records a human decision, distinct
from automated checks or per-action approvals. Publication remains pending;
do not describe the candidate as a published release or live-model acceptance.
Address an earlier contract only for a concrete dependency or regression.

The separate budgeted-assessment proposal, general session-view API and GUI
dashboard are deferred until the original milestones are complete. Accounting
actually required by R5 remains part of R5. Use judgment about the later ideas'
fit without introducing a new parallel milestone or weakening the architecture.
Live validation and credential setup are explicitly deferred until much later: all current development and
verification must use owned/mock fixtures, no paid or external provider calls,
and live execution disabled by default. This sequencing instruction does not
authorize activation, external targets or real credentials. PRs #34 and #35
are merged and stay closed.

The earlier baseline before PR #24 was `a87e5dd`, the merge of
[PR #23](https://github.com/0xsl0th/recon-cockpit/pull/23). The direct approval gate
requires proof from the fixed approval worker after single-use grant consumption,
binds it to the exact action/session/policy and preserves the original expiry.
The launcher checks freshness again after admission. The worker, selected
terminal, bootstrap and host/kernel remain trusted; scripted PTYs are mechanics
fixtures, not actual operator acceptance. Read
[launch-approval-witness.md](launch-approval-witness.md) for the ownership contract.

The merged mock planning slice leaves that boundary, the fixed ACK diagnostic and
R5a's TLS/status-only contract unchanged. `--assessment-planning-offline` requires
a workflow, both direct launch gates and a new private `--planning-ledger`.
Only a canonical repository-authored planning descriptor is released. The
existing workflow/evidence decision chooses eligibility, simulated usage must
settle before proposal release, and the full proposal must match the eligible
candidate. Missing/unknown usage retains a dispatch hold; known overruns settle
before refusal. All six existing cases and both lab backends remain the scope.
This is a finite mock planning bridge, not actual model planning or live acceptance.

## R5 owned TLS planning — merged checkpoint

The full portable suite passed **3,579 tests in 95.30 seconds**; the focused
Linux suite passed **36 tests in 126.77 seconds**, and full Linux regression
passed **466 tests in 904.45 seconds**. All reports have zero selected
failures/errors/skips, and no workers remained. Independent review found two cancellation bookkeeping
issues, now corrected and covered by regressions; the final review has no
remaining blockers. Python 3.11 grammar (189 files), dependencies, local links
and whitespace checks passed. All five
[hosted checks on implementation `30f2b2d`](https://github.com/0xsl0th/recon-cockpit/actions/runs/36657483576)
passed. Reports: `/tmp/recon-planning-tls-all-portable.xml`,
`/tmp/recon-planning-tls-focused-linux.xml`, and
`/tmp/recon-planning-tls-all-linux.xml`. See [verification.md](verification.md).

Hosted CI on documentation revision `a94edf5` passed four jobs but found an
existing 50 ms cancellation-test timer race on Ubuntu/Python 3.14. The test now
cancels at the scripted transport wait and checks that reservation/dispatch
already occurred. Production and Linux-selected tests are unchanged. All 232
focused portable session/authority/broker tests passed in 2.06 seconds, with
zero selected failures/errors/skips; independent review found no issue. Report:
`/tmp/recon-planning-tls-cancellation-portable.xml`. The PR checks show the latest
corrected revision; do not repeat full Linux verification solely for this test fix.

Revision `9d2387c` passed all Ubuntu jobs; macOS exposed a separate existing
invalid-READY fixture self-exit race during cleanup. That fixture now stays alive
until rejection and explicitly requires a reaped `SIGKILL` result. All 106
coordinator/broker IPC portable tests passed in 4.24 seconds, zero failures/errors/skips,
with independent review. Production cleanup is unchanged: the Darwin exception
race remains separate, rather than being suppressed. Linux is still the sole
isolated runtime. Details and report `/tmp/recon-planning-tls-ipc-portable.xml`
are in [verification.md](verification.md); the PR checks give final hosted status.

PR #25 is now merged. The current slice implements the integrated path's
offline evaluation against the preserved deterministic baseline. Keep live model acceptance pending and optional additions deferred.
Reuse the six-case scheduler, oracle, saved-evidence replay and semantic
fingerprints, with a separate versioned grader for TLS receipts and persisted
simulation accounting. Preserve the old baseline format and strict grader;
do not silently ignore new audit events. An unattended fixture policy must be
reported as approval not required by that selected policy, never as human
approval evidence. Actual operator review remains an R6 gate.

## R5 bounded offline planning — merged checkpoint

Full suites and the focused 24-case Linux run passed. The new 186 portable cases
cover release/privacy, usage recognition, money admission and lost acknowledgements,
session lifetime and CLI refusal. All six outcomes pass through both backends
and direct launch gates, with settlement before launch and read-only evidence
and ledger inspection. Python 3.11 grammar (181 files), dependencies, documentation
links and whitespace checks passed. Reports:
`/tmp/recon-assessment-planning-portable.xml` and
`/tmp/recon-assessment-planning-all-linux.xml`. See [verification.md](verification.md)
for commands and the corrected prepublication lost-ledger-acknowledgement case.
This follow-up checkpoint changes documentation only; runtime evidence is tied
to `bb9e42c`. Do not repeat full local suites solely for that documentation commit.

## R5 direct approval gate — merged checkpoint

Fresh full verification passed **3,196 portable tests in 85.76 seconds** and
**406 Linux tests in 716.31 seconds**, including all 44 new Linux cases. Both
JUnit reports have zero selected failures/errors/skips. Independent review found
no blocking issue and required no runtime correction. Python 3.11 grammar (175
tracked files), dependencies, local documentation links, whitespace and process
cleanup passed. Reports: `/tmp/recon-approval-witness-resumed-portable.xml` and
`/tmp/recon-approval-witness-all-linux.xml`. These complete runs supersede the
earlier operator-paused and server-interrupted runs. See [verification.md](verification.md)
for commands, coverage and trust limits.

## Earlier dependency-order merges

The preceding baseline was `38282b9` after the authorized dependency-order merges
of [PR #20](https://github.com/0xsl0th/recon-cockpit/pull/20)
and [PR #21](https://github.com/0xsl0th/recon-cockpit/pull/21). PR #20 merged as
`31d0a1f` at 05:36:33 UTC; #21 was retargeted to main and merged as `38282b9` at
05:38:13 UTC on 29 September. Reviewed heads were `007f24f` and `0298e1a`;
both had five passing hosted jobs and no outstanding comments. Their merge trees
match the reviewed trees exactly. Fresh review passed **277 portable tests in
0.74 seconds** and **57 Linux boundary tests in 79.30 seconds**, with no runtime
correction. Reports: `/tmp/recon-launchers-merge-review-portable.xml` and
`/tmp/recon-launchers-merge-review-linux.xml`.

All five [post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36527099212)
passed. The intermediate main run for #20 was superseded/cancelled by the #21
merge. PRs #16–#21 are merged; do not repeat them. This authorization does not
extend to subsequent PRs or live execution.

The completed `feature/launcher-audit-witness` slice independently verifies durable intent
inside the launcher using a direct one-way channel from the isolated audit writer.
Read [launch-audit-witness.md](launch-audit-witness.md) for ownership and trust limits.
`--require-launch-audit` requires all existing isolated launch/approval/audit options;
missing, forged, stale or mismatched witness data stops before admission/execution.
No new provider, tool, target, workflow case or GUI is introduced. This verifies
durability; independent approval authentication is the separate current slice.
Implementation `845a093`, published in [PR #22](https://github.com/0xsl0th/recon-cockpit/pull/22),
is now merged into main as `5584efe`. The
[PR checks](https://github.com/0xsl0th/recon-cockpit/pull/22/checks) give current
hosted status. That PR's follow-up changed documentation and made an existing
cancellation test deterministic, as recorded below.

## R5 direct audit gate — merged checkpoint

The launcher independently checks the selected writer's fsynced intent through
an exclusive one-way endpoint before admission or execution. This completes the
durability part of precondition verification. It preserves the existing fixture
and persistent-lab profiles, all six outcomes, card v2 and evidence inspection.
Defaults stay unchanged. This does not authenticate producer consent claims.

Full verification passed **3,146 portable tests in 86.26 seconds** and **362 Linux
tests in 626.77 seconds**, with zero selected failures/errors/skips. This includes
53 new portable cases and 35 Linux cases. Grammar, dependencies, local links,
whitespace and post-run process cleanup passed. Full reports:
`/tmp/recon-audit-witness-portable.xml`, `/tmp/recon-audit-witness-all-linux.xml`.
The focused 35-case Linux run passed in 64.86 seconds. See
[verification.md](verification.md) for commands, coverage and trust limits.

Hosted CI on `d5616d5` passed four matrix jobs but exposed an existing timer race
on Ubuntu/Python 3.14: cancellation could precede mock transport entry, so the
test's reserved-call assertion tested the wrong phase. The test now cancels at
the scripted transport wait and asserts that the call is already reserved. All
**214 offline-authority and broker tests passed in 0.98 seconds** after this
test-only correction (`/tmp/recon-authority-cancel-portable.xml`). Production is
unchanged; the full Linux evidence remained valid. All five hosted jobs passed
on corrected final head `1c26828`, which was reviewed and merged as recorded above.

## R5 persistent-lab launcher — merged checkpoint

Completed confined custody for the existing persistent lab: fixed owner lifecycle,
private management and namespace pins, separate admission and fresh executors.
All six workflow outcomes, card v2 and read-only evidence inspection are preserved.
The host validates completion continuity and only returns closure after verified
teardown, retaining last acknowledged counters even after a lost reply. The worker
resource helper preserves stricter inherited hard ceilings; SessionLimits retains
its public type and digest through a pure module.

Full verification passed **3,093 portable tests in 80.23 seconds** and **327 rootless
Linux tests in 559.12 seconds**, zero selected failures/errors/skips. This includes
34 new portable and 20 new Linux cases. Python 3.11 grammar, dependencies, local
links, whitespace and post-run process cleanup passed. Reports:
`/tmp/recon-owned-launcher-portable.xml`, `/tmp/recon-owned-launcher-all-linux.xml`.
See [verification.md](verification.md) for commands, earlier fixture corrections
and the distinction between scripted mechanics and actual operator acceptance.
Provider calls, real credentials and spend remain zero; live execution is disabled.

Hosted CI on publication head `3f0d7d1` passed all four Ubuntu jobs, but macOS
correctly exposed a new test's assumption that RLIM_INFINITY equals `-1`. The
fixture now uses `resource.RLIM_INFINITY`, as production already did. All 34
focused portable cases passed again in 0.17 seconds
(`/tmp/recon-owned-launcher-portability.xml`). Production is unchanged, so the
full Linux evidence remains valid; see the PR checks for the corrected head's
five-job portable matrix.

## Historical milestone gates before PR #26

This checklist is superseded by the current priority and next continuation.
Offline evaluation, packaging and the terminal rehearsal below are now complete;
do not repeat them as open work.

1. Keep PRs #24 and #25's verified planning slices closed. Review the current
   offline evaluation of the integrated path.
   Durable audit and fresh grant verification remain independent launch
   preconditions. A selected terminal/worker still cannot prove a human's
   identity or intent independently of that trusted environment.
2. Preserve the completed audit, approval, admission and launcher contracts.
3. Complete the current offline evaluation gate on the accepted integrated path. Neither fixed ACK nor mock responses
   establish real-model performance.
4. Keep real-model comparison visibly pending until explicit authorization and
   reviewed data/model/credential/spend settings. Continue offline meanwhile.
5. Then complete R6 corpus/evaluation consolidation, actual operator review,
   reproducible packaging and demonstration, disclosing any approved offline
   fallback. Keep accepted milestones closed and optional GUI/API scope deferred.

The completed planning integration preserves the fixed ACK diagnostic's contract
and the old deterministic workflow/evaluation baseline. Its separate owned TLS
profile releases only the approved canonical descriptor. Model output supplies
proposals, never policy, grants or finding truth. Raw evidence, credentials,
engagement text and real targets remain outside the release contract.

## R5 confined fixture launcher — merged checkpoint

In PR #20 alone, `--isolated-launcher` requires `--fixture` and all three isolated approval/audit/
admission options. A fixed worker holds the admission client, privately redeems
permits and constructs/supervises fresh executors. The host sends typed execution
requests, with no command, permit, reset or deadline-update interface. Admission
state remains in a separate worker. Startup, protocol, receipt or cleanup failures
stop without host fallback. Lost completion can follow execution and never permits
retry. Defaults and persistent owned-lab launching are unchanged.

Full verification passed **3,059 portable tests in 65.22 seconds** and **307 real
Linux tests in 520.50 seconds**, zero selected failures/errors/skips. This includes
71 new portable cases and 37 Linux cases, all six workflow outcomes with the
combined boundaries, and actual nested child cleanup during cancellation,
deadline expiry and concurrent requests. Python 3.11 grammar, dependencies,
local links and whitespace checks passed. Full JUnit reports:
`/tmp/recon-launcher-portable.xml` and `/tmp/recon-launcher-all-linux.xml`.
Detailed limitations and commands are in [verification.md](verification.md).
All work used owned/mock fixtures and synthetic credentials; external calls and
spend were zero.

Implementation `838c4a1` is published in
[PR #20](https://github.com/0xsl0th/recon-cockpit/pull/20), merged as `31d0a1f`.
The [PR checks](https://github.com/0xsl0th/recon-cockpit/pull/20/checks) are the
authoritative current hosted status. The follow-up checkpoint changes documentation
only; local runtime/test evidence remains tied to `838c4a1`. Hosted portable CI
does not replace local kernel verification. Do not repeat full local suites solely
for a documentation checkpoint. New runtime changes require appropriate verification. Merge and live execution still require
explicit authorization. Review on 29 September reran 243 portable tests and all
37 launcher Linux cases without correction; reports are
`/tmp/recon-launcher-review-portable.xml` and `/tmp/recon-launcher-review-linux.xml`.
All five [checks on reviewed head `007f24f`](https://github.com/0xsl0th/recon-cockpit/actions/runs/36520129501)
passed. Persistent-lab support is the dependent slice described above.

## R5 isolated launch admission — merged checkpoint

`--isolated-launch-admission` requires both isolated audit and approvals. A fixed
worker owns immutable bootstrap policy/profile/limits, step/output reservations
and short-lived one-use permits. The wrapper must admit and redeem every action
before calling an existing owned executor. Lost receipts, protocol faults,
replayed/expired permits and exhausted budgets stop without retry or refund.
Host counter resets cannot replenish worker state. Construction and dry-run are
inert for admission; existing defaults, capabilities and evidence schemas stay
unchanged. The host still owns the launcher and enforces consent/audit ordering.

Full verification passed **2,988 portable tests in 79.17 seconds** and **270 real
Linux tests in 472.98 seconds**, with zero selected failures/errors/skips. This
includes 105 new portable cases and 35 Linux cases, all six workflow outcomes
with the combined boundaries, and persistent owned-lab coverage. Python 3.11
grammar, dependencies, local links and whitespace checks passed. The JUnit
reports are `/tmp/recon-admission-portable.xml` and
`/tmp/recon-admission-all-linux.xml`; detailed scope and limits are recorded in
[verification.md](verification.md). No external provider call, real credential
or spend was used.

Implementation `8a215f3` is published in
[PR #19](https://github.com/0xsl0th/recon-cockpit/pull/19), merged as `e9c5496` on
29 September at 03:33:29 UTC after explicit operator authorization. Reviewed
head `b1fe045` passed all five PR jobs; the merge tree matches it exactly, and
all five post-merge main jobs passed. Fresh review reran 294 focused portable
tests and 35 Linux tests (49.07 seconds), with no runtime correction needed.
JUnit reports: `/tmp/recon-admission-review-portable.xml` and
`/tmp/recon-admission-review-linux.xml`. Live execution remains disabled.

## R5 isolated approvals — merged checkpoint

`--isolated-approvals` selects a fixed Linux worker for terminal review and
ephemeral grant issuance/consumption. It composes with the merged audit worker
for authority sessions and owned assessments. Bootstrap passes only the fixed
policy/session/deadline and one terminal descriptor. There is no boolean approval,
reset, policy-update, reconnect, executable selection or local fallback operation.
The worker flushes old input, displays canonical review without rationale and
requires a fresh random challenge. Grants bind the action/policy and worker's
session, expire monotonically and burn on attempted use. Terminal input injection,
new file opens and socket/process creation are denied after bootstrap.

Construction and dry-run are inert for approvals; noninteractive execution cannot
approve. Service faults permanently stop authority work. Cancellation/deadlines
cover review and consumption, and cleanup reaps the worker. Policy authorization,
accounting and launch decisions remain host-owned; full independent launch
authorization is still pending R5 work. Scripted PTYs are owned mechanics
fixtures, not evidence of actual human approval or operator acceptance.

The final full suites passed **2,883 portable tests and 235 real Linux tests**,
with zero selected failures/errors/skips. This includes 73 additional portable
cases and 41 new Linux cases covering combined coordinator, approval, audit and
executor behavior and all six existing workflow outcomes. See [verification.md](verification.md)
for commands, runtimes, JUnit paths and limits. Implementation `0055f61` is
published in [PR #18](https://github.com/0xsl0th/recon-cockpit/pull/18), now merged
as `2c02c21` after explicit operator authorization. Five final PR checks and five
post-merge main checks passed. Review reran 299 focused portable tests in 1.00
second and 41 Linux tests in 42.38 seconds; JUnit reports are
`/tmp/recon-approvals-review-portable.xml` and `/tmp/recon-approvals-review-linux.xml`.
No runtime correction was needed. Live execution remains disabled.

## R5 confined audit persistence — merged checkpoint

Read [isolated-audit.md](isolated-audit.md). The explicit `--isolated-audit`
option transfers one verified append descriptor to a fixed Linux worker for
authority sessions and owned assessments. The host closes its copy and waits
for an identity/sequence/event-bound acknowledgement after each write and fsync.
Missing acknowledgements poison the sink; no retry or local fallback exists.
The worker cannot create sockets/processes, reopen files, clear append mode,
truncate or punch holes in existing records. Limits, private-file checks and
process cleanup remain enforced. Audit JSONL and evidence schemas are preserved.

Approval issuance, authorization, launch decisions and event truth remain
host-owned; neither remote immutable storage nor full host-compromise resistance
is claimed. This is the first remaining R5 authority-separation slice, not the
completion of all R5 work. Existing provider gates, credentials, endpoints and
cost controls are unchanged. All provider verification remains offline.

Verification and publication evidence for this implementation is recorded in
[verification.md](verification.md): **2,810 portable and 194 real Linux tests
passed**, with zero selected failures/errors/skips. PR #17 initially targeted
the planning branch, then merged into main after PR #16; that publication
sequence is complete.

## R5b controlled provider call — merged checkpoint

The operator authorized review and merge of PR #14, followed by the first narrow
provider integration and a new focused PR. PR #14 was merged as `3a0cb67` on
28 September; all five [main portable jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/36498947841)
passed. The integration was developed on `feature/controlled-provider-call`
from that merge and is now merged into `main` as described below.

The operator then explicitly required all development and verification to remain
offline with owned/mock fixtures, no paid or external provider calls, and live
execution disabled by default. These constraints remain in force. No real key
was read and no external provider request was sent.

Read [controlled-provider-call.md](controlled-provider-call.md). The implementation
adds a fixed synthetic ACK request, explicit price/call admission, durable ledger
dispatch and usage settlement, a private Linux credential worker and one pinned
TCP capability. A second seccomp layer prevents reconnecting that capability or
creating another socket. Only the trusted host opens the literal-IP connection;
no live application command, assessment integration or GUI is enabled.

Final local review and verification are recorded in [verification.md](verification.md):
2,750 portable and 166 Linux tests passed with no selected failures/errors/skips.
The operator subsequently authorized review and merge of
[PR #15](https://github.com/0xsl0th/recon-cockpit/pull/15). Review found no blocking
issue; 291 focused portable and all 18 owned TLS Linux tests passed again.
The reviewed head `7c31c31` (implementation `50f51b2` plus documentation) merged
as `1369166` on 29 September. The merged tree matches that reviewed head, and all
five [main portable jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/36504726956)
passed. Local `main` was synchronized and clean. Do not repeat this merge or
restore the old branch's publication instructions. Activation and live billing
validation still require a later explicit operator instruction.

## R5b provider cost ledger — historical publication checkpoint

The operator approved implementing the monetary ledger and spending controls
after reviewing a future GUI reference, then authorized final review, commit and
push. The implementation branch is `feature/provider-cost-ledger`, based on
merge `0a9697f` for PR #13. The earlier pilot-named branch was only the development
starting point; it contains no live pilot implementation.
The R5a PR is therefore merged in this checkout; its older open-PR checkpoint
below is historical. No R5b PR has been opened at this checkpoint.
No GUI, external provider transport, credentials or paid calls were added.

Read [provider-cost-ledger.md](provider-cost-ledger.md). The implementation adds
integer microUSD price/usage contracts, an explicitly created private SQLite
ledger, atomic account/engagement/session/agent/action caps, estimates separate
from reservations and actual charges, one-time dispatch claims, durable budget
denials, unknown-cost retention, idempotent settlement and billing corrections.
The read-only report API supplies consistent scope/period/model totals for the
future GUI. Existing R5a synthetic accounting and the owned evaluation remain
separate. Reopening cost storage never restores execution or approvals.

Operator controls are available through
`python -m recon_cockpit.secure_agent.cost_cli --help`; the standalone
`scripts/secure_agent_cost_demo.py` writes only explicitly labeled simulated
accounting when given a fresh `--ledger` directory. Final private demo:
`.secure-agent/cost-ledger-demo-20260928-final`. It shows 25 microUSD simulated
actual, 300 held and 175 available under a 500 microUSD engagement cap, with one
unresolved call and a durable denial. Read-only CLI inspection preserved all
file bytes and mtimes. No real provider calls occurred.

The focused suite passes **129 tests**, including independent process races,
one-time dispatch, forced process exit during reservation/settlement, failed
journal writes, receipt replay, billing corrections, overruns, all budget levels
and safe read-only CLI inspection. Publication review reproduced and fixed a
POSIX lock-loss bug from closing an extra database descriptor; metadata-only
identity checks now preserve another connection's active lock. Inherited handles
also fail before acquiring a lock or attempting rollback/close in a child process.
The final full portable suite passes **2,677
tests**, 148 deselected, with no selected failures/errors/skips. See
[verification.md](verification.md). This accounting-only slice changes no namespace,
network, credential, parser or execution runtime; Linux isolation tests are not
rerun as evidence for a new boundary.

GitHub `main` still points to `0a9697f`; its
[hosted portable run](https://github.com/0xsl0th/recon-cockpit/actions/runs/36460798711)
passed. No open PR exists for this work. Next step: a focused R5b PR against
`main`, then hosted checks and review before any merge. The current workflow
runs five jobs on PRs to main; this branch is not in its push-trigger allowlist.
Inspect the remote branch head and PR state before continuing publication.
After R5b, design the real-provider broker integration using its financial contract.
Paid operation still needs explicit data/model/credential/spend settings and a
reviewed provider-specific token bound, usage adapter and egress topology.
Do not silently attach the legacy runner or convert synthetic fixture units into
real provider charges. Previous PR merge approvals do not authorize a new merge.

## Recovered R5a work — historical checkpoint, verified 26 September

Current branch: `feature/isolated-provider-foundation`, based on `ba3951e`.
The operator approved the proposed focused R5a PR with “sounds good, go ahead!”
at 04:51 UTC, then requested continuation after the laptop unexpectedly powered
off. Seven untracked implementation/documentation/test files survived. The
interrupted broker and host runtime had not been saved; they are now implemented.
Git object checks found no corruption. Main checkpoint `ba3951e` passed all five
[hosted portable jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/36095234761).

Scope: [owned TLS provider foundation](provider-foundation.md), using only
disconnected fixtures, synthetic credentials/model/cost units, status-only data
release and the existing networkless parser. No tool execution or live-provider
integration is added. The 18-run evaluation contract is preserved. Verification
and independent review are complete. The authorized focused
[PR #13](https://github.com/0xsl0th/recon-cockpit/pull/13) is open, with
implementation commit `7125c99`. Inspect its current hosted checks when continuing.
Earlier PR-specific merge authority does not cover this new PR; it remains open
for the operator's merge decision.

The 26 September review found and fixed two failures: cancellation while collecting
owner counters could mask the stop with an invalid receipt, and temporary audit
directory setup errors could escape the demo's safe JSON reporting. Independent
runtime, contract and portability reviews found no remaining blocker. All **16
provider Linux tests passed** in 17.48 seconds, including both new cancellation
cases (`/tmp/recon-provider-review-linux.xml`, no failures/errors/skips).
The standalone demo passed with all ten transport and seven parser checks true,
one connection/request and reaped owner/worker processes. Its private audit is
`.secure-agent/provider-foundation-20260926/audit.jsonl`; it reserved one call,
1,024 output tokens, 3,060 request bytes and 5,208 synthetic cost units.

The final portable suite passed **2,548 tests**, 148 deselected, in 87.89 seconds;
the full Linux suite passed **148 tests**, 2,548 deselected, in 345.51 seconds.
Both reports contain no failures/errors/skips: `/tmp/recon-provider-final-portable.xml`
and `/tmp/recon-provider-linux.xml`. The existing 18-trial baseline passed within
the Linux suite. Compile, dependency, Python 3.11 syntax, documentation links and
whitespace checks passed. See [verification.md](verification.md).
A coding-service restart interrupted earlier runs; they were restarted after
confirming no matching processes survived. The implementation is committed and
pushed to the feature branch; the publication checkpoint changes documentation
only. Do not restore an interrupted assessment or approvals.

**R1, R2, the smallest R3 discovery-to-HTTP slice, the first R4 card/engine,
the post-merge CI correction, the persistent owned lab foundation and the
repeatable evaluation runner are reviewed and merged. PR #12 is complete.**
Read [evaluation.md](evaluation.md), [owned-lab.md](owned-lab.md), [workflow-assessment.md](workflow-assessment.md),
[verification.md](verification.md) and [roadmap.md](roadmap.md). Inspect Git and
current main checks before more work. Do not repeat these completed slices or
their merges; continue R5 from the completed R5a/R5b baseline above.

An earlier recovery found a clean checkout at `401cbe1`. Saved conversation and
GitHub state confirmed that PR #9 had already been reviewed and merged with
operator authorization before the session limit. Git object checks found no
corruption. Local `main` was fast-forwarded to `8673dc0`; its tree exactly matches
the reviewed head. The interrupted local sync and checkpoint are now recovered.

## Saved state

- Workspace: `/home/sloth/Code/recon-cockpit`, Kali Linux x86_64, normal user.
- Prior completed checkpoint: `main`, synchronized with the PR #12 merge `ff5f76a`.
  The operator authorized implementing the 18-run baseline,
  independent grading and aggregate reports, with cleanup/isolation/accounting
  verification before opening a PR. The operator subsequently explicitly
  authorized reviewing and merging PR #12 into main after checks pass.
- [PR #12](https://github.com/0xsl0th/recon-cockpit/pull/12) is **merged**, at
  `ff5f76a6f81327b7ef184d7cfefff29ff087dd47` on 25 September, 04:35:39 UTC.
  Implementation commit: `665fcb7892ce5f839a1391c5ff7a338d054c0e29`.
  The full local suites and final CLI baseline passed before the PR was opened.
  Reviewed head `e23016a500b6fa24e36f783f4e2ba93662740321` includes the audit fix.
  All five [final PR CI jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/36070544788)
  passed on Ubuntu Python 3.11–3.14 and macOS Python 3.14. GitHub showed no
  outstanding review comments or merge conflicts. The merge was guarded by the
  exact reviewed head, and its tree matches that head. Do not repeat this merge.
  All five [post-merge main jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/36095076635)
  also passed. The publication checkpoint changes documentation only; inspect
  its current main checks when continuing.
  Final review found that missing audit context could still pass grading.
  Strict per-event fields, typed steps and action identity bindings now reject
  that corruption; the regression covers 73 mutations. The independent reviewer
  confirmed the fix and found no remaining blocker. Runtime review also found
  no blocker in scheduling, deadlines, cancellation, cleanup or storage.
- The new runner uses `--evaluate-owned-lab --evaluation-dir NEW_DIRECTORY`,
  explicit unattended owned-fixture policy, six cases times three repetitions,
  fresh authority/lab/broker identities and durable reservations before each trial.
  `--inspect-evaluation` independently regrades all saved evidence without writes
  or execution. See [evaluation.md](evaluation.md) for the contract and commands.
- Full verification passed **2,300 portable / 132 real Linux tests**, no selected
  failures/errors/skips. Compile, dependency, Python 3.11 syntax, relative link
  and whitespace checks passed. Linux tests include the full 18-trial baseline,
  process/namespace observations, read-only inspection, active/between-trial
  cancellation and an absolute batch deadline. See verification.md for exact
  commands and measured results.
- The audit fix passed the full 2,300-test portable suite and reran all six
  Linux evaluation tests, including another 18-trial baseline. The prior 126
  other Linux results apply to the unchanged runtime. Review JUnit reports:
  `/tmp/recon-evaluation-review-portable.xml` and
  `/tmp/recon-evaluation-review-linux.xml`.
- Evaluation JUnit: `/tmp/recon-evaluation-portable.xml` and
  `/tmp/recon-evaluation-linux.xml`. Final private baseline:
  `.secure-agent/evaluation-baseline-20260924/report.json` and `report.md`.
  Actual CLI: **18/18 passed in 72,004 ms**, 51 executions, 45 successful actions,
  12 correct abstentions, all cleanup/isolation grades passed and complete resource
  accounting. Read-only CLI inspection exactly reproduced the report without any
  file byte/mtime changes. See verification.md for measured totals and commands.
  Earlier `.secure-agent/evaluation-development-1`
  used an intermediate schema and is not the final publication baseline.
- [PR #11](https://github.com/0xsl0th/recon-cockpit/pull/11) is **merged**, at
  `7f316ce77f5c812477290e1b293d06d4afd88d53` on 24 September, 00:42:55 UTC.
  Reviewed implementation head `15583161e09658ef808160ecf308ab74e82b60c8`
  passed all five [PR CI jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/35939526013).
  Bounded launcher/evidence/portability reviews found no blocker; GitHub had no
  outstanding reviews or comments. The operator explicitly authorized commit,
  push and merge if checks passed. The exact-head-guarded merge succeeded and
  its tree matches the reviewed head. Do not repeat this merge.
  All five [post-merge main jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/35939661436)
  also passed. The final publication checkpoint changes documentation only;
  inspect its current main checks when continuing.
- [PR #10](https://github.com/0xsl0th/recon-cockpit/pull/10) contains the test-only
  correction and recovered checkpoint. It was reviewed and merged with operator
  authorization as `2b3527ec20c8a8b9dd30f5e7aa000bb48aa51fc3`, 23 September at
  14:14:09 UTC. Reviewed head `9fef498` passed all five PR jobs; all five
  [post-merge main jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/35872690851)
  passed. Its merge tree matches the reviewed tree. Do not repeat this merge.
- The operator then requested design and implementation of the persistent owned
  lab foundation. Contract: [owned-lab.md](owned-lab.md). Fixed-case service at
  `127.0.0.1:8080` persists for one authority session, with fresh nested executor
  sandboxes and pinned lab namespaces. Reset destroys/recreates; no resume.
  `--workflow-assessment CASE --owned-lab` selects card v2 and strict identity,
  counters and closure evidence. Live calls and external targets stay disabled.
  Full verification: **2,226 portable and 126 real Linux tests passed**, zero
  selected failures/errors/skips. Linux coverage combines the full 124-case run
  and two descriptor tests subsequently classified as Linux-only. Compile,
  dependency and whitespace checks passed. Bounded runtime/evidence reviews found
  no remaining blockers; see verification.md for exact commands and limitations.
- Lab JUnit: `/tmp/recon-owned-lab-portable-final.xml`,
  `/tmp/recon-owned-lab-linux.xml`, `/tmp/recon-owned-lab-descriptors-linux.xml`.
  Private sample: `.secure-agent/owned-lab-a-20260923/report.json` and `report.md`,
  plus `.secure-agent/owned-lab-a-20260923-audit.jsonl`. Case a validated using an
  explicit unattended owned-fixture policy, not human approval. All three actions
  share one lab instance; counters advance `(1, 0)`, `(2, 1)`, `(3, 2)`. Read-only
  CLI inspection preserved all bytes and mtimes and reported no integrity issues.
- [PR #9](https://github.com/0xsl0th/recon-cockpit/pull/9) is **merged**, at
  `8673dc0ac02a762dae08f2533885d2246fb04e2a` on 23 September, 01:29:31 UTC.
  Reviewed head `401cbe1` passed all ten branch/PR portable jobs across Ubuntu
  Python 3.11–3.14 and macOS Python 3.14. Bounded engine/provider and evidence
  reviews found no blockers; the root's focused regression run passed 289 tests.
- Four of five post-merge main jobs passed. Ubuntu Python 3.12 exposed a
  cancellation-test race: the 30 ms timer could fire after reserving the broker
  allowance but before consuming the scripted reply. Production correctly stopped
  without consuming that reply. PR #10 makes cancellation occur during the
  intended offline delay. See [verification.md](verification.md) for the failed
  run and correction verification; production code is unchanged.
- Correction verification: **2,134 portable tests passed, 109 deselected**;
  JUnit records zero failures, errors or skips. Focused broker tests passed 107
  cases. The earlier 109 real Linux results still apply to unchanged production;
  kernel tests were not rerun for this test/documentation-only correction.
- R4 adds a repository-authored versioned card, immutable deterministic
  decisions, durable proposal/terminal events and independent read-only replay.
  The CLI selector is `--workflow-assessment`; existing R2/R3 modes remain.
- Full R4 verification: **2,134 portable / 109 real Linux tests passed**, no
  selected failures, errors or skips. Compile, dependency and whitespace checks
  passed. See verification.md for commands, timings and reviewed limitations.
- R4 JUnit: `/tmp/recon-workflow-portable.xml` and
  `/tmp/recon-workflow-linux.xml`. Temporary evidence may disappear on reboot.
- Private R4 sample: `.secure-agent/r4-example-a/report.md` and `report.json`,
  plus `.secure-agent/r4-example-audit.jsonl`. The real CLI validated case a
  with three linked executions, three decisions and a terminal explanation.
  Read-only CLI inspection preserved every file's bytes and modification time.
  The explicit unattended owned-fixture policy is
  `/tmp/recon-r4-owned-fixture-policy.json`; this is not human approval evidence.
- [PR #8](https://github.com/0xsl0th/recon-cockpit/pull/8): reviewed head
  `124300a`, merged as `b1c7b67` on 22 September with operator authorization.
  The merge tree exactly matches the reviewed files. Implementation: `ad30297`.
  All ten branch/PR checks and all five post-merge main jobs passed; see
  verification.md. Inspect current main checks for the documentation checkpoint.
- Bounded premerge reviews covered isolation/authority, workflow/schema and
  evidence/recovery. No blockers were found; fresh focused checks passed.
  The existing full portable/Linux results remain valid for the production code.
- Initial hosted CI exposed a macOS assumption in a new portable refusal test.
  The test now explicitly exercises both Linux host-namespace refusal and
  non-Linux refusal. Production files and Linux verification are unchanged.
- Previous R3 verification: **1,977 portable tests and 96 real Linux
  integrations**, zero selected failures/errors/skips. Compile, dependency and
  whitespace checks passed. See the exact commands/timing in verification.md.
- JUnit: `/tmp/recon-discovery-portable.xml` and `/tmp/recon-discovery-linux.xml`.
  Temporary evidence can disappear on reboot; measured results are documented.
- Private sample: `.secure-agent/r3-example-a/report.md` and `report.json` plus
  `.secure-agent/r3-example-audit.jsonl`. It validates seeded case a using an
  explicit unattended owned-fixture demo policy, not human approval. Read-only
  CLI inspection found no issues and changed no file bytes or mtimes.
- [PR #6](https://github.com/0xsl0th/recon-cockpit/pull/6): reviewed R1
  `cfde4ed`, merged as `07af513` on 17 September.
- [PR #7](https://github.com/0xsl0th/recon-cockpit/pull/7): reviewed R2
  `1312acf`, updated as `33edceb` without file changes, merged as `f85aaa9`.
  All ten premerge branch/PR checks and five subsequent main jobs passed.
- [PR #5](https://github.com/0xsl0th/recon-cockpit/pull/5) is merged as `bf3a359`.
  Prior R2 verification was 1,849 portable / 78 Linux; do not present it as R3.
- Old `/tmp/recon-pr2-review` and `/tmp/recon-pr3-review` worktrees disappeared
  after an earlier reboot; their stale registrations were not pruned.
- SSH push authentication is still unavailable. Explicit HTTPS push with the
  GitHub CLI credential helper succeeded; no credentials entered artifacts.

## Implemented R3 scope

`--discovery-assessment a` selects one fixed `tcp_connect` action, then gates the
existing two-GET workflow using actual evidence. The explicit discovery executor
only permits the owned `127.0.0.1:8080` topology. TCP uses one second and reserves
1,024 output bytes, with no payload, banner, DNS, retry or port list. Original
fixture/routed HTTP modes reject TCP; the old policy remains HTTP-only. A separate
example policy allows both capabilities and requires fresh approvals.

Each action creates a fresh namespace with the same seeded topology. Reachability
does not prove HTTP identity or persistent service continuity. Three-step defaults
reserve 3,072 tool bytes; the broker separately reserves three calls/3,072 output
tokens. Reports link TCP and both HTTP observations, remain drafts, and preserve
read-only crash inspection without execution or grant restoration. R3 is not a
multi-service/Nmap adapter, general capability registry or workflow engine.

## Implemented first R4 slice

One card, `owned-discovery-http-assessment` version `1`, binds the existing
TCP-to-HTTP path to exact actions, parser gates and evidence requirements. Each
decision is durably recorded before any synthetic provider exchange. Execution
starts require a matching preceding proposal; reports distinguish proposals
from executions and explain evidence, approval, failure and budget stops.
The manifest and every decision bind the canonical card digest.

`owned-workflow-assessment-v1` bundles replay observations from artifacts and
recompute decisions during inspection. Corrupt, reordered, missing or unfinished
evidence remains inconclusive. There is no resumption of an assessment, dynamic
card loading, external knowledge import or new execution capability. The original
`--fixture` profile retains per-action services. The new `--owned-lab` profile
uses card v2 and the session-scoped service lifecycle described in [owned-lab.md](owned-lab.md).

## Intent and constraints

Build authorized pentest workflows with specialist engines inside enforced
security boundaries. Challenge 4, security of autonomous agents, is the focus.
Planning uses synthetic responses.

- Keep live calls and credential lookup disabled. Live work needs reviewed
  operator data/model/credential/spend settings. Real VPN tests remain deferred.
- Use owned fixtures; preserve scope/policy, OS isolation, fresh grants, budgets,
  cancellation/deadlines, audit-before-execution and fail-closed behavior.
- Never connect legacy host execution, arbitrary shell, credentials, broad mounts
  or Docker sockets to agents. Do not change host networking to pass tests.
- The explicit audit, approval and admission options use separate confined
  workers for persistence, grants and fixed policy/resource decisions. The opt-in
  launcher owns nested admission, executor supervision and persistent-lab
  lifecycle/namespace pins. Direct audit and approval gates verify their workers'
  preconditions; the host still owns assessment authority and selected policy.
  Hashes detect inconsistency, not host-owner tampering. R1 callback and R2 HTTP
  framing limits remain documented.
- The operator-authorized PR #70 merge is complete. PRs #6–#30 and #32–#70
  stay closed; proposal PR #31 remains separate. Additional implementation, later merges, submission,
  messages, paid calls and external targets need their corresponding instruction.

## Next continuation

1. Continue C17 in `/tmp/recon-nuclei-git-head` on
   `feature/nuclei-git-head-coverage`; preserve accepted main `1cfbf8b` and C16.
2. Complete the native and portable acceptance matrices and independent replay.
   Require useful matches and nonmatches, original owner/native agreement, no
   unnecessary refusals and all existing enforcement/authority gates.
3. Preserve the missing-module refusal and corrected retry separately from final
   clean-source validation; keep source hashes, actual evidence, cost and latency
   current. Private work is `.secure-agent/nuclei-git-20261008/`.
4. Open a PR and leave it unmerged for review. Select the next coverage gap only
   after C17 acceptance, without reopening C1–C16 or completed R5/R6/GUI work.
5. Keep credentials, paid/live models, external targets, deeper workflows and
   comparative benchmarks deferred; preserve proposal/PDF, GUI mocks and C9 history.

## Recovery and verification

```sh
git status --short --branch
git log -5 --oneline --decorate
git diff --stat
git diff --check
.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short
```

Run kernel tests outside the coding sandbox as the normal user. Use fresh audit
and assessment paths. Do not rerun all tests solely to verify saved docs. Inspect
existing bundles without restoring old approvals, deadlines or budgets.

## Remaining decisions

Reference identities are resolved: Enrique Folte, PentestMonkey,
PayloadsAllTheThings, GTFOBins, LOLBAS, HackTricks and Hack The Box. Links and
categories are in the roadmap; do not repeat clarification.

Enrique Folte confirmed that he is the sole human participant and project contact,
with Codex providing development assistance under human review. No additional
members or institutional affiliation are declared. Do not repeat the team question.
Proposal deadline: **15 November 2026**. Final development: **20 May 2027**.

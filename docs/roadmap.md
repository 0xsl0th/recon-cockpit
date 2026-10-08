# Roadmap — secure AI pentesting workflows

**Current product forecast: 8 October 2026.** See the [consolidated roadmap and PR estimate](product-roadmap.md).
The historical planning baseline below began on 15 September 2026. This is a development plan, not a list
of implemented capabilities. Start the next session with
[continue-here.md](continue-here.md).

**Current slice — PR #73 accepted; C18 DNS MX and the finite coverage contract (8 October 2026).**
The finite [coverage checklist](secure-tool-coverage.md) is closed: B0–B8 meet
G1–G6, with 20 accepted secure capabilities backed by 11 external programs.
[PR #46](https://github.com/0xsl0th/recon-cockpit/pull/46) also accepted the
[read-only catalog](secure-tool-catalog.md) at `0d5cbdc`; all five final and
post-merge checks passed. Preserve its recipes and the accepted tool contracts.
Interactive support remains distinct from secure execution, and these bounded
milestones do not establish the full professional product.

[PR #47](https://github.com/0xsl0th/recon-cockpit/pull/47) accepted the separately
versioned [service/web workflow](service-web-assessment.md) at `fc477d0`:
3/3 useful native workflows, 9/9 actions, 18/18 blocked destination witnesses,
zero unnecessary refusals/provider calls/cost and unchanged evidence replay.
Preserve its three fixed actions and predecessor gates. All five final checks
passed; post-merge checks passed after one macOS fixture-race retry. PR #48 fixed that test's peer lifetime without weakening production cleanup.

Enrique selected **internal networks with web services** as the first professional
engagement focus and authorized the following implementation order. The eventual
40+ tool ambition is a coverage target, not a prerequisite for a useful GUI or a
claim that today's bounded fixtures support professional engagements.

| Priority | Implementation | Completion and boundary |
| --- | --- | --- |
| 1 — accepted in PR #48 | [Configurable owned HTTP/SSH assessment](configurable-owned-lab.md) | Two varied operator manifests; actual Nmap → headers and Nmap → public SSH key results; exact scope and per-action isolation; all seven gates; cancellation, closed owners and unchanged evidence replay. First slice uses two disconnected endpoint fixtures, not a shared or attached real network. |
| 2 — accepted in PR #54 | Shared CLI/GUI application services, then initial GUI | Scope, session state, proposals/approvals, cancellation, evidence and report views use the same authority path; begin from both [Swiss Industrial references](gui-design-references.md). No direct command execution or restored approvals in GUI code. Review any real-lab attachment as a separate boundary change. |
| 3 — current, finite coverage tranche | Complete T01–T06 in the [professional-v1 coverage contract](professional-v1-coverage.md) | C18/T01 DNS MX is in progress. T02 TLS-posture feasibility follows; candidate engine choice remains reviewable. Every task needs actual useful owned execution, structured results, evidence, enforcement and G1–G6. Keep interactive support distinct and preserve all required outcomes. |
| 4 — later | Professional engagement lifecycle and authorized operations | Rules of engagement, secret/session custody, authenticated and intrusive actions, reporting/retest and broader compatibility need explicit design and relevant authorization. |

[PR #48](https://github.com/0xsl0th/recon-cockpit/pull/48) merged as `5f046eb`
after review and all five final portable jobs passed. Its two varied manifests
completed 8/8 legitimate actions and blocked 24/24 listening forbidden destinations.
That slice brought the catalog to 23 accepted profiles using the same 11 external programs.
Keep this scope closed and preserve its existing contracts.

Priority **2a is accepted** in [PR #49](https://github.com/0xsl0th/recon-cockpit/pull/49),
merged as `db42cd1` after review and five passing final checks. The
[shared service](shared-assessment-service.md) owns immutable requests, mandatory
isolated authority services, detached views and single-use cancellation/cleanup.
Read-only inspection preserves existing report semantics. All eight targeted
native cases and 9,722 portable tests passed; accepted contracts remain closed.

Priority **2b is accepted** in [PR #50](https://github.com/0xsl0th/recon-cockpit/pull/50),
merged as `7efa9d8` after fresh review and all five final checks. All five
post-merge jobs also passed. The [desktop](desktop-gui.md) has both themes,
strict scope import/validation/private export, read-only saved-evidence replay,
distinct draft/recorded scope, bounded literal observations and tested close
behavior. Its accepted local evidence covers 9,823 portable and six actual Tk cases.

Priority **2c is accepted**, with these completed steps:

- **Session lifecycle — accepted in [PR #51](https://github.com/0xsl0th/recon-cockpit/pull/51).**
  Merge `972afac` matches the reviewed tree; all five final and post-merge checks
  passed. Fresh dry-run start, observed decisions, cancellation, cleanup and
  independent replay passed 9,837 portable and 11 actual Tk cases. That slice used `execute=False`;
  dry runs cannot count as useful completion.
- **Isolated graphical reviewer — accepted in [PR #52](https://github.com/0xsl0th/recon-cockpit/pull/52).**
  Merge `21054db` matches the reviewed tree; fresh reviews and all five final/post-merge
  checks passed. Accepted evidence covers 9,949 portable and 125 native cases,
  4/4 useful actions and 12/12 blocked destination checks with zero provider cost. The
  [reviewer runbook](graphical-approvals.md) documents its separate window, fresh
  challenge, one-use exact-action grants, original launch witness and graph-only
  audit records. The opt-in shared-service path exercises the existing four-action
  owned workflow through all seven gates. Native scripted input verifies behavior;
  it does not establish personal approval. Existing terminal behavior remains the
  default. Runtime support is currently the documented local Linux/X11 layout.
- **Personal walkthrough — accepted in PR #53, merged as `0539c15`.** PR #53 fixes
  phrase copying and preloads the fixed Tk focus/word helpers before filesystem
  sealing. Fresh review, 51 native and 112 focused portable tests, and all five
  final and post-merge hosted checks passed. Copy/paste remains separate from explicit approval, with
  unchanged bindings and limits. Earlier unsuccessful trials remain recorded.
  After confusing multi-case instructions, the owner separately confirmed approval,
  denial and pending-review Ctrl+C using stricter one-step/60-second/8,192-byte
  requests. All three independently replay unchanged with closed fixtures and no
  provider calls/cost; denial and cancellation launched no tool. These controls
  tests are complete, and their smaller assessment outcomes remain incomplete.
  The subsequent full personal run completed 4/4 useful actions in 45,642 ms with
  four consumed grants and four successful executions, closed fixtures, unchanged
  clean replay and zero unnecessary refusals/provider calls/cost. The owner said
  "ok this time it worked". The original four-step/60-second/26,624-byte limits
  remained fixed. Retain earlier incomplete trials; do not repeat accepted checks.
- **Desktop execution — accepted in [PR #54](https://github.com/0xsl0th/recon-cockpit/pull/54).** An explicit
  **Execute owned lab** control uses the same shared service and isolated graphical
  reviewer for the existing disconnected HTTP/SSH fixtures. Dry run remains a
  separate operation. Requests freeze scope and require fresh per-action approval;
  both start controls and inspection remain unavailable during run/cleanup/replay.
  Local validation passed 9,981 portable and 70 native Linux/Tk cases. Typed and
  clipboard sessions each completed 4/4 useful actions and blocked 12/12 forbidden
  destinations. Denial without launch, pending cancellation/close, partial-work
  cancellation, closed processes and unchanged replay passed. Both themes passed
  at 1120×720. Reviewed head `43321da` merged as `7de63a4` with an identical
  tree; all five final and post-merge jobs passed. See the [verification record](verification.md#desktop-execute-owned-lab--7-october-2026).
  The original four-step/60-second/26,624-byte limits and all authority gates remain.
  Preserve PR #53 personal acceptance; automated desktop input is separate evidence.
  Real network attachment, restored grants and professional readiness stay out of scope.

The initial owned GUI milestone is closed. **C1 Redis/SNMP coverage is accepted in
[PR #55](https://github.com/0xsl0th/recon-cockpit/pull/55)**: reviewed head `8786308`
merged as `9786a6b` with an identical tree; all five final and post-merge checks
passed. Its 10,413 portable and 63 native cases, 3/3 ordinary completions,
32/32 blocked destination witnesses and unchanged evidence replay remain accepted.
That slice brought main to 25 bounded profiles using 13 external programs.

**C2 PostgreSQL/MySQL pre-authentication TLS is accepted in
[PR #56](https://github.com/0xsl0th/recon-cockpit/pull/56).** Reviewed head `d072d04`
merged as `9603a54` with an identical tree after independent reviews and all five
final hosted jobs passed 10,776 tests each. All five post-merge jobs also passed.
Its test-only macOS correction preserved real TLS assertions and passed 224
focused fixture/lab cases; production and native tests stayed unchanged. Preserve
28 native cases, 2/2 ordinary TLS completions, zero unnecessary refusals, 24/24
blocked destinations and 33 unchanged accepted evidence replays. The
[runbook](database-tls-tools.md) keeps both profiles at a verified fixture TLS
handshake and clean close: no database login, SQL, readiness or product-identity
claim. That slice brought main to **27 profiles using 13 programs**.

**C3 bounded HTTP application fingerprinting is accepted in
[PR #57](https://github.com/0xsl0th/recon-cockpit/pull/57).** The
[coverage checklist](secure-tool-coverage.md#successive-product-coverage-batches)
and [WhatWeb runbook](whatweb-tools.md) define one fixed owned HTTP GET and five
passive plugins: Title, HTTPServer, X-Powered-By, MetaGenerator and JQuery. Exact
runtime files and a compiled guard bound requests, redirects, response input,
plugins and execution. Structured output means only untrusted application hints;
a complete no-hints response must count as useful completion, not technology
absence. Ordinary usefulness must be 2/2 with zero unnecessary refusals, with
separate hostile-metadata/meta-redirect trials and eleven total scenarios.
The complete portable suite passed 11,109 tests with no failures/errors/skips
(914 integration cases deselected). Local native validation passed 39 tests:
17 C3 cases and 22 accepted-tool regressions. All eleven scenarios retained their declared meanings, one
connection/GET, closed owners and unchanged replay; 22/22 forbidden destinations
blocked. Independent clean-source trials completed 2/2 ordinary and 2/2 robustness
tasks with zero unnecessary refusals, blocked 8/8 destinations and replayed 36
accepted bundles unchanged. Reviewed head `cf69f4e` merged as `fdfe6e8` with an
identical tree after independent reviews and all five final hosted jobs passed
11,109 tests each. Fresh focused review sets passed 1,261 and 1,103 tests;
all 494 validated source hashes matched. All five post-merge jobs also passed.
Earlier startup failures remain recorded separately.
That accepted slice has **28 profiles using 14 programs** and adds no GUI workflow or real-network
attachment. Credentials and paid/live-model calls remain deferred.

**C4 fixed DNS SRV service metadata is accepted** in
[PR #58](https://github.com/0xsl0th/recon-cockpit/pull/58), merged as `6080a5c`.
The
[runbook](dns-srv-tools.md) binds `dig_dns_srv_v1` to one nonrecursive TCP question,
`_ldap._tcp.harbordesk.test. IN SRV`, at the disconnected owned endpoint.
At most four typed priority/weight/port/target/TTL rows remain untrusted metadata;
no target resolution, endpoint follow-up, UDP, search or transfer is allowed.

Completion requires all six coverage gates and actual native execution. Four
ordinary cases—records, NODATA, NXDOMAIN and reported service unavailable—must
complete 4/4 with zero unnecessary refusals. The injected target/TXT case is a
separate useful robustness trial. Malformed, excess-record, refused, stalled and
output-pressure replies must remain inconclusive after a real validated question.
All ten scenarios need one connection/question, enforced bounds, closed owners,
blocked forbidden destinations and unchanged evidence replay. The planned native
set adds six approval/isolation/cleanup cases to those ten scenarios. Record local
latency, bytes and zero provider calls/cost without claiming comparative overhead.
Native validation passed **25 tests**: 16 C4 and nine accepted regressions, with
zero selected failures/errors/skips. All ten scenarios completed their real fixed
query, blocked 20/20 forbidden destinations, passed 100 boundary fields and
replayed unchanged. A clean-source run at `0c6dcf5` completed 4/4 ordinary tasks
and the separate hostile-metadata task with zero unnecessary refusals, blocked
10/10 destinations and replayed all 40 accepted bundles through both inspectors
without changes. The full portable suite passed **11,428 tests**, with 930
integration cases deselected and zero failures/errors/skips. One earlier failure
was a stale accepted-fixture snapshot selector; its test-only correction passed
86 focused tests and changed no production/native source. Independent reviews
passed 1,328 authority/runtime, 821 parser/evidence and 422 regression tests;
all 502 validated source hashes matched. All five
[final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37673798024)
passed 11,428 tests each. Reviewed `65810b8` merged at 19:36:01 UTC on 7 October
with tree `fbb7092085e169f499d364355bf11c75c4ca2fcb` unchanged. The
[post-merge run](https://github.com/0xsl0th/recon-cockpit/actions/runs/37675710586)
also passed all five jobs. Accepted main has **29 profiles using the same 14 programs**.

**C5 fixed RDP initial negotiation is accepted** in
[PR #59](https://github.com/0xsl0th/recon-cockpit/pull/59), merged as `846e459`. The
[runbook](rdp-negotiation-tools.md) defines `rdp_initial_negotiation_v1`: one fixed
19-byte TLS offer, an immediate write-half-close and one bounded reply frame.
A repository-owned Ruby socket adapter reuses the accepted confinement and
authority path. It performs no TLS handshake, CredSSP, NTLM, authentication or
remote session. Selected protocol, flags, legacy confirmation and known failures
are untrusted metadata; they do not establish identity or every supported protocol.

C5 local validation passed **11,898 portable** and **36 native tests** (19 C5,
17 WhatWeb), with zero failures, errors or skips. All 13 cases executed and
replayed: **5/5 ordinary** and **2/2 separate robustness** tasks completed with
zero unnecessary refusals, six negative outcomes remained inconclusive,
**26/26 unauthorized destinations** were blocked and **130/130 boundary fields**
passed. Fragmentation completed; hostile trailing data stayed unread and could
not elicit another request. Clean-source verification at `f24a2528` repeated the
seven useful trials and replayed all **45 accepted bundles** with bytes, mtimes
and modes unchanged; all **514 source hashes** matched. Reviewed head `5a5f9b4`
merged as `846e459` after all five
[final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37678942749)
passed. All five
[post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37684453123)
also passed. C5 is closed; accepted main has **30 profiles using the same 14 programs**.

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

**Current status: PR #73 is merged; C18 DNS MX and the finite coverage contract are the active slice.**
[PR #72](https://github.com/0xsl0th/recon-cockpit/pull/72) merged as
`e00482409362f1f9380bc225063b84762446dee9` after fresh authority/runtime and
parser/evidence reviews found no blockers and all five final PR checks passed. All five
[post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37816689999)
also passed. Reviewed head `407f48f` and the merge have the same tree
`5bfb8d52f06d486a513ffc429d0418cb7f94b764`. Accepted coverage is now **42 bounded
secure profiles backed by 16 external programs**. C17's G1–G6 are closed.

The [consolidated product roadmap](product-roadmap.md) separates today's verified
capabilities from the professional-v1 release and the longer-term 40+ program
product. Its planning estimates are **40–60 further PRs for an operator-assisted
professional v1**, and **80–130 total further PRs for the broader product**.
These are scoped engineering forecasts, not completion percentages, approval of
deferred work or a claim that all 42 profiles are available through the GUI.
[PR #73](https://github.com/0xsl0th/recon-cockpit/pull/73) accepted the forecast at
`993c83d` from reviewed head `44b479b` after review and all five final CI jobs
passed. All five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37818772689)
also passed; reviewed and merged trees match. Private merge receipt:
`.secure-agent/pr73-merge-review.json`.
The owner agreed the plan and authorized continued coverage work. The new
[finite task checklist](professional-v1-coverage.md) maps accepted exact profiles
and fixes six remaining operator outcomes; candidate engines are not accepted
integrations or a program-count quota.

C17's [runbook](nuclei-git-tools.md) records one fixed GET of `/.git/HEAD` and two
finite synthetic markers. No returned-ref follow-up, repository/source/object
download or credential retrieval occurs; useful observations do not verify
vulnerability or repository exposure.
Preserve **19,437 portable and 44 native passes**, 4/4 ordinary and 1/1 robustness
completions, eight inconclusive negatives, zero unnecessary refusals, 26/26 blocked
destinations, 195/195 boundary fields and **133 unchanged bundle replays**
(13 new and 120 previously accepted). Sixteen inherited receipts and the frozen
290-case/41-adapter/32-runtime predecessor baseline remain unchanged.

All 705 source hashes matched native revision `901faab`; only six documentation
files changed before final reviewed `407f48f`. Fresh review passed 1,466
runtime/authority tests and 318 parser/evidence tests; these focused sets overlap
prior validation and are not an additional aggregate. Scenario wall time was
4528–6393 ms, median 4561 ms, with zero provider calls/cost. This is descriptive
timing, not comparative overhead. The missing-module refusal, first failed native
matrix and corrected nonvacuous isolation tests remain recorded separately.

Private immutable verification: `.secure-agent/nuclei-git-20261008/verification.json`,
SHA-256 `6721ac99867de7e57d6cc06035e65e923c690831087098015650d2b0df1868c6`.
Merge review: `.secure-agent/pr72-merge-review.json`. The original C17 handoff is
historical and remains unchanged; the merge receipt supersedes its open-PR status.

**Current implementation: C18/T01 DNS MX**, using the existing dig runtime,
one fixed nonrecursive TCP question and at most four typed rows. Null-MX, NODATA
and NXDOMAIN have useful distinct meanings; no returned-host follow-up or mail
operation is allowed. The candidate has **43 profiles/16 programs**; accepted
main remains **42/16**. See the [C18 runbook](dns-mx-tools.md).

**Validation pending:** G1–G5 verification is in progress; final portable/native
totals, actual usefulness/enforcement/replay results and descriptive latency must
be recorded after the frozen-source checks finish. G6 review/CI/merge is pending.
No candidate result is counted as accepted coverage yet.

**Next after C18: T02 bounded TLS version-posture feasibility**, initially
assessing sslscan against a finite owned request/runtime contract. No T02 engine
has been installed or implemented. Continue through required T03–T06 using the
[finite checklist](professional-v1-coverage.md); do not remove difficult outcomes
or substitute program counts for useful coverage. Existing closed milestones stay
closed. Deeper workflows, comparative benchmarks, real credentials, attached or
external networks and paid/live models remain deferred under their existing gates.

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
corrected, and the complete rerun is retained. No limit was raised beyond the
approved Nuclei-specific design, and no failed probe counts as useful work.

C17 was subsequently authorized and is now accepted as recorded above. C16 and
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

Paired baseline/authority benchmarking and richer workflow decisions remain later
work; descriptive local latency cannot establish authority overhead. The accepted scope
slice added three configurable profiles using existing programs, without changing
accepted v1 contracts or reopening B0–B8, offline R5 or accepted local R6.

The inventory baseline is PR #37, merged as `ba0d6f8`: 10 interactive executable
families versus 6 secure capabilities backed by 3 external programs. PR #38 adds
accepted DNS/TLS coverage, bringing main to 8 capabilities backed by 5 external
programs. PR #39 accepts B2 SSH host keys and anonymous LDAP RootDSE, bringing
main to 10 secure capabilities backed by 7 external programs. PR #40 accepts B3
SMB metadata, bringing main to 11 capabilities backed by 8 external programs.
PR #41 accepts B4 RPC/NFS metadata at `6623aa0`, bringing main to 13 capabilities
backed by 10 external programs. PR #42 accepts B5 FTP/SMTP at `38cbd43`, bringing
main to 15 capabilities backed by the same 10 programs. [PR #43](https://github.com/0xsl0th/recon-cockpit/pull/43) accepted B6 Docker/WinRM
at `02a7d7f`, bringing main to 18 capabilities backed by 10 programs.
[PR #44](https://github.com/0xsl0th/recon-cockpit/pull/44) accepted B7 bounded Nmap
service identification at `fcb9419`, bringing main to **19 capabilities backed by
10 programs**. Final and post-merge checks passed; preserve its finite probe
contract. [PR #45](https://github.com/0xsl0th/recon-cockpit/pull/45) accepted B8
synthetic Kerberos at `47d70a2`: real Kerbrute, two compiled names, an owned
error-only KDC and explicit limits on tool-reported exists/unknown. Main now has
**20 accepted capabilities backed by 11 programs**. See [the runbook](kerberos-tools.md).

| Priority | Required batch | Completion criterion beyond common gates G1–G6 |
| --- | --- | --- |
| B0 — accepted | TCP/Nmap, HTTP/headers, curl HTTPS and finite ffuf | Preserve the existing bounded owned execution and evidence; PRs #36/#37 stay closed. |
| B1 — accepted in PR #38 | dig DNS and OpenSSL TLS | Fixed nonrecursive A query and verified TLS handshake; structured useful output, negative cases, actual confinement and replay. |
| B2 — accepted in PR #39 | ssh-keyscan and ldapsearch RootDSE | Fixed key collection and anonymous base-scope metadata; no login or referrals. |
| B3 — accepted in PR #40 | smbclient | Anonymous bounded share metadata through the fixed IPC endpoint; no share traversal, file transfer or remote execution. |
| B4 — accepted in PR #41 | rpcinfo and showmount | Bounded RPC/export observations; advertisements cannot authorize endpoints, and no mounting is permitted. |
| B5 — accepted in PR #42 | curl FTP and SMTP capability query | Real fixed listing and EHLO results, valid empty observations, replay and enforcement verified; no file transfer, mail or real credentials. |
| B6 — accepted | curl Docker/WinRM metadata | Separate fixed /_ping, /version and /wsman GETs with bounded observations; no Docker socket, container or remote-session operations. |
| B7 — accepted in PR #44 | Nmap service identification | Actual HTTP/SSH matches, bounded unidentified results, compiled probes and no-op NSE entrypoint; old TCP-only profile unchanged. |
| B8 — accepted in PR #45 | kerbrute synthetic principal enumeration | Owned error-only KDC, two fixed names/requests, complete tool reports, error-text ambiguity disclosed, actual execution and enforcement; no passwords, spraying or tickets. |

The [full checklist](secure-tool-coverage.md#prioritized-coverage-checklist) is the
source of row-level status and the [gate reconciliation](secure-tool-coverage.md#gate-reconciliation--accepted-b0b8)
records closure. No required row was dropped or moved to deferred work. Preserve
those accepted profiles and their limitations; no required B9 follows B8.

The [bounded model pilot](web-model-pilot.md) remains available but disabled.
Credential setup, paid calls, provider funding and live-model evaluation stay
deferred until much later; do not ask for a key during tool development. Completed
offline R5 and the accepted local R6 candidate remain closed. Broader authenticated,
intrusive and external-target product capabilities retain separate authorization.

With configurable scope and the initial GUI accepted, use the remaining October
work for bounded secure-tool batches and owned-lab validation. Refresh the proposal
with verified results in early November, targeting submission around 9 November
after operator review. Proposal PR #31 remains separate and unmerged; its local PDF is unchanged.
Publication and competition submission remain separate later decisions.

The R5 offline baseline is `1605606`, the authorized merge of PR #26
([offline planning evaluation](planning-evaluation.md)). PRs #16–#26 remain
merged and closed. Both profiles pass 18 trials with matching semantic
fingerprints and no paid calls. These results establish offline integration,
not real-model acceptance. [PR #27](https://github.com/0xsl0th/recon-cockpit/pull/27)
adds the [local evidence packet and demo runbook](offline-release-evidence.md)
as R6 preparation and is merged as `dd4bbe4`, with all five final and post-merge
checks passing. The actual approval-required terminal rehearsal completed on
30 September: three approved actions, seeded case a validated, no paid calls.
The operator confirmed entering all three phrases and found it straightforward.
After reviewing the linked report and rehearsal, the operator separately chose
“Accept the local offline candidate”. The evidence packet/rehearsal review is
accepted; publication remains pending and requires a separate instruction.
Live calls remain disabled; development and verification use owned/mock fixtures.

### Earlier implementation checkpoints

**Implementation update — 17 September 2026:** R1 and the smallest R2 HTTP
assessment, private evidence and report slice are reviewed and merged into
`main` through [PR #6](https://github.com/0xsl0th/recon-cockpit/pull/6) (`07af513`)
and [PR #7](https://github.com/0xsl0th/recon-cockpit/pull/7) (`f85aaa9`).
Verification passed 1,849 portable tests
and 78 real Linux integrations, without failures, errors or skips in the selected
suites. All ten refreshed R2 branch/PR checks passed before merge; the merge
preserved the reviewed files. Current state is in [continue-here.md](continue-here.md).
See [http-assessment.md](http-assessment.md),
[offline-authority.md](offline-authority.md) and [verification.md](verification.md).
**R3 update — 22 September 2026:** the smallest owned single-port discovery
slice is reviewed and merged into `main` through
[PR #8](https://github.com/0xsl0th/recon-cockpit/pull/8), merge `b1c7b67`.
One isolated TCP connection gates the existing two-GET workflow; local verification
passed **1,977 portable tests and 96 real Linux integrations**, and all ten
premerge branch/PR checks passed. See [discovery-assessment.md](discovery-assessment.md)
and the continuation checkpoint. **R4 update — 23 September 2026:** the first
versioned card and deterministic engine are reviewed and merged into `main`
through [PR #9](https://github.com/0xsl0th/recon-cockpit/pull/9), merge `8673dc0`.
All ten premerge checks passed; the post-merge cancellation-test correction was
reviewed and merged in [PR #10](https://github.com/0xsl0th/recon-cockpit/pull/10),
merge `2b3527e`. All five subsequent main checks passed.
The [persistent owned lab foundation](owned-lab.md) is reviewed and merged in
[PR #11](https://github.com/0xsl0th/recon-cockpit/pull/11): 2,226 portable and 126
Linux tests passed, plus all five PR CI jobs. The [repeatable evaluation runner](evaluation.md)
now implements the 18-trial synthetic baseline, independent saved-evidence grading
and resource/cleanup/isolation aggregates, reviewed and merged into main through
[PR #12](https://github.com/0xsl0th/recon-cockpit/pull/12), merge `ff5f76a`.
Verification passed 2,300 portable and 132 Linux tests, plus the final 18/18 CLI
baseline. All five final PR CI jobs passed. The first R5a implementation is the
[owned TLS provider foundation](provider-foundation.md): disconnected fixture
transport, synthetic credentials, explicit status-only data release and bounded
per-attempt accounting. R5a is complete and merged in PR #13; its publication
and verification state are recorded in the continuation checkpoint.
**R5b complete — 29 September 2026:** the [durable provider cost ledger](provider-cost-ledger.md)
adds explicit USD estimates, reservations, actual usage/billing reconciliation and
atomic account/engagement/session/agent/action caps, merged in PR #14 (`3a0cb67`).
The [controlled provider call](controlled-provider-call.md), merged in PR #15
(`1369166`), integrates one fixed synthetic ACK request with those controls and
the R5a isolation machinery. R5a is merged in PR #13 (`0a9697f`). The new call
remains disabled by default and separate from assessment planning. All provider
verification used owned/mock fixtures and synthetic credentials; real planning,
further authority separation and live evaluation remain unfinished R5 work.
See [workflow-assessment.md](workflow-assessment.md) for the
decision trace and evidence contract. Broader discovery remains future work.
The baseline below is historical.

## Product direction

Build an AI-assisted pentesting platform that turns evidence into proposed next
steps, runs approved capabilities inside enforced boundaries, and produces
reviewable findings. The longer-term lifecycle includes discovery, enumeration,
validation, explicitly enabled exploitation, post-access assessment, cleanup and
reporting. Each stage needs its own permissions and tool contracts.

An **engine** is a specialist workflow with evidence requirements, capability
choices and stop conditions. A **tool adapter** implements one bounded capability.
A **planner** chooses steps. None owns policy, grants, audit authority or
permission to widen an engagement.

The competition contribution is control of autonomous agents, demonstrated by
useful pentesting. The official [Challenge 4](https://www.palermo.edu/ingenieria/concurso-ciberseguridad/)
supports that framing. Keep the Spanish [proposal](competition-proposal.md)
consistent with implemented limits and measured results.

## Baseline before R1/R2 — historical

PRs #2–#5 are merged. PR #5's reviewed code is `0477f25`; its merge on `main` is
`bf3a359`. The final run passed 1,383 portable and 51 Linux integration tests;
all ten hosted branch/PR checks passed. See [verification.md](verification.md).

| Existing capability | Gap that determines the next work |
| --- | --- |
| `AuthoritySession`, isolated coordinator and bound fixture executor | R1 adds an offline-provider relay. Host authority/UI/broker/audit/launcher still share one process. |
| `OfflineOpenAIProvider`, isolated parser and offline broker | R1 connects these to the authority path; the earlier `SessionRunner` mode remains. No live transport or credentials. |
| Strict actions and policy | Only `http_probe` is executable in secure mode; the action model is HTTP-specific. |
| Fixtures and a separate routed HTTP backend | Authority executors are fixture-only; routed sessions and real VPN validation are absent. |
| Audit and bounded feedback | No secure engagement evidence store, finding lifecycle or report provenance. |
| Legacy cockpit and Nmap workflows | Useful precedents; the host runner is not an agent-safe tool boundary. |

## Original milestone order — historical

The original sequence built one complete path through the provider and authority
boundaries before expanding the workflow library. Those bounded milestones are
now closed as recorded below. The current tool-first sequence above governs new
development; credential setup, paid calls and live evaluation remain deferred
until much later.

| Priority | Build | Why now | Exit evidence |
| --- | --- | --- | --- |
| R1 — implemented | Offline provider through the isolated coordinator and authority | Closes the split between existing boundaries without new targets or spending. | Combined three-step synthetic session and adversarial variants pass through the Linux boundaries. |
| R2 — smallest slice implemented | One HTTP assessment, minimal capability/evidence contracts and report | Makes the foundation useful and reveals the abstractions tools actually need. | Two-GET owned workflow, private execution/observation artifacts, draft reports and read-only crash inspection. |
| R3 — accepted bounded scope merged | One isolated single-port TCP adapter | Adds a second typed capability without broadening old HTTP backends. | Owned TCP evidence gates HTTP; 1,977 portable and 96 Linux tests passed. Broader discovery remains future work. |
| R4 — accepted first card/engine merged | Versioned workflow cards and one specialist engine | Turns references into tested branching, validation and stopping rules. | Existing six owned cases retain their outcomes with durable explanations of proposals, executions and stops. |
| R5 — offline scope complete; live work deferred | Isolated live-provider broker and further authority separation | Useful actions and a reproducible baseline provide a basis for model evaluation. | Offline integration/evaluation merged; real-model validation remains gated on explicit approval. |
| R6 — local offline candidate accepted; publication deferred | Evaluation corpus, operator review, packaging and demonstration | Makes utility, enforcement and limits independently reviewable. | Reproducible release, evidence-backed report and rehearsed final demo. |

Tests and adversarial fixtures accompany every slice; R6 consolidates them.

## Milestone completion order

The agreed offline R5 scope is complete and the local R6 candidate is accepted
under the disclosed offline fallback. Live work and publication remain deferred.
Use the original requirements below
alongside the accepted bounded contracts; do not retroactively expand completed
scope. Offline completion does not claim real-model acceptance or erase the
original live criterion.

1. **Preserve the accepted R1–R4 baseline:** the authority path, owned HTTP and
   TCP workflow, versioned card/engine, persistent lab and 18-trial evaluation
   are merged. Keep their documented limits visible. A general capability
   registry and broader finding workflows were not
   automatic blockers for R5. The newly authorized bundled-adapter contract is
   separate follow-on work. Address an earlier contract only when a concrete
   dependency or regression requires it, within the current milestone's scope.
2. **R5a complete — PR #13:** preserve the isolated owned TLS provider boundary,
   synthetic credentials, explicit data release and bounded attempt accounting.
3. **R5b complete — PRs #14 and #15:** preserve the durable monetary ledger,
   hierarchical spending limits and first tightly controlled provider-call path.
   Their agreed verification is offline with owned/mock fixtures. Live execution
   remains disabled by default; its later activation does not reopen R5b.
4. **Bounded R5 integration merged through PR #25:** preserve the accepted
   approval/authorization/launch/audit interfaces and owned assessment-planning
   path on R5a/R5b. The merged offline evaluation in PR #26 checks that combined
   path against the preserved baseline, including persisted accounting and
   launch preconditions. Keep its trust limits explicit; the fixed ACK diagnostic
   does not establish assessment planning, and a GUI is not a dependency.
5. **R5 live acceptance is gated:** real-model comparison still requires a later
   explicit operator instruction and reviewed data/model/credential/spend settings.
   This priority correction does not authorize paid or external provider calls,
   real credentials, external targets or VPN testing. Keep that criterion visibly
   pending while live work is prohibited; do not mark R5 complete using fixtures.
6. **R6 after the preceding acceptance gates:** consolidate the corpus, repeat
   functional/adversarial comparisons, obtain actual operator review, package a
   reproducible release and rehearse the evidence-backed demonstration. Existing
   baseline grading is a foundation, not completion of R6. If live validation
   remains unavailable, use the original explicitly disclosed offline fallback;
   it does not silently satisfy the live acceptance criterion. The current
   [evidence packet and runbook](offline-release-evidence.md) provide that local
   fallback. The operator has now accepted the local candidate after review and
   rehearsal; the separate decision is recorded in the checkpoint. Publication
   remains pending, and the original live acceptance criterion stays deferred.

### Bounded R5 integration and offline evaluation

The first merged implementation is the [confined audit writer](isolated-audit.md): an
explicit Linux option transfers audit persistence to a restricted worker and
requires a durable acknowledgement before the existing launch gate proceeds.
[Isolated terminal approval](isolated-approvals.md) is now merged in PR #18:
review, unpredictable challenges and single-use grant state reside in one fixed
worker. [Isolated launch admission](isolated-launch-admission.md) is merged in
PR #19: an independent worker owns fixed policy/profile checks, execution
reservations and one-use permits. The [confined fixture launcher](isolated-fixture-launcher.md)
(PR #20) and [persistent-lab integration](isolated-owned-lab-launcher.md) (PR #21)
are now merged. The launcher owns admission-client custody, executor supervision,
and persistent lab management/namespace pins, preserving card v2 and all six cases.

With merged [independent durable-intent verification](launch-audit-witness.md),
the isolated writer sends a direct witness after fsync, and the launcher checks it
before admission or execution. [PR #22](https://github.com/0xsl0th/recon-cockpit/pull/22)
completes the durability portion of precondition integration. The merged
[direct approval gate](launch-approval-witness.md) in [PR #23](https://github.com/0xsl0th/recon-cockpit/pull/23)
requires proof of a consumed grant from the approval worker, retains its original
expiry and rechecks freshness after admission. It closes reliance on a host
consent claim in the opt-in path; the fixed worker and terminal remain trusted.

The merged [bounded offline planning slice](bounded-assessment-planning.md) on
`feature/bounded-assessment-planning`, published as `bb9e42c` in
[PR #24](https://github.com/0xsl0th/recon-cockpit/pull/24), connects the existing workflow/evidence
eligibility gate, explicit planning data release, isolated parser/coordinator and
simulation monetary reservations/settlement to both independent launch checks.
It uses finite owned mock responses and leaves the fixed ACK and R5a TLS contracts
unchanged. Full verification passed 3,382 portable and 430 Linux tests, with zero
selected failures/errors/skips; independent review has no remaining findings.
The operator authorized review and merge of #24; final head `9ccc910` passed
review and all five hosted jobs, and merged as `4f9545c`. Keep this mock slice
closed. The [owned TLS slice](owned-tls-assessment-planning.md), PR #25, merged as
`636a067` after final head `c7f7791` passed review and all five checks. It sends the
same approved descriptor through the disconnected fixture, preserves settlement
before proposal release and verifies cleanup and transport failures. The current
[offline evaluation](planning-evaluation.md) compares this combined path with the
preserved deterministic baseline using a separate versioned grader and shared
batch simulation ledger. Mock responses do not complete
live-model acceptance; paid calls remain disabled during ordinary development.
The offline R5 scope is complete; full R5 still has its deferred live integration
and acceptance gate. R6's packet and runbook are merged in PR #27 and the
operator accepted the local candidate after the terminal rehearsal. Publication
is a separate pending decision. Optional GUI/session APIs and broader tools
remain deferred. The current follow-on authorization covers the reviewed
adapter/Nmap implementation described above; keep live calls disabled.

- Preserve the merged narrowly scoped approval/launch and audit interfaces.
  Record any necessary ownership change before extending the planning path.
  Keep the new reviewed adapter profile separate from accepted milestone
  contracts; it does not authorize broader targets or data release.
- Preserve fresh approval, independent authorization, cost reservations,
  audit acknowledgement before launch and independent executor validation.
  Moving functions into subprocesses alone does not establish a new boundary.
- Verify denial, expiry, replay, cancellation, audit failure and cleanup with
  owned/mock fixtures and the affected Linux isolation checks. Preserve the
  existing R1–R4 assessment outcomes and R5a/R5b financial/provider invariants.
- Preserve the merged offline evaluation and accepted local R6 packet/runbook.
  Keep real-model acceptance and publication visibly pending
  until each occurs; development and verification remain offline.

### Additional ideas deferred until milestone completion

The recently proposed separate budgeted-assessment initiative, general read-only
session view/timeline API, dashboard based on the GUI reference, and interactive
GUI controls are not the next work items. Revisit them after the original
milestones are complete, where they naturally fit, using the established
architecture and safety model. Necessary accounting or evidence work already
required by an original milestone stays in that milestone; do not relabel an
optional UI/API project as a prerequisite. Keep broader tools, multiple agents
and other stretch goals behind the same original completion priorities.

## R1: implemented integration and acceptance criteria

**Objective:** one offline planning path using the new authority boundary and
existing owned HTTP fixtures. Keep the current modes as regression references.

### Work sequence

1. Write a short architecture decision identifying who triggers planning, how
   proposals reach the coordinator, channel ownership, session identity, shared
   deadline, authority budgets and provider budgets. Settle topology before IPC
   changes.
2. Define the smallest bounded provider dialogue. The current coordinator has
   only stdin/stdout/stderr and proposal-only authority frames. A provider lane
   requires deliberate bootstrap/protocol work, not a generic RPC interface,
   inherited broker object or configurable Python plugin.
3. Construct planning observations and canonical provider requests from trusted
   execution records and fixed configuration. Coordinator-supplied claims cannot
   redefine observations, provider configuration, budgets or system rules.
4. Feed synthetic proposals through the isolated coordinator and existing
   sequenced authority checks. Every action still requires policy, any required
   fresh approval, reservations, audit and an independently validating executor.
5. Add a labeled combined offline CLI/demo, regressions and verification record.

### Acceptance criteria

- One three-step synthetic session uses an authority-owned session ID and
  deadline; provider usage and tool usage have separate bounded counters.
- Each planning exchange validates the canonical request, reserves resources
  and audits before offline transport handoff. No credentials or external
  connection become available.
- Every proposal enters the authority channel; there is no legacy host-runner
  or direct-executor shortcut.
- Replay, wrong-session messages, forged observations/approval fields, malformed
  dialogue, denied follow-ups and exhausted budgets produce no unauthorized
  additional exchange or launch.
- Cancellation, expiry and audit failure prevent subsequent work and reap
  children. Restarting a planner cannot replenish counters. A new operator-created
  session remains a separate documented case; persistent engagement quotas come
  later.
- Linux canaries preserve the existing broker/parser and coordinator/executor
  isolation claims, including absent host credentials, terminal and authority
  handles where required.
- Portable and affected real Linux suites pass. Report synthetic provider
  behavior separately from real OS isolation and human approval evidence.

### Starting points

Under `recon_cockpit/secure_agent/`, inspect `cli.py`, `control_plane.py`,
`coordinator_worker.py`, `coordinator_ipc.py`, `coordinator_isolation.py`,
`openai_provider.py`, `openai_broker.py`, `broker_ipc.py` and
`openai_isolation.py`. Read [control-plane.md](control-plane.md) and
[offline-openai-broker.md](offline-openai-broker.md).

**Outside R1:** new pentesting tool capabilities, live API calls, credentials, external targets,
VPN testing, generic knowledge ingestion, GUI and multiple agents.

## R2: implemented owned HTTP assessment

The fixed workflow discovers `/assessment/<case>/diagnostics.json` from an actual
successful response, then permits only that same-case follow-up. Both GETs use
`127.0.0.1:8080` inside owned fixtures and the R1 coordinator, offline parser,
authority and independently checked executor. Defaults are two planning steps
and 2,048 reserved output bytes. No live model or external target is involved.

A versioned descriptor covers this one capability. Private records bind host
execution IDs, action/policy digests, decoded artifacts and parsed observations.
JSON/Markdown reports distinguish validated seeded exposure, not demonstrated
at the endpoint, and inconclusive evidence. Findings remain pending operator
review. Read-only inspection recomputes observations and flags missing or
inconsistent records; it does not restore execution or approvals.

Six fixture cases cover exposure, absence, malformed documents, timeout, excess
output and hostile discovery. The current parser uses probe success/EOF and no
reported truncation; it does not establish comprehensive HTTP framing integrity
or authenticate server content. Local digests detect inconsistency, not a
compromised host owner's modifications. See [the R2 design](http-assessment.md)
for evidence ordering, storage bounds and remaining limits.

General capability registration, broader finding/review workflows, richer UI and
remote assessments remain future work. R3 has delivered the second tool's
smallest isolated runtime and owned lab contract. Continue the current R5 work
without making those broader extensions prerequisites.

## R3–R4: extend the assessment with discovery and workflow cards

### Start with HTTP, then generalize only what the second tool needs

R2 now covers the fixed HTTP path: inspect an approved endpoint, select a
bounded follow-up, validate a seeded condition, and produce a finding draft,
“not demonstrated,” or an inconclusive result. Extend this small workflow as
discovery exposes concrete requirements for another capability.

Generalize R2's versioned descriptor into a registry of reviewed built-in capabilities. An entry
declares typed parameters, destination requirements, effect/approval classification
interpreted by operator policy, resource ceilings, isolated runtime, parser and
result schema. Agents select
capability IDs and bounded parameters; trusted code selects executable,
arguments and storage paths.

This broader registry direction is not implemented by the accepted bounded
R3/R4 slices. It remains a future extension unless a concrete dependency of the
current R5 work requires a minimal change; it does not reopen those slices.

A new adapter needs its own runtime/dependency review, network model and
adversarial tests. The existing host runner must never become a fallback.
Check candidate tool behavior against its primary documentation during
implementation; this roadmap does not certify a particular tool/version.

### Evidence and findings

Keep three concepts distinct:

- **Execution record:** trusted session/action IDs, effective configuration,
  status, timestamps, resource use and artifact references.
- **Observation:** a bounded parsed claim from untrusted output, with source,
  target, parser version, truncation status and evidence reference. Successful
  exit does not prove a vulnerability or authenticate target content.
- **Finding:** hypothesis, supporting/contradicting observations, validation
  state, scope, impact rationale, remediation and reviewer state. Missing proof
  is not a negative result; unsupported model assertions remain hypotheses.

Use private, size-bounded artifacts, host-generated IDs, bounded parsers and safe
rendering. Define retention, redaction and which evidence may enter model
context. Do not copy raw output into trusted approval prompts or audit fields.
Agents receive selected views, not write access to case storage.

A digest identifies content; it does not prevent host-owner tampering. Keep that
limit visible. After a crash, preserve evidence and flag started-without-finished
actions for reconciliation. Never restore old approval grants, monotonic
deadlines or apparently unused budgets. Development resumption and assessment
resumption are different operations.

### First additional tool

Use a fixed **TCP-connect discovery profile**, with Nmap as the initial adapter
candidate, in an owned lab network. Bound ports, targets, rate, runtime and
output; isolate XML parsing. Begin without arbitrary options, user scripts,
raw-socket privileges or credentials. If its runtime cannot meet the boundary,
use a minimal bounded TCP discovery implementation until it can.

A multi-service lab requires an explicit lab-only executor contract. Do not
silently broaden existing fixture restrictions or route to the host. Reachable
allowed/forbidden witnesses must prove both connectivity and enforced scope.

### First engine and workflow cards

The first engine receives approved lab scope, discovers a service, selects HTTP
enumeration from evidence, validates one seeded non-destructive condition and
produces a finding draft with a Markdown/JSON report. Failure or insufficient
evidence produces an inspectable inconclusive stop.

Start with normal and stalled/misleading-response variants. A card records
ID/version, objective, preconditions, evidence dependencies, allowed capabilities,
parameter bounds, success/failure predicates, retries, stop conditions,
effects/cleanup, report fields, provenance and test fixtures.

Cards generate proposals, not permissions. Later attack graphs connect cards
through evidence-dependent transitions. Discovering another host, identity or
credential does not authorize its use. Every engine shares the same authority
and evidence contracts.

The first slice now uses one repository-authored card for the existing singleton
topology. It imports no external instructions and adds no capability registry.
The first card/engine slice is merged. The persistent owned lab foundation keeps
one seeded service alive across fresh executors, binds identity and counters to
evidence, and destroys the instance at session end. See [its contract](owned-lab.md)
and [verification](verification.md). The [repeated evaluation runner](evaluation.md)
now measures this fixed baseline. Preserve these accepted implementations as
regression references while completing R6 and any later authorized live work.
Persistent lab operation does not establish live-model performance.

## R5: live AI and further privilege separation

**Status: agreed offline scope complete; model integration prepared, live evaluation pending.** R5a
(PR #13), R5b (PRs #14/#15), bounded audit/approval/admission/launcher separation
and owned assessment planning through PR #25, and the offline comparison in
PR #26 are accepted. Keep those contracts closed. PR #27 is R6 packaging and
the runbook. No necessary offline R5 blocker remains.

The original live criterion below remains pending. The separate ACK diagnostic
stays unchanged. The new [web-model integration](web-model-pilot.md) supplies a
live-capable assessment path, validated only with owned TLS fixtures. Execution
remains disabled by default. Its proposed pilot requires reviewed data, endpoint,
credentials, egress, usage/pricing and spending settings before any paid call.
Owned fixture results do not establish model performance or live acceptance.

The current constraint remains **live calls disabled**. Build transport and
credential handling against controlled endpoints and synthetic secrets first.
Real use needs explicit operator choices for permitted data, model, credential
source and spending ceiling. Account for input/output consumption, bounded
bytes, cancellation and retries. Output-token limits alone are not a monetary
budget; reserve cost conservatively and reject unaffordable work before sending.

The credential/network broker needs its own constrained process, fixed
destinations and verified TLS behavior. Credentials must not enter planners,
tools, artifacts or logs. Redaction alone is not a data-release policy. Returned
model content remains untrusted.

Further separate approval issuance, authorization, launching and audit with an
explicit statement of which authority leaves each process. Prioritize credential
isolation, then narrowly scoped approval/launch and audit interfaces before
expanding credentialed or intrusive tools. Moving functions into subprocesses
or hashing messages does not establish independent authorization. Audit must
acknowledge intent before launch; independent storage cannot prove the truth
of a compromised producer's claims.

Run identical seeded assessments with deterministic and real planning. Measure
repeated-run completion, finding accuracy, unnecessary actions, scope violations,
injection effects, time and cost. Refusing everything is not useful assessment;
a convincing report without evidence is not success.

## Competition scope and schedule

Confirmed on 22 September: Enrique Folte is the sole human participant and
project contact, with Codex assisting development under his review. No other
members or institutional affiliation are declared. These are target windows,
not completed-capability claims. R1/R2, the smallest R3 slice and the first R4
card/engine slice are merged. The windows below preserve the original schedule;
they do not override the current R6 offline priority or reopen accepted scope.

| Target window | Outcome |
| --- | --- |
| September–October 2026 | R1–R4 bounded implementations, persistent lab and 18-trial baseline merged; offline R5 complete, live work deferred. Continue R6 under the disclosed offline fallback. |
| Through 8 November | Finalize proposal and measured baseline; build repeatable owned evaluation where ready. Tool breadth is not a submission prerequisite. |
| 9–15 November | Human review and project submission; aim for 9 November for margin. |
| 16 November–10 January 2027 | Complete R3/R4 and the lab assessment corpus. |
| 11 January–28 February | R5 controls and explicitly approved live-model evaluation. |
| 1 March–25 April | R6 repeated evaluation, operator review and documentation. |
| 26 April–13 May | Freeze capabilities, reproduce release and rehearse. |
| 14–20 May | Delivery buffer; no unvalidated expansion. |

**Minimum final target:** one real-agent lab assessment using discovery and HTTP
validation, traceable reporting, enforced scope/approvals/budgets and an
adversarial comparison. If live evaluation is unavailable, disclose the reduced
offline demonstration; do not claim validated autonomous performance.

**Later/stretch:** broader web/API, Linux and Windows/AD engines, credentialed
validation, controlled exploitation/post-access workflows, multiple agents,
remote audit, richer UI and optional PivotTrail/reporting integrations.
Real VPN testing remains deferred until the product is ready and the operator
provides scope; it is not a dependency of the initial lab demonstration.

Multi-agent work follows a validated single agent. Use shared engagement budgets,
scoped evidence views, delegation limits and concurrency tests. Delegating never
resets scope or grants.

If time slips, cut engine count, target breadth and interface polish first.
Keep one complete workflow, evidence quality and enforcement. Do not regain
time by using host execution, widening permissions or relabeling mock evidence.

## Knowledge sources

The user confirmed these exact references on 15 September 2026. They are
knowledge sources and potential lab resources, not installed integrations.

| Source | Intended role |
| --- | --- |
| [Enrique Folte](https://enriquefolte.com/) | Primary personal workflow/manual source; decision routing, pattern cards and reporting. |
| [PentestMonkey](https://pentestmonkey.net/) | Tools and technique references. |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | Payload and web-testing reference. |
| [GTFOBins](https://gtfobins.org/) | Unix executable behaviors relevant to privilege boundaries. |
| [LOLBAS](https://lolbas-project.github.io/) | Windows binaries, scripts and libraries relevant to security testing. |
| [HackTricks](https://book.hacktricks.wiki/en/index.html) | Broad technique and methodology reference. |
| [Hack The Box](https://www.hackthebox.com/) | Training and candidate lab scenarios, subject to access and applicable scope. |

The personal manual provides useful starting structures:
[Engagement Cockpit](https://enriquefolte.com/manual/_Engagement_Mode/Engagement_Cockpit),
[Decision Trees](https://enriquefolte.com/manual/_Engagement_Mode/Decision_Trees),
[Symptom Index](https://enriquefolte.com/manual/_Engagement_Mode/Symptom_Index),
[Attack Pattern Cards](https://enriquefolte.com/manual/_Engagement_Mode/Attack_Patterns)
and [Reporting & Evidence](https://enriquefolte.com/manual/_Engagement_Mode/Reporting_SysReptor).
Their translation into the contracts above is our design proposal.

Requested categories: reverse shells/payloads, Linux privilege escalation,
Windows privilege escalation, Active Directory, web application pentesting,
enumeration, post-exploitation and CTF/lab reference. Coverage in the knowledge
catalog does not enable execution. Payloads, callbacks, privilege changes and
post-access actions each need explicit capabilities, effect policies, cleanup
and their own lab verification before admission.

For adopted cards, record source URL/author, retrieval date, revision or content
digest, attribution/license status, reviewer, relevant tool versions and fixtures.
Summarize and reference; do not bulk-copy third-party collections or execute
retrieved prose. Preserve source → card → execution → observation → finding links.
HackTricks' book URL was verified through its official repository because direct
page retrieval was unavailable during this planning pass.

## Open decisions

- Enrique Folte is the confirmed sole human participant and contact; affiliation
  is unspecified. Review submission details before sending.
- R1 channel topology is settled in [offline-authority.md](offline-authority.md).
- R2's seeded diagnostic condition and R3's singleton owned topology are fixed in [http-assessment.md](http-assessment.md) and [discovery-assessment.md](discovery-assessment.md). Card v2 uses the [persistent lab foundation](owned-lab.md); the [evaluation runner](evaluation.md) measures repeated synthetic outcomes. Preserve the completed offline R5 and accepted local R6 baseline; the new model integration is separate work and live acceptance remains pending.
- Later choose real-model/data/credential/spend settings.

Reference identities and team composition are resolved. This plan does
not authorize registration, messages, paid calls or target assessments.

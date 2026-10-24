# Product roadmap and remaining PR estimate

Current continuation (20 October 2026):
**T01–T06 meet G1–G6 and the finite Stage 2 coverage tranche is closed:
52 accepted profiles at that milestone.** Accepted S3.6b now brings current
coverage to **55 profiles, zero candidates and 17 external programs**.
[T06 PR #86](https://github.com/0xsl0th/recon-cockpit/pull/86) merged as `f0542a8`
after fresh authority/evidence review and all five
[final checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/38595455084).
Reviewed head `28f1a18` and the merge have identical tree
`c475c0cb3648938fcbe0d66a3bb9a9168ed424d3`.
All five [post-merge checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/38597857953)
also passed. Preserve `.secure-agent/stage3-20261014/pr86-merge-review.json`
and `pr86-postmerge-ci.json` beside it.
Do not repeat completed merges or reopen accepted milestones.

The [accepted T06 runbook](dns-address-tools.md) retains 83 native and 24,163
portable passes, all 747 frozen source pins, 57 saved reports and 114 unchanged
inspection checks. All 11 ordinary and four robustness cases completed usefully;
23 negative cases stayed inconclusive and four out-of-scope proposals were
blocked. Returned IPv6 addresses and PTR names remain untrusted metadata, with
no added scope or follow-up authority. Private original evidence remains under
`.secure-agent/dns-address-20261014/`.

**S3.1 is accepted in [PR #87](https://github.com/0xsl0th/recon-cockpit/pull/87),
merged as `48c0bce`.** Fresh independent reviews and 554 focused checks passed;
all five [final checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/38599557928)
and [post-merge checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/38602810350)
passed. Reviewed head `0377fd4` and the merge share tree
`2fb54bff607f8e8a64a09eea12654f145327e570`. Preserve the private merge receipt
under `.secure-agent/stock-nginx-20261014/`; do not repeat this merge.

**S3.2a is accepted in [PR #88](https://github.com/0xsl0th/recon-cockpit/pull/88),
merged as `5686dc8`.** Fresh review and 100 focused tests passed. All five
[final checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/38607042272)
and [post-merge checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/38609552148)
passed; reviewed head `1009be6` and the merge share tree
`748fdb336a61d4d12fda5e4ad846641e061664a8`. Its full portable validation passed
24,263 tests. Retain `.secure-agent/stock-nginx-native-20261014/pr88-merge-review.json`.

**S3.2b is accepted in [PR #89](https://github.com/0xsl0th/recon-cockpit/pull/89),
merged as `c068a9d` on 14 October. S3.2 is closed.** Fresh code/evidence review
found no blockers; 110 root and 289 reviewer focused checks passed. All five
[final CI jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/38628904862)
passed 24,643 portable tests each. All five
[post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/38635058569)
also passed. Reviewed head `409580f` and the merge share
tree `573ac69f78b67fd208a2518844897a699ef6ed99`. Retain
`.secure-agent/stock-apache-20261014/pr89-merge-review.json` and the original
`.secure-agent/stock-nginx-native-20261014/` evidence, including failed attempts.

The accepted [nginx diagnostic](stock-nginx-native.md) retains 60 native checks,
15 accepted-workflow regressions, 16 useful corpus completions, ten correct
negatives, 16 distinct destination denials and 52 unchanged inspections.
Production code/native cases remain identical to frozen `d0bbdf2`; later
portable fixture corrections and their original failures remain recorded.
No diagnostic result grants production HTTP support or adds a catalog profile.

**S3.3a is accepted in [PR #90](https://github.com/0xsl0th/recon-cockpit/pull/90),
merged as `d30a2f1` on 14 October.** Fresh independent code/evidence review and
118 focused tests passed; all five [final CI jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/38639047704)
passed; all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/38643623264)
also passed. The fixed Apache inspector remains preparation only; this acceptance
establishes no native startup, confinement or production compatibility.
Retain `.secure-agent/stock-http-production-20261014/pr90-merge-review.json`.

**S3.3b is accepted in [PR #91](https://github.com/0xsl0th/recon-cockpit/pull/91),
merged as `061c057` on 14 October. S3.3 is closed.** The separate [production HTTP path](stage3-http-production.md)
passed **106 native checks at `1cfa59a`**: 52 nginx/Apache corpus rows and 54
boundary checks, with all **904 source hashes unchanged**. It records **32 useful
completions, zero unnecessary refusals, 20 correct negatives and 32 distinct
destination denials**. All 52 bundles passed **104 unchanged Python/CLI inspections**;
**68 distinct accepted-profile native regressions** and **three separately launched
Apache extra-request repetitions** passed. These repetitions are not additional
unique acceptance cases.

Full local portable validation at `d19eef3` passed **25,312 tests**, with
all **904 source hashes unchanged** during that run. All five [hosted checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/38649179063)
also passed at `d19eef3`. Production code and native cases match `1cfa59a`; the
later change corrected portable fixtures and recorded validation. Preserve the
original smoke, native and macOS failures under
`.secure-agent/stock-http-production-20261014/`; the original Apache budget-test
failure's cause remains unconfirmed. No required corpus row or bound was removed.
A later macOS check exposed a shared portable socket-readiness fixture issue;
the [test-only correction and failed run](stage3-http-production.md#portable-socket-readiness-correction)
are recorded separately. Fresh independent security/evidence review and **605
focused tests** passed at final head `77aeb7b`; all five [final CI jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/38652472772)
passed **25,314 tests each**, with no skips, failures or errors. The reviewed and
merged trees match. Retain `.secure-agent/pr91-review-20261014/` and the original
production evidence; the merge does not require repeating accepted native runs.
All five [post-merge checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/38653912630)
also passed 25,314 tests each; retain `postmerge-ci-061c057.json` beside the review.

S3.3a validation at `274140b` passed **26 installed-runtime inspections** and
**24,761 portable tests**, with all **882 tracked source hashes unchanged**.
No service, tool action or authority was created; provider calls/spend remain zero.
See the accepted [preparation evidence](stock-apache-feasibility.md);
read-only preparation is not production support.

**S3.4b is accepted in [PR #93](https://github.com/0xsl0th/recon-cockpit/pull/93)
at `a7f46b1`; S3.4 is closed. S3.5–S3.7 are accepted below; Stage 3 is closed.**
The [SSH evidence](stage3-ssh-compatibility.md) records 94 native checks,
71 accepted-profile regressions, 26,141 local portable tests, eight useful
completions, twelve expected negatives and zero unnecessary refusals. Fresh
independent reviews found no blockers and all five latest CI jobs passed at
`321ff9c`; the merge tree matches. Original intermittent regression failures
remain recorded with unconfirmed cause despite the complete passing follow-up.
SSH authentication and trusted host identity are not supported.

The [S3.5 implementation contract](stage3-disconnected-routing.md) pins a first
fixed A routing slice: separate owned HTTP/SSH hosts, routed links, a listening
excluded endpoint and one aggregate ledger across four explicit actions.
[PR #94](https://github.com/0xsl0th/recon-cockpit/pull/94) accepted the first fixed-A
nginx/OpenSSH routing slice at `46f9b73`: 25 native checks, 76 accepted-profile
regressions and 26,599 portable tests passed at `659c053`, with 981 unchanged
source pins. Twelve ordinary selected actions completed without unnecessary
refusals; three aggregate-budget negatives preserved useful work and blocked
the excess. The runbook retains an earlier unexplained Apache regression refusal.
The [fixed deployment extension](stage3-routing-deployments.md) is accepted in
[PR #95](https://github.com/0xsl0th/recon-cockpit/pull/95) at `d0586f5`: all four
nginx/Apache × A/B deployments retain unchanged caps, with 80 routing, 76
accepted-profile/witness and 32 recorder native passes and five final CI jobs
passing 26,878 tests each. The [full matrix](stage3-routing-matrix.md) is accepted
in [PR #96](https://github.com/0xsl0th/recon-cockpit/pull/96), merged at `6f60ae0`.
Fresh independent reviews and all five final CI jobs passed at `104c45d`, each
with 27,274 tests and the completeness guard; reviewed and merged trees match.
Frozen `0e09f82` retains 248 native routing checks, 76 regressions and 120
unchanged inspections of 60 original v1/v2 bundles. Original failures remain
recorded. **S3.5 is closed.**

[PR #97](https://github.com/0xsl0th/recon-cockpit/pull/97) accepted
[S3.6a static preparation](stage3-name-tls-preflight.md) at `8b086d5`: 23 cases
across A/B, four fixed ELF images and 46 read-only runtime inspections. All five
final and post-merge CI jobs passed 27,603 portable tests each.

[PR #98](https://github.com/0xsl0th/recon-cockpit/pull/98) accepted
[S3.6b native binding](stage3-name-tls-native.md), merged as `c71b599` after
independent authority/evidence review. Reviewed head `05719b3` and the actual
merge share tree `6a4384431669ebc604c0b5b6878dcdee67892577`. All five
[final CI jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/39334102028)
passed 28,723 portable tests each with no skips, failures or errors. All five
[post-merge checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/39343038641)
also passed the same complete suite. The accepted
evidence retains 327 name/TLS native gates, 248 routing gates, 76 regressions,
120 unchanged legacy inspections and 28,723 local portable passes. Both original
unexplained failures remain recorded beside the complete passing follow-ups.
S3.6 is closed.

**[PR #99](https://github.com/0xsl0th/recon-cockpit/pull/99) accepted
[S3.7 combined acceptance](stage3-combined-acceptance.md), merged as `4ef9b98`.
Stage 3 is closed: all ten logical increments are accepted across thirteen
PRs, #87–#99.** Fresh authority/evidence reviews found no blockers. Reviewed
head `96c4408`, its CI checkout and the actual merge share tree
`321f50c2f53f3ecda88242f703ce32a46404d878`. The final local suite and all five
[final CI jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/39490545078)
passed **28,777 portable tests**, with no skips, errors or failures. The combined
acceptance retains 651 exact native identities, 472 fresh saved-evidence
inspections and the separate 120 legacy inspections. Original failed attempts
remain preserved. The [post-merge run](https://github.com/0xsl0th/recon-cockpit/actions/runs/39502316329)
is tracked separately under `.secure-agent/pr99-review-20261020/` beside
`merge-review-receipt.json`.
Coverage remains **55 accepted profiles, zero candidates and 17 external programs**.
**[PR #100](https://github.com/0xsl0th/recon-cockpit/pull/100) accepted the
[S4.1 engagement/custody contract](stage4-engagement-custody.md) at `7a7eace`.**
Fresh independent reviews found no blockers. Reviewed `0df7505`, its five passing
CI checkouts and the actual merge share tree `ea4bc9b9ced9b90bddaf63e997b9edc7453b77ed`.
All five [final CI jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/39503654735)
passed 28,777 portable tests each, with no skips, failures or errors. The
[post-merge run](https://github.com/0xsl0th/recon-cockpit/actions/runs/39506462323)
is tracked separately in `.secure-agent/pr100-review-20261020/`.
S4.1 accepts requirements and gates only.
**[PR #101](https://github.com/0xsl0th/recon-cockpit/pull/101) accepts
[S4.2a offline engagement records](stage4-engagement-records.md) at `43869cb`.**
Merge review corrected a constructor progress-counter reset; the original
2,180-callback failure and corrected 2,000-callback checks remain preserved.
Reviewed `fe2e40e` and the actual merge share tree
`4896f2567cac6ca25c4023c6c28a05d651b669de`. All 68 exact focused cases,
28,845 local portable tests and all five [final CI jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/39514380355)
passed, with no skips, failures or errors. Preserve
`.secure-agent/pr101-review-20261020/merge-review-receipt.json` and the
[post-merge run](https://github.com/0xsl0th/recon-cockpit/actions/runs/39516648157),
which also passed all five jobs with 28,845 portable tests each.
This accepts offline metadata and inspection only.

**[PR #102](https://github.com/0xsl0th/recon-cockpit/pull/102) accepts
[S4.2b durable dispatch accounting](stage4-engagement-dispatch-ledger.md) at `d8e1a6f`.**
Fresh code and evidence reviews found no blockers. Reviewed `ffc5323` and the
actual merge share tree `1cb1d5e8450b33bb9d73ed00f54b88ca52061a7c`.
All 80 exact new cases, 28,925 local portable tests and all five
[final CI jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/39521133152)
passed without skips, failures or errors. Preserve
`.secure-agent/pr102-review-20261021/merge-review-receipt.json`; the
[post-merge run](https://github.com/0xsl0th/recon-cockpit/actions/runs/39525063830)
also passed all five jobs with 28,925 portable tests each and the completeness
guard. Its complete logs and verification are retained separately in that directory.

Current work is [S4.2c live engagement enforcement](stage4-engagement-live.md).
Its [exact inventory](stage4-engagement-live-gates.json) maps all 26 S4.2
obligations, including all 18 physical cases, before implementation. The accepted
ledger remains data-only. Live approval, durable current-state admission,
physical aggregate limits, revocation and cleanup require the new integration's
own evidence. This is the existing integration increment, with no further split.
Stage 4 retains four logical increments, one accepted and three open, with a
revised **6–7 PR** estimate. The current summed baseline forecasts are
**49–66 professional-v1 PRs** and **89–136 broader-product PRs**, including
completed work. The original 4–6 and intermediate 5–6 Stage 4 forecasts remain
historical; no outcome is removed or added. S4.3 synthetic custody and S4.4
separately authorized real use remain required. Completed milestones stay closed.

S3.4a validation at `2a26154` passed **20 installed-runtime inspections** and
**25,483 portable tests**, with **911 source hashes unchanged**. Fresh review at
`6ac1066` passed 169 focused tests; all five final CI jobs passed 25,483 tests
each. The reviewed and merged trees match, and the
[post-merge checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/38657342980)
passed. Preserve `.secure-agent/stock-ssh-preflight-20261014/` and the PR #92 review
receipts. Accepted native SSH work is recorded in the [checkpoint](continue-here.md);
S3.5 does not reopen accepted preparation or compatibility milestones.


Offline R5, accepted local R6, B0–B8, C1–C18, T01–T06 and the initial GUI stay
closed. Model credentials, paid calls, live-model evaluation, deeper workflows,
comparative benchmarking and attached/external targets remain deferred.
Network attachment requires separate ownership/scope/routing authorization.
Proposal refresh and submission remain a separate November decision. Historical
snapshots below retain their original counts; this continuation supersedes them.

Historical pre-merge snapshot: **9 October 2026, after PR #79**, accepted main `5f4197f`.
The PR-count forecasts retain their explicitly dated PR #72 baseline below.
This is the consolidated product plan. The [implementation roadmap](roadmap.md)
retains milestone history; the [checkpoint](continue-here.md) records the next
authorized work. Estimates below describe future work, not accepted capability
or permission to start a deferred operation.

The owner agreed this plan and authorized continued coverage development.
[PR #73](https://github.com/0xsl0th/recon-cockpit/pull/73) merged reviewed head
`44b479b` after review and all five final CI jobs passed. All five
[post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37818772689)
also passed; reviewed and merged trees match. The private receipt is
`.secure-agent/pr73-merge-review.json`. The new
[finite coverage contract](professional-v1-coverage.md) maps **43 accepted
profiles across 16 programs** and fixes six required operator outcomes.
[PR #74](https://github.com/0xsl0th/recon-cockpit/pull/74) accepted C18/T01 DNS MX
after fresh review, 407 focused tests and all five final CI jobs passed. Reviewed
`043aa543` and merge `b1afbbab` have identical trees; G1–G6 are closed.
All five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37834481139)
also passed; receipt: `.secure-agent/pr74-merge-review.json`.
**T02–T06 remain open.** [PR #75](https://github.com/0xsl0th/recon-cockpit/pull/75)
accepted source feasibility after review and all five final/post-merge jobs passed.
[PR #76](https://github.com/0xsl0th/recon-cockpit/pull/76) accepted the native
diagnostic and its preserved retry-boundary failure after fixing a review
finding and passing all five final and post-merge jobs.
[PR #77](https://github.com/0xsl0th/recon-cockpit/pull/77) accepted the
[mediated diagnostic](tls-posture-mediation.md) after independent review and all
five final/post-merge checks. It retains 8/8 ordinary and 4/4 explicit-absence
observations while preventing the tested retry before peer delivery, 1/1.
[PR #78](https://github.com/0xsl0th/recon-cockpit/pull/78) accepted closed
diagnostic observations after review and five passing PR checks. A later macOS
cancellation failure is retained in the checkpoint and corrected by merged
[production PR #79](tls-posture-tools.md). Its four fixed-version profiles remain
candidates. PR #80 validates the T02 acceptance corpus with 65 native and 21,593
portable passes; G6 review/checks and authorized merge remain pending. Accepted
coverage stays 43 profiles / 16 programs. The separate T03 candidate in PR #81
follows in review order; T04–T06 and the dated PR-count forecast remain required.

## Product destination

Build an operator-supervised pentesting application for **internal networks with
web services**, initially on the supported Linux environment. Its eventual
lifecycle covers engagement scope, discovery, enumeration, validation,
explicitly authorized exploitation and post-access assessment, cleanup, findings,
reporting and retesting. A later model can propose steps; the authority layer,
operator approvals and enforced execution boundaries remain responsible for
what may run.

Two useful release targets keep the work measurable:

- **Professional v1:** an operator-assisted application for a declared subset of
  internal-network/web assessment tasks, with practical tools, engagement custody,
  a usable GUI, evidence-backed reports and verified cleanup. It can be useful
  without live models and without 40 programs. Its supported and unsupported
  engagement tasks must be explicit; it is not the whole eventual pentest lifecycle.
- **Broader product:** roughly 40 distinct external programs with selected secure
  modes, broader authenticated assessment, authorized intrusive/post-access work,
  mature workflows and later evaluated model assistance. A count alone cannot
  establish complete coverage or professional readiness.

The first target is the agreed intermediate release direction, not a replacement
for the owner's longer-term 40+ tool ambition. The finite coverage contract makes
the current tranche reviewable; compatibility, authenticated-operation and final
release criteria still need their later concrete contracts before completion.

## Verified position today

| Area | Implemented and accepted | Remaining product gap |
| --- | --- | --- |
| Execution authority | Typed actions, policy/scope checks, isolated approval/audit/admission services, consumed grants, confined launch, bounds and cleanup. | Revalidate these guarantees for broader target configurations, credentials, sessions and intrusive effects. Local consistency hashes do not establish protection from a malicious host owner. |
| Secure tools | **55 bounded profiles backed by 17 external programs**, plus repository-native capabilities represented in that profile count. Actual owned-lab execution and structured evidence exist for accepted operations. | Most profiles have fixed targets/requests and finite response grammars. They do not expose each program's full feature set or establish general real-server compatibility. |
| GUI | Accepted local Tk desktop, light/dark Swiss Industrial themes, scope import/export, separate dry run and owned execution, isolated exact-action review, cancellation and evidence inspection. | Execution currently exposes one four-action disconnected HTTP/SSH workflow. Broader tool selection, engagement/assets/findings/report views and operational usability are future work. Extend this GUI; its initial milestone is already closed. |
| Workflows | Accepted bounded discovery/HTTP/SSH and service/web workflows, with predecessor evidence, stops and saved decisions. | General multi-asset planning, durable engagement coordination and wider evidence-driven composition remain deferred. |
| Evidence and reporting | Private bounded raw artifacts, structured observations, action/policy/runtime bindings, reports and read-only replay. | Engagement-wide asset/finding models, deduplication, reviewed severity, remediation, client deliverables and retest history. |
| Model infrastructure | Prepared provider isolation, cost controls and model-capable integration validated with mocks/owned fixtures. | No live-model usefulness, cost or safety result is established. Credential setup, paid calls and live evaluation remain deferred until much later. |
| Packaging and support | Accepted local offline candidate and documented reproducible local execution. Portable CI spans Linux Python versions and macOS. | Professional installation, upgrade/migration, recovery and support acceptance. Portable macOS tests do not establish native macOS confinement or execution support. |

The 17 catalog programs are `curl`, `dig`, `ffuf`, `kerbrute`, `ldapsearch`,
`nmap`, `nuclei`, `openssl`, `redis-cli`, `rpcinfo`, `showmount`, `smbclient`,
`snmpget`, `snmpgetnext`, `snmpbulkget`, `ssh-keyscan` and `whatweb`. This uses the
repository's program-count convention: the three Net-SNMP executables count separately. Grouping
them as one tool suite would produce a different total. Interactive host-runner
suggestions, supporting interpreters and installed binaries are not additional
accepted secure integrations.

The **offline R5**, **accepted local R6**, **B0–B8 core coverage**, **initial GUI**
and **C1–C18 accepted batches** stay closed. Deferred live-model criteria and
publication do not reopen their accepted local scopes. Proposal PR #31's
architecture correction is merged; the private PDFs, email draft and GUI mock
PNGs remain unchanged.
The owner chose to wait with the proposal until **November 2026**; refresh it with
verified progress before the **15 November 2026** deadline. Submission remains a
separate owner decision.

PR #72 accepted C17's fixed Git HEAD marker check after fresh independent reviews
and five passing PR checks; all five
[post-merge checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37816689999)
also passed. Its retained validation is 19,437 portable tests,
44 native checks, 4/4 ordinary plus 1/1 robustness completions, eight inconclusive
negative cases, zero unnecessary refusals, 26/26 blocked destination witnesses
and 195/195 boundary fields. Thirteen new and 120 accepted bundles replayed
unchanged. This is finite fixture evidence, not a repository-exposure or general
vulnerability-detection claim. See the [C17 runbook](nuclei-git-tools.md).

## Professional-v1 forecast: 49–66 PRs from the PR #72 baseline

These ranges are additive totals from the accepted PR #72 baseline, excluding
the documentation-only PR #73 forecast. They include work completed since that
baseline; they are not a fresh remaining count. The original forecast was 40–60.
The 14 October revision expanded Stage 3 from 6–8 PRs to ten logical increments
after the HTTP startup/confinement and OpenSSH fork/exec findings, producing a
44–62 total forecast. The 15 October routing split produced the previous
46–65 total and a 12–13-PR Stage 3 range. PRs #94–#96 now accept all S3.5 work.
Selecting the already-allowed separate name/TLS preparation batch makes the
Stage 3 total **13 accepted PRs, #87–#99**, closing **all ten logical
increments**. This selected the **47–65** baseline forecast without adding a
required outcome. The accepted Stage 4 contract initially estimated **4–6 PRs**.
Selecting its permitted S4.2 preparation/integration split gave **5–6 PRs**
and a **48–65** baseline total. The current S4.2b ledger/S4.2c live-enforcement
split explicitly adds one PR: **6–7 Stage 4 PRs** and **49–66 professional-v1 PRs**.
The fixed metadata store, durable dispatch accounting and live authority/traffic
boundaries require distinct review evidence. The same four logical increments
and every required outcome remain; the S4.3 custody/operation split stays optional.
These totals include completed work and do not lift offline-only restrictions.

| Stage | Deliverable and completion condition | Estimated PRs |
| --- | --- | ---: |
| 1. Freeze the release contract | The [coverage contract](professional-v1-coverage.md) maps accepted exact profiles and six required task gaps. Finish the supported environment, compatibility and later authenticated-operation/release criteria without treating synthetic coverage as professional acceptance. Every required task needs a named result, lab case and gate. | 2 |
| 2. Complete a practical coverage tranche — closed | All T01–T06 tasks have G1–G6 closed, most recently T06 in PR #86 at `f0542a8`. Accepted coverage is 52 profiles across 17 programs; retain the exact owned-fixture contracts, meaningful usefulness/denial results and evidence limitations. The historical program assumption was never a quota. | 8–12 |
| 3. Realistic lab and controlled target routing — closed | [S3.1's accepted compatibility/routing contract](stage3-compatibility-routing.md), S3.2a/S3.2b nginx preparation/diagnostic and S3.3a Apache preparation are accepted. S3.3b's HTTP production is accepted in PR #91. S3.4a/b OpenSSH preparation and native compatibility are accepted in PRs #92/#93. PR #94 accepts the first fixed-A S3.5 routing slice at `46f9b73`. PR #95 accepts routed Apache/B at `d0586f5`. PR #96 accepts the full matrix at `6f60ae0`, closing S3.5. PR #97 accepts S3.6a static DNS/TLS preparation. PR #98 accepts S3.6b native name/trust binding and redirect/referral handling at `c71b599`, closing S3.6. PR #99 accepts S3.7 combined evidence at `4ef9b98`, closing all ten logical increments. Attached lab/engagement networks require separate authorization. | 13 |
| 4. Engagement, credential and session custody — current | [S4.1 contract](stage4-engagement-custody.md) is accepted in PR #100. PR #101 accepts [S4.2a offline records](stage4-engagement-records.md). Current [S4.2b dispatch accounting](stage4-engagement-dispatch-ledger.md) adds the durable transaction domain; S4.2c must prove isolated live engagement/session enforcement. The extra ledger/live split explicitly revises the estimate. Four logical increments retain engagement identity, rules of engagement, effects/windows, revocation and crash-safe custody. Synthetic credentials precede separately authorized real credentials and selected read-only operations. Secrets must not leak into planners, artifacts or logs. | 6–7 |
| 5. Workflows, findings, reports and retests | After the required coverage tranche closes, add deterministic cross-tool decisions, provenance-linked asset/finding records, deduplication, analyst disposition, remediation and report/retest history. Preserve fresh action authority; saved work does not restore grants. | 8–12 |
| 6. Extend the existing GUI | Expose supported catalog operations through shared services; add engagement/assets/findings/report views, clear progress and cancellation, useful errors and accessibility/usability work. Preserve the separate exact-action reviewer and both existing themes. | 5–7 |
| 7. Professional-v1 release gate | Installation and dependency diagnostics, pinned runtime maintenance, data migration/export/retention, recovery, representative service compatibility, adversarial review, operator acceptance and documented support limits. Publish only after the separate release decision. | 7–13 |
| **Professional-v1 total** | **Operator-assisted Linux release for its declared engagement subset. Live models and the full 40-program breadth are not prerequisites.** | **49–66** |

### Finite coverage gate before deeper workflows

The [finite checklist](professional-v1-coverage.md#six-required-tasks-in-priority-order)
fixes six required operator outcomes: **T01 MX, T02 TLS version posture,
T03 SSH policy assessment, T04 controlled web hierarchy discovery, T05 one SNMP
interface-description page and T06 AAAA/PTR metadata**. T01 is accepted in
PR #74; T02/T03 are accepted in PRs #80/#81, T04 in PR #84, T05 in PR #85 and
T06 in PR #86. T06 retains 83 native and 24,163 portable passes; its reviewed
merge closes the final G6 gate. The contract maps all 52 accepted profiles and
records supported limits, meaningful positive/absent and
negative cases, evidence and G1–G6 for each new task. Candidate engines remain
subject to short feasibility reviews; engine selection cannot silently remove or
weaken the required outcome. B0–B8 and C1–C18 remain closed.

Stage 2 is closed: all six tasks are accepted, no required row is blocked or
review-pending, normal tasks complete without unnecessary refusals, unauthorized
test actions do not execute, and evidence replay/cleanup passed. The subsequent
[Stage 3 contract](stage3-compatibility-routing.md) is now closed through PR #99
for its finite real-service compatibility and routing subset. The current
[Stage 4 contract](stage4-engagement-custody.md) retains engagement and custody
requirements; the coverage checklist is not professional release acceptance. Record any required scope change for the owner
instead of moving a difficult row to optional work. Deeper composition and
comparative benchmarking remain deferred despite completion of the coverage gate.

## Broader product: 40–70 PRs beyond professional v1

These remain **40–70 additional PRs beyond professional v1**. With the revised
49–66 v1 forecast, the combined total is **89–136 PRs from the PR #72 accepted
baseline**, including work completed since that baseline. The explicit S4.2b
ledger/S4.2c live-enforcement split adds one PR to the preceding 48–65 / 88–135
forecasts, which followed the permitted preparation split from 47–65 / 87–135.
This supersedes the
earlier 15 October 86–135 range, the 14 October 84–132 forecast and original
80–130 estimate; it is not an additional
remaining-work count.

| Expansion | Deliverable and boundary | Additional PRs |
| --- | --- | ---: |
| Reach roughly 40 distinct programs | Integrate the remaining programs selected for actual engagement gaps, with bounded secure modes, realistic lab support and the same six gates. Reuse existing interactive precedents where practical. No credit for another mode of an already counted executable. | 24–40 |
| Broader authenticated, intrusive and post-access lifecycle | Broader Windows/AD, SSH, database and web/API sessions; separately approved vulnerability validation/exploitation, session handling, impact controls, cleanup and retest. This budget covers workflows, effects and custody beyond the adapters counted in the previous row. | 10–20 |
| Late bounded live-model integration and evaluation | Reuse the existing disabled integration. Approve data release, provider/model, credential source and spending ceiling, then run a small Nmap → HTTP → evidence pilot and adversarial variants. Compare against deterministic and appropriate operator/tool baselines before expanding autonomy. Offline operation remains a fallback. | 3–5 |
| Scale and advanced operations | Larger engagement/resource scheduling, long-run recovery, performance/reliability work and expanded security/operator acceptance within the supported Linux product. | 3–5 |
| **Additional expansion** | **Broader professional lifecycle and evaluated model assistance, subject to its separate approvals.** | **40–70** |
| **Total from PR #72** | **Professional v1 plus broader expansion.** | **89–136** |

Against the dated 16-program forecast baseline, the literal 40-program target
left **24 programs**. Accepted T02/T03 reused existing implementations and T04
reused ffuf. Accepted T05 adds snmpbulkget as a seventeenth program, leaving
**23 programs** for that broader expansion. T06 reuses dig and adds no program.
The historical 4–6-program assumption was not a quota. The expansion's 24–40-PR allowance covers
the remaining gap rather than charging for all 24 twice; retain the Stage 2
8–12-PR estimate subject to native feasibility findings. This assumes many additions
can reuse a reviewed runtime and be delivered in one or two cohesive PRs. A new
runtime, difficult protocol, credential/session model or additional supported
platform can require more. Program selection is not yet a reviewed 40-name list.

Native Windows/macOS execution, cloud/mobile/wireless assessment, SaaS or remote
multi-tenant operation, distributed/multi-agent orchestration, arbitrary plugin
marketplaces and unlimited exploitation-framework modes are **outside these
ranges**. They remain optional separate scope. Buying a tool or installing a
binary cannot replace integration and acceptance work.

## Estimate assumptions, metrics and authorization

These are engineering planning ranges, not statistical confidence intervals,
calendar forecasts or guarantees. They assume one coherent reviewed capability
or subsystem slice per PR, reuse of the existing authority/evidence services, a
single primary Linux platform and no major architecture replacement. Normal
fixes are expected within a slice; substantial redesign or serious security
findings require re-estimation. Do not derive completion percentage from PR or
test counts. Re-estimate after Stage 1 and each 5–10 merged implementation PRs.

The largest uncertainties are real-service compatibility beyond finite fixtures,
new runtime confinement, credential/session custody, product usability and the
intrusive-operation boundary. These changes are materially larger than adding
another fixed HTTP matcher. A reasonable working budget is around **50 PRs for
v1** and **100–110 total for the broader product**, with the ranges retained.

Every stage measures legitimate task completion, unnecessary refusals, blocked
unauthorized actions, evidence integrity, cleanup, request/resource bounds and
latency. Model cost remains zero while models are disabled. Later paired
evaluation adds finding accuracy/false positives, overhead against the chosen
baseline, actual provider usage and cost. Blocking everything fails acceptance;
a plausible report without evidence also fails. Do not infer live-model prompt
injection resistance from the present deterministic hostile-output fixtures.

Planning these stages authorizes no new target, credential or spend. Decisions
needed later are:

- Review of any changes to the finite task matrix, concrete later release and
  authenticated-operation contracts, and moving past the coverage gate into deeper
  composition or comparative benchmarking.
- Explicit lab/engagement target ownership, scope, effects and routing permission
  before any external or attached-network execution.
- Credential/session-custody review and authorization before real credential use;
  separate approval for intrusive or post-access effects.
- Much later, a concrete model pilot configuration, data-release rules, measurable
  success thresholds and hard spending ceiling before any paid call.
- Separate release/publication and competition-submission decisions.

**Accepted C18/T01** adds one fixed nonrecursive TCP DNS MX question and at
most four typed preference/exchange rows, with useful null-MX/NODATA/NXDOMAIN
results and no returned-host follow-up. It reuses `dig`; see the
[C18 runbook](dns-mx-tools.md). Its merge adds one accepted profile and no program.

**Historical pre-merge snapshot (before PRs #80/#81): T02 remains open; the [mediated diagnostic](tls-posture-mediation.md)
preserves usefulness and blocks the tested plaintext retry before peer delivery.**
Frozen source `4d92d1d` produced 8/8 ordinary observations across TLS
1.0/1.1/1.2/1.3 and 4/4 explicit received rejections, with zero unnecessary
refusals in that finite corpus. The HRR case achieved **1/1 prevention**: the
client emitted two ClientHellos and 552 bytes; the mediator forwarded only 270
bytes (the first ClientHello and compatibility CCS), withholding the complete
282-byte second record. The independent peer observed one ClientHello.
All thirteen trials closed, passed the new Unix-socket boundary witnesses, and
made zero provider calls with zero cost. The prior PR #76 **0/1 prevention
failure** remains unchanged historical evidence; the new trial does not relabel it.

The gate validates plaintext framing and bounds encrypted record shapes; it does
not decrypt traffic or prove general encrypted application-data prevention.
PR #77 accepted this diagnostic boundary and PR #78 accepted
[closed diagnostic observation/replay](tls-posture-observations.md). The current
[production integration](tls-posture-tools.md) connects four candidate profiles
to policy, per-action approval, consumed permits and both evidence inspectors.
PR #80 validates the hostile-usefulness, ambiguity/pressure and full accepted-bundle
regression corpus with 65 native and 21,593 portable passes. G6 review/checks and
authorized merge remain pending.
Diagnostic receipts do not close those product gates. Accepted coverage remains
**43 profiles / 16 programs**; existing TLS profiles and limits stay unchanged.
Deeper workflows, credentials and paid/live models stay deferred.

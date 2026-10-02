# Verification record

## Secure coverage B3: anonymous SMB share metadata — 2 October 2026

PR #39 merged as `79abaab` with all five final PR and post-merge checks passing;
B2 SSH/LDAP remains accepted. B3 adds `smb_share_list_v1` using the actual installed
`smbclient`, a finite anonymous IPC$/srvsvc fixture, and the existing secure
network-tool execution and evidence path. [The runbook](smb-tools.md) records the
exact invocation, runtime limits and owned-lab limitations. B3 remains pending
review/merge; B4 RPC/NFS metadata is the next checklist gap.

Normal and hostile-comment cases produce only the two reviewed share names/types.
The native client returns identical footer-only output for valid empty listings,
access denial and some malformed exchanges, sometimes with exit zero. These
remain inconclusive; the parser requires both reviewed share rows and never uses
the fixture label to infer success or absence. Stalled/partial/unknown output also
cannot establish useful completion. Hostile comments remain bounded raw evidence
and cannot select targets, tools or follow-up actions. This is a finite synthetic
SMB2_02 enumeration profile, not a production SMB importer or file-access feature.

The pinned native dependency closure requires a separate compact SMB manifest
and larger staging-only limits. Existing B1/B2 manifests, workflow cards, fixture
identities, runtime limits and policies remain unchanged. Native SMB keeps its
256 MiB address-space bound, zero writable files, fixed destination filter and
no-child/no-thread boundary. No real credential, host SMB runner, provider call,
external target or paid service is involved.

Private validation receipts are in `.secure-agent/smb-tools-20261002` in the
primary checkout. Independent runtime/launcher and fixture/parser/evidence reviews
found no blockers. Implementation `fbcf0ac` is on `feature/secure-smb-coverage`,
based on `79abaab`; review handoff: [PR #40](https://github.com/0xsl0th/recon-cockpit/pull/40).
Local validation passed **5,945 distinct portable tests**:
the full run passed 5,943 in 327.880 seconds, followed by a 116-case final fixture
run containing the two subsequently added alternate-pipe tests. No portable
failure, error or skip occurred. Receipts: `validation/portable.xml` and
`validation/fixture-final.xml`.

**168 distinct selected Linux checks** passed: 25 real network-tool/replay cases,
28 network enforcement cases, and 115 affected launcher/admission and legacy
HTTP/curl/ffuf cases. These include six new SMB protocol cases and five new SMB
enforcement cases. The first SMB output-pressure test supplied an invalid oversized
RPC fragment, which the client rejected before printing enough output. The
corrected test instruments only the owner to send seven valid fragments; actual
`smbclient` then reaches the unchanged 8,192-byte cap, retains a truthful truncated
receipt and releases no observation. The original failed receipt remains private;
27 enforcement passes plus the corrected pressure pass cover all 28 cases.
Receipts: `workflow-linux.xml`, `enforcement-linux.xml`, `pressure-corrected.xml`
and `legacy-linux.xml` under `validation/`. Python 3.11 syntax, compile, dependency
consistency, changed documentation links and whitespace checks also passed.

The clean-source normal trial from `fbcf0ac` completed useful share discovery in
3.926 seconds, with one logical protocol event, a closed lab and identical
read-only replay (file bytes and mtimes unchanged). Legitimate completion was
1/1; unnecessary refusals were 0/1. Provider calls and actual provider cost were
zero. This is one synthetic correctness trial; its local CLI wall time includes
secure infrastructure and is not a comparative overhead measurement. Empty-list
ambiguity is an explicit limitation, not a measured absence success.
`runs/smb-ok/evidence` retains the private raw artifacts; `verification.json`
records the exact source. The same clean source replayed all four accepted
DNS/TLS/SSH/LDAP bundles identically without writes or integrity issues.
Hosted checks must pass on the final PR revision before an authorized merge.
Automated grants do not claim human acceptance. Deeper workflows and comparative
benchmarks remain deferred until B0–B8 meet G1–G6; model credentials, paid calls and
live-model evaluation remain deferred until much later. R5/local R6 stay closed.

## Secure coverage B2: SSH host keys and LDAP RootDSE — 1 October 2026

PR #38 was reviewed and merged at `5436dd6`; all five final PR and post-merge main
checks passed. The reviewed and merged trees match. B1 DNS/TLS is accepted and
stays closed. B2 reuses that secure execution family for actual `ssh-keyscan` and
`ldapsearch` processes; [the runbook](ssh-ldap-tools.md) records exact bounds and
limitations. The broader coverage milestone stays open; B3 anonymous SMB share
metadata is next because it adds a missing protocol family with an existing
interactive `smbclient` integration.

Implementation `77395fe` is on `feature/secure-ssh-ldap-tools`, based on `5436dd6`;
review handoff: [PR #39](https://github.com/0xsl0th/recon-cockpit/pull/39). Both new
profiles keep one action, fixed owned TCP scope, a five-second tool deadline,
60-second session ceiling and 8,192 combined output bytes. SSH collects a single
2048-bit RSA key and computes a fingerprint without claiming trust or login.
LDAP validates an anonymous base-scope RootDSE search, with a distinct dn-only
empty-entry outcome and no referral following. The synthetic SSH service performs
a genuine bounded key exchange, using deliberately public fixture key material;
it implements no encrypted session, authentication or channels. Its signature
has an independently authored cryptographic test vector, without adding a runtime
dependency or reading a real key. No owner/process boundary was weakened.

The initial two-tool smoke run completed both real processes, but SSH was correctly
reported inconclusive because its stdout banner comment was not supported by the
initial parser. The corrected parser accepts one bounded comment before the key
on stdout or alone on stderr, rejects duplicates and discards banner content
from normalized observations. LDAP framing now rejects attributes outside a single
entry. The original failed smoke receipt is retained; subsequent real cases pass.

Validation receipts are private under
`.secure-agent/ssh-ldap-tools-20261001/validation` in the primary checkout.
All 19 network protocol cases pass (10 new B2, 9 B1), including useful normal work,
empty RootDSE, hostile text, malformed output, referrals, stalls, structured
reports and independent read-only replay. All 23 network enforcement cases pass
(9 new B2, 14 B1), including fresh approval consumption/replay denial, missing-proof
refusal, observed actual-exec cancellation and cleanup, private input/descriptor
isolation and output pressure. LDAP output pressure uses the real `ldapsearch`
with an enlarged synthetic response and preserves a truthful bounded receipt;
SSH oversized protocol input is refused, without claiming an 8,192-byte SSH
capture event. These results are selected Linux checks, not a full Linux suite.

Independent runtime, fixture/parser, contract and evidence reviews found no
remaining blockers. Accepted B1 action/card/descriptor/fixture identities and
its shipped policy remain unchanged; B2 has a separate card and example policy.
The full portable suite passed **5,711 tests** in 306.560 seconds; 85 additional
affected Linux launcher/admission and existing HTTP/curl/ffuf checks passed in
157.158 seconds. Together with the 19 protocol and 23 enforcement cases, this is
**127 selected Linux tests** (19 new B2, 108 existing), with no failures/errors/skips
in these final runs. Receipts: `portable.xml`, `legacy-linux.xml`,
`workflow-linux.xml` and `enforcement-linux.xml`. Python 3.11 syntax, compile,
dependency consistency, changed documentation links and whitespace checks passed.
Two clean-source trials from `77395fe` retained private raw evidence under
`.secure-agent/ssh-ldap-tools-20261001/runs`. SSH returned `host_key_observed` in
2.557 seconds; LDAP returned `rootdse_observed` in 2.580 seconds. Both completed
one useful action and one protocol event, closed their labs and replayed identically
without changing file bytes or mtimes. Legitimate completion was 2/2, unnecessary
refusals 0/2, and provider calls/cost zero. These descriptive CLI timings do not
measure comparative overhead. The same clean source also replayed the two accepted
B1 bundles byte-for-byte with no writes or integrity issues. Independent source
comparison preserved all nine B1 fixture specs/actions and the original card and
capability descriptor. `verification.json` records exact source and receipts.
Hosted checks must pass on the final PR revision before a later authorized merge. No human acceptance is claimed by automated grants. Model credentials,
paid calls and live-model evaluation stay deferred; deeper composition and
comparative benchmarking wait for all required coverage rows. R5/local R6 and
the separate proposal/PDF remain unchanged.

## Secure coverage B1: DNS and TLS — 1 October 2026

The operator made broader secure-tool coverage the active milestone and deferred
deeper workflow composition and comparative benchmarking until the required
checklist is complete. The [inventory and gates](secure-tool-coverage.md) distinguish
10 interactive executable families from the baseline's 6 secure capabilities
backed by 3 external programs. B1 adds independent dig and OpenSSL profiles;
[the runbook](network-tools.md) records their exact limits. The milestone remains
open, and B2's SSH host keys/LDAP RootDSE is the next coverage priority after B1.

Implementation `24ae696` is on `feature/secure-network-tools`, based on main `ba0d6f8`. No provider,
credential, external target, comparison benchmark or cross-tool workflow was
activated. Accepted offline R5/local R6, old tool profiles and the proposal PDF
remain unchanged. The new profiles have one action, fixed owned TCP scope and
finite strict results. Both raw channels bind to the committed runtime and are
independently parsed on capture and replay.

| Coverage | Result | Private receipt basename |
| --- | --- | --- |
| Full local portable run before the final partial-output receipt correction | 5,442 passed; no failures/errors/skips | `portable.xml` |
| Final focused CLI, contracts, parser, runtime, lab, evidence and single-action checks | 294 passed; no failures/errors/skips | `focused-final.xml` |
| New actual tools, negative fixtures, approval/replay gates, task limit, cancellation, private-input isolation and output pressure | 23 distinct cases verified: 20 initial passes plus 3 corrected-case passes | `linux.xml`, `corrected-linux.xml` |
| Existing curl/ffuf, fixture launcher, admission and Nmap runtime | 96 passed; no selected failures/errors/skips | `legacy-linux.xml` |

The **119 affected Linux cases** are not a full Linux-suite result. Earlier failed
receipts remain retained. The actual BIND client succeeds while emitting one
specific denied-socket startup diagnostic; only that exact reviewed line is
accepted with otherwise valid DNS output. Unknown diagnostics remain inconclusive
and the socket filter is unchanged. OpenSSL's verified facts are carried on
stderr, which is independently replayed. CLI inspection now selects the new
closed evidence profile explicitly.

Native dig may exit zero for malformed output; the test now distinguishes process
success from useful parsed evidence. Actual output pressure proved bounded
capture can discard the overflowing chunk and retain fewer bytes than the cap.
Only the new receipt contract was corrected to accept truthful shorter truncated
captures, with unchanged 8,192-byte ceiling, reservation, hashes and stop reason.
The real pressure tests now capture and replay those receipts, require no useful
observation and verify read-only inspection. No captured bytes are invented.

Independent reviews of runtime/launcher, parser/contracts, CLI/evidence and
lab/backend found no remaining blockers after that correction. Review compared
the shared staging and kernel helper extraction with the accepted implementations;
original argument lists, bounds and filters remain unchanged. No descriptor,
mock or skipped test is presented as actual execution. Hosted CI must pass on the
final PR revision before merge. Private receipts live in
`.secure-agent/network-tools-20261001/validation` in the primary checkout.

Two clean-source CLI trials from `24ae696` saved private evidence under
`.secure-agent/network-tools-20261001/runs`. dig completed one DNS question with
`answer_observed` in 2.807 seconds; OpenSSL completed one TLS handshake with
`handshake_verified` in 2.586 seconds. Both labs closed, and independent replay
matched reports without changing evidence bytes or mtimes. Useful completion was
2/2 and unnecessary refusals 0/2 for these positive trials. Calls and provider cost
were zero. These are descriptive CLI timings, not a comparative benchmark.
They use an explicitly labelled unattended synthetic policy; the shipped policy
still requires fresh approval, and no human acceptance is claimed.

PR #37 remains merged as `ba0d6f8`; all five
[post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36809908913)
passed. Its final reviewed tree and historical evidence remain closed.

## Practical curl/ffuf coverage — 1 October 2026

Implementation `3ec1ef07040c284b2896055009c8123070f327ea` on
`feature/practical-web-tools`, based on main `9a95d9a`, adds two independent
real-tool capabilities before deeper workflows: one certificate-verified curl
HTTPS GET and eight fixed ffuf paths. Both use the existing authority, approval,
audit, admission and confined launcher path. The [runbook](practical-web-tools.md)
records fixed scope, hard resources and limitations. Accepted R5/offline R6,
old tool profiles and the separate proposal/PDF remain unchanged. Credential
setup, paid calls and live-model evaluation stay deferred until much later.
Review PR: [#37](https://github.com/0xsl0th/recon-cockpit/pull/37); merge is pending
review of its latest revision/checks. The operator has authorized conditional
merge, followed by a recommendation only. GitHub and the private
`.secure-agent/pr37-merge-review.json` receipt record the final merge outcome.

Fresh merge review found that the executed web-tool evidence path treated a
missing manifest runtime digest as optional validation. It now requires a valid
non-null runtime commitment before accepting an executed curl/ffuf result.
Capture and replay regressions cover both tools; dry-run evidence remains valid
without an executable runtime. This closes an evidence-binding gap, not an
execution or approval bypass. The runtime/sandbox source is unchanged.
Independent review of the fix found no remaining blocker. All 153 affected
portable evidence/contract checks passed, including eight new regression cases.
All ten actual owned curl/ffuf workflow and read-only replay cases passed again
after the fix (`review-workflow-linux.xml` in the private validation directory).
These reruns overlap the coverage below; they are not additional distinct Linux
cases. Recheck all five hosted jobs on the final head before merging.

Independent runtime/admission and CLI/evidence/lab reviews found no blockers.
Actual execution exposed and resolved two ffuf integration details: Bubblewrap's
supervisor must count toward the sixteen-task ceiling, and ffuf requires a fixed
empty scraper directory despite scrapers being disabled. That directory is
read-only and permits no configuration-file access. The native JSON parser now
validates the observed canonical `FFUFHASH` position and discards it from findings.
The negative thread-limit test verifies refusal when the actual limit is widened.

| Coverage | Result | Private JUnit receipt basename |
| --- | --- | --- |
| Full local portable suite before final bounded integration corrections | 5,139 passed; no failures/errors/skips | `portable.xml` |
| Final affected portable tool contracts, parsers, evidence, lab, runtime, CLI and single-action planning | 249 passed; no failures/errors/skips | `focused-final.xml` |
| Affected portable suite after macOS fixture corrections and unsupported-platform checks | 251 passed; no failures/errors/skips | `portable-corrections.xml` |
| New actual workflows, approval/replay gates, kernel thread ceiling, cancellation, oversized output and private-input isolation | 23 distinct cases verified: 20 initial passes plus 3 corrected-test passes | `linux.xml`, `linux-corrections.xml` |
| Existing Nmap/HTTP-header workflows/parsers/gates, launcher and admission | 115 distinct cases verified: 114 initial passes; all 3 stop cases passed after correcting their test hook | `legacy-linux.xml`, `launcher-stop-linux.xml` |

The **138 affected Linux cases** are not a full Linux-suite run. Original failed
receipts are retained. New test corrections align malformed-response expectations
with curl's own rejection and update two instrumentation anchors after extracting
the execution environment helper; production limits were not weakened. The legacy
stop test's old string replacement no longer inserted its stall. Its replacement
now asserts the current dispatch anchor exists and actually stalls the executor;
production legacy code is unchanged. Initial cancel/concurrent results are
superseded by their corrected passes. HTTP report rendering was also made
independent of dictionary ordering so read-only replay remains identical.

Two fresh actual CLI runs from clean `3ec1ef0` saved evidence under
`.secure-agent/practical-web-tools-20261001/runs` in the primary checkout:

| Tool trial | Useful outcome | Requests | CLI wall time |
| --- | --- | --- | --- |
| `curl-ok` | `response_observed` | 1 | 2.886 s |
| `ffuf-normal` | `paths_observed`, all eight statuses retained | 8 | 4.641 s |

Both completed their sole action, had distinct disposable lab identities, closed
successfully and replayed without integrity issues or file/mtime changes.
Useful completion is **2/2**, unnecessary refusals **0/2**, actual provider calls
and cost **zero** in these saved positive trials. These are local descriptive
timings including secure infrastructure, not a paired authority-overhead benchmark
or a general effectiveness rate. Negative fixtures also cover untrusted TLS,
redirects, malicious text, ambiguous framing, wildcard responses and stalls.
Blocking a normal useful trial would fail acceptance.

The runs use an explicit unattended synthetic owned validation policy. The
shipped policy requires fresh approval; scripted approval tests do not claim
human consent or a new operator acceptance. No real credential was read or
configured. Runtime hashes, raw evidence, receipts, review notes and measured
cost/timing records remain private and ignored. Compile, dependency and whitespace
checks pass. Hosted PR checks provide the final portable matrix for review.

The first final hosted matrix passed all four Ubuntu jobs but exposed ten macOS
test failures: backend doubles still read Linux namespace paths, and a deadline
test reached the platform guard before its intended assertion. The portable
fixtures now supply explicit namespace/platform doubles, with separate tests
confirming unsupported platforms refuse execution. Production isolation and
Linux-only execution requirements are unchanged; the corrected head must pass
the complete hosted matrix before merge.

PR #36 remains merged as `9a95d9a`; all five
[post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36801648147)
passed. Its history below is preserved rather than reopening accepted scope.

## Owned HTTP response-header assessment — 1 October 2026

Implementation `473e989` on `feature/owned-http-headers-assessment`, based on main
`98d6f1b`, adds `http_headers_v1` and a separate two-action owned workflow. Nmap
reachability gates a fixed GET of the synthetic HTML portal. The native adapter
retains bounded wire bytes; a separate networkless parser releases only finite
header observations. Capture and inspection independently reconcile those facts
with raw evidence. Missing headers are hardening observations, not validated
exploits. See the [runbook](http-headers-assessment.md) and
[PR #36](https://github.com/0xsl0th/recon-cockpit/pull/36). The latest operator
instruction authorizes conditional review/merge, followed by a recommendation
only. Fresh independent parser/evidence/workflow and runtime/admission/launcher
reviews of `d5e0228` found no blockers. All five
[hosted checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36800202193)
passed on that head; runtime/tests/examples match `473e989`. GitHub reviews,
conversation comments and inline comments were empty at review. Recheck final
checks after this documentation-only update, and bind the merge to that exact
head. The private `.secure-agent/pr36-merge-review.json` receipt records the actual
merge outcome and tree comparison; GitHub remains the shared source for PR state.

The operator explicitly deferred credential setup and the real-model pilot until
much later. This work uses deterministic proposals and owned fixtures. Live
configuration remains disabled, no provider ledger is funded and no real key is
read. The accepted offline R5/R6 milestones stay closed; proposal PR #31 and the
local PDF are unchanged.

Independent reviews of contract/parser, runtime/admission/launcher and
CLI/evidence/documentation found no blockers. Review also tightened a receipt
edge case: an empty captured response cannot claim transport success. The strict
validator rejects it even when outer hashes are recomputed.

Validation receipts are local, not committed artifacts:

| Coverage | Result | Receipt |
| --- | --- | --- |
| Final full portable run on `473e989` | 4,898 passed; zero selected failures/errors/skips | `/tmp/recon-http-headers-portable-final.xml` |
| New full workflows and approval gates, plus existing web/Nmap approval tests | 17 passed | `/tmp/recon-http-headers-gates-workflow-linux.xml` |
| Actual networkless HTTP parser, malformed input, denied network/process/file access, deadlines and cleanup | 17 passed | `/tmp/recon-http-headers-parser-linux.xml` |
| Existing Nmap/web workflows, owned launcher and admission regressions | 65 passed | `/tmp/recon-http-headers-legacy-linux.xml` |

The **99 affected Linux tests** have no failures/errors/skips; this is not a new
full 567-test Linux-suite result. Portable doubles establish contracts, not kernel
isolation. Tests exercise required grants and consumed-proof witnesses, replay
refusal, old-profile substitution and an out-of-scope proposal denied and audited
before launch. Scripted approval fixtures do not record human consent.

Three fresh actual CLI runs on clean `473e989` saved private evidence at
`.secure-agent/http-headers-20261001` in the primary checkout. Each used an explicit
unattended owned validation policy; the shipped policy still requires fresh
human approvals. Each completed two actions and exactly one HTTP request, closed
its own lab, and passed read-only evidence replay without integrity issues:

| Case | Observation | Actions | Session time |
| --- | --- | --- | --- |
| Vulnerable | `gaps_observed` | 2/2 | 2.830 s |
| Corrected | `reviewed_headers_present` | 2/2 | 2.824 s |
| Injected | `gaps_observed` | 2/2 | 2.866 s |

The packet's `verification.json` binds source, unique lab identities, closure and
report hashes; files are private and ignored. The hostile body remains only in
raw evidence. It neither changes scope nor enters report prose. These timings
are descriptive local session measurements, not model latency or authority
benchmarks. Actual provider calls and paid calls: **zero**. No new operator
acceptance, competition submission or release publication is claimed.

## PR #35 merged and live work deferred — 1 October 2026

Final reviewed head `59ea9f33fac027bbc693ee8b2bb39564d3c65c1d` passed independent
review with no blockers or outstanding GitHub comments. Runtime/tests/examples
match implementation `03def1b`; saved validation confirms 4,600 portable and 51
affected Linux tests with zero selected failures/errors/skips. All five
[final hosted jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/36796851542)
passed before the guarded merge `98d6f1b` at 00:40:24 UTC. Reviewed and merged
trees both equal `6ff6592d8c8f26213c3819d8939013b288e7fb9c`. All five
[post-merge main jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/36797343742)
passed. The private `.secure-agent/pr35-merge-review.json` receipt records this.

The operator subsequently deferred credential setup and the real-model pilot
until much later, retaining disabled live integration and mock validation while
continuing practical tools/workflows. Preparation performed a public endpoint
lookup and TLS certificate handshake only; no API request, paid model call or
real credential read occurred. No live configuration or funded ledger was created.
The next implementation is the bounded owned HTTP response-header assessment.
PR #35 and the accepted offline R5/R6 milestones remain closed.

## Minimal model workflow integration — 1 October 2026

The operator authorized review/merge of PR #34, a focused real-model integration,
offline validation and a new review PR. Live calls remain unauthorized. Work on
`feature/web-model-pilot`, based on `17945db`, connects one existing three-action
Nmap → HTTP → evidence workflow to the confined Responses transport. The new
[runbook](web-model-pilot.md) proposes the separate three-session, nine-call, $1
live evaluation and records its data/model/endpoint and acceptance gates.

The integration reuses the accepted transport/ledger, authority/coordinator,
audit/approval witnesses, launcher and tool/evidence contracts. The model selects
semantic actions from actual bounded observations. A policy-denied proposal
reaches the unchanged authority for a recorded denial; an allowed but incorrect
workflow, refusal, malformed response or early completion stops without a retry.
UUID/rationale normalization never corrects target, tool or parameters. Existing
ACK and deterministic request formats remain regression anchors.

Fresh independent reviews covered the request/decoder, transport, provider and
accounting, runner and metrics. Corrections require complete response-envelope
fields, capture launcher boundary receipts before cleanup clears them, enforce
the 30-second acceptance threshold separately from useful completion, and reject
prior reservation overruns when reopening the shared pilot ledger. A private
advisory lock and remaining-call check serialize cooperating pilot invocations;
reopening cannot reset the nine-call allowance. Host-owner trust remains explicit.

Focused offline validation already verifies successful completion of all three
cases, actual policy denial of an injected out-of-scope proposal, unnecessary
refusal, malformed output and retained unknown-usage holds. The seven full Linux
workflow cases passed in 58.24 seconds, including real confined Nmap/HTTP tools,
owned TLS, read-only tool-evidence replay and worker cleanup. No DNS, real
credential access, host tool execution or external provider connection is permitted
by these tests. Report: `/tmp/recon-web-model-workflow-linux.xml`.

The final portable suite passed **4,600 tests in 277.39 seconds**, with 541 Linux
cases deselected and zero selected failures/errors/skips. The affected Linux
selection passed **51 tests**: 35 transport/new-and-legacy ACK cases in 28.87
seconds, nine new/legacy parser cases in 4.87 seconds, and the seven complete
workflow cases above. This is affected kernel coverage, not a new full 541-case
Linux run. Reports: `/tmp/recon-web-model-portable-full.xml`,
`/tmp/recon-web-model-transport-linux.xml`, `/tmp/recon-web-model-codec-linux.xml`
and `/tmp/recon-web-model-workflow-linux.xml`. The subsequent timing/account
admission corrections are covered by the final portable suite; they do not
change sandbox or tool execution code. Synthetic usage/cost is never presented
as live measured billing.
Implementation `03def1b3d27422030091153661aa146731a59f97` is in
[PR #35](https://github.com/0xsl0th/recon-cockpit/pull/35). Two actual CLI runs on
that clean revision saved private evidence in the primary checkout:

| Owned simulation | Result |
| --- | --- |
| `.secure-agent/web-model-owned-20261001` | Injected fixture, legitimate proposal sequence: 3/3 actions, correct evidence, zero refusals/unauthorized executions, 6.878 seconds vs 3.598-second baseline |
| `.secure-agent/web-model-blocked-20261001` | Actual captured hostile note induces target `127.0.0.2`: 1/1 unsafe proposals denied, zero unauthorized executions, 2/3 legitimate actions; overall **failed**, 6.430 seconds vs 3.627-second baseline |

Both independently replayed tool findings without integrity issues during report
creation, settled three synthetic usage receipts (2,670 microUSD each run), and
retained zero unresolved holds. The successful run reports a +3,280 ms session
difference, +2,142 ms common-prefix difference and −1,139,607 ns third-decision
difference. The blocked run reports +2,803 ms, +2,257 ms and +340,473 ns
respectively, while omitting the final tool action. These are descriptive local
measurements including synthetic-provider/process overhead; they do not estimate
live inference latency or total authority overhead. Actual paid calls: **zero**.
The adjacent `.secure-agent/web-model-20261001-verification.json` records source,
receipt summaries and local file hashes; it is not hostile-host attestation.

All private artifacts remain ignored. The follow-up documentation commit changes
no runtime/tests; consult [PR #35 checks](https://github.com/0xsl0th/recon-cockpit/pull/35/checks)
for its final hosted status and the review handoff above for merge authorization. The immutable
accepted R6 packet, proposal PR #31 and local PDF stay unchanged.

## PR #34 merge review — 30 September 2026

Fresh independent reviews of exact head
`7494b7fe230c9f6ab73366fa746afcc306935426` found no blockers or outstanding GitHub
review comments. Main has no configured required checks; all five available
[final hosted jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/36782099190)
passed. Saved JUnit reports independently confirmed 4,438 portable cases and
eight new Linux cases without selected failures/errors/skips. Runtime/tests match
the earlier verified `6268543`; subsequent changes were documentation only.

The authorized guarded merge is `17945db6217c7901f41110b6f7ea9ed743bac606`,
at 23:46:20 UTC. The merge tree exactly matches the reviewed head:
`93aeddc1e434d3ed8377b5a7abe4f380f4e95372`. All five
[post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36792805339)
passed. The primary checkout is clean on that main revision. Keep PR #34 closed;
its offline comparison remains the fallback demonstration.

## Offline malicious-output comparison — 30 September 2026

After the authorized PR #33 merge, the next separate implementation is
`6268543c3d7c4c1ba5cc79ab4b78829d7bafdc64` in
[PR #34](https://github.com/0xsl0th/recon-cockpit/pull/34), based on `ed7d839`.
The source adds a bounded baseline/scripted evaluation using the accepted web
lab, authority and Nmap/HTTP tools. Only the CLI changes in existing application
modules; isolation, authority, fixture and tool implementations remain unchanged.
The default explicit unattended owned policy preserves the singleton scope and
original per-trial ceilings. R5/R6 acceptance and the proposal/PDF remain closed.

Independent reviews covered contract/provider, runtime/cleanup, grading and
batch/CLI behavior. The review correction preserves all verified journal
reservations when trailing corruption exceeds the event count; regression tests
cover object and non-object trailing records without writes. No blockers remain.

The complete portable selection passed **4,438 tests in 250.79 seconds**, with
zero selected failures/errors/skips; 515 Linux tests were deselected. The eight
new Linux integration tests passed: seven runtime/cancellation cases in 23.22
seconds and one six-trial CLI/replay/tamper case in 26.70 seconds. Every real
case/arm branch was independently regraded using the isolated XML parser. The
earlier accepted 507-case Linux suite is PR #33 evidence, not a newly rerun
full suite for this additive comparison. Reports:
`/tmp/recon-web-comparison-portable-full.xml`,
`/tmp/recon-web-comparison-runtime-linux.xml` and
`/tmp/recon-web-comparison-batch-linux.xml`.

On that clean implementation revision, the actual default CLI run completed
**18/18 passing trial criteria** in 66.192 seconds before final aggregate replay.
All **3/3 induced unauthorized proposals were blocked**, with **zero unauthorized
executions**. **15/18 legitimate tasks completed**, totaling 51 legitimate
actions. Each injected scripted trial stopped after two actions with
`target_out_of_scope`, two execution reservations and 17,408 reserved output
bytes. Its incomplete assessment is an expected, explicit task-completion cost,
not a completed task. Actual provider calls and approval wait were both zero;
the unattended policy does not constitute a human rehearsal.

Private evidence is `/home/sloth/Code/recon-cockpit/.secure-agent/web-comparison-20260930`.
The 163-file copy exactly preserves the original bytes, modes and mtimes.
Independent read-only CLI inspection reproduced the report without changes.
Inspection of a separate copy with an added claimed execution reservation failed
with `saved_trial_grade_mismatch`, leaving execution counts unknown and both
original and altered inputs unchanged. The adjacent
`web-comparison-20260930-verification.json` records execution revision and checks.
These files remain local and ignored.

All nine same-case pairs are reported. The three injected decision-latency deltas
(scripted minus baseline) were +96,492, −268,476 and +363,114 nanoseconds. Their
full-trial deltas were −488, −498 and −234 milliseconds, each omitting one action
and 1,024 reserved bytes. Those shorter elapsed times are **not** lower enforcement
overhead. Concurrent portable tests ran on the same host; three repeats provide
descriptive measurements only. No model susceptibility, total authority overhead
or professional deployment readiness is claimed. See
[web-comparison.md](web-comparison.md) for the precise timing interval and limits.

The checkpoint-only follow-ups do not alter runtime/tests. Consult
[PR #34 checks](https://github.com/0xsl0th/recon-cockpit/pull/34/checks) for its
final hosted status. PR #34 has since merged as recorded above.
Model/endpoint, data exposure, credentials, egress and spending require
separate operator authorization before the planned real-model pilot.

## PR #33 merge review — 30 September 2026

The operator authorized review/merge of the current PR and continuation. Fresh
independent reviews of exact head `aaa5c6aa8a33a3a2f627092a22104b16fbf50ad9`
found no runtime/authority, contract/evidence or documentation blockers. GitHub
had no outstanding review comments. Main has no configured required checks;
all five available [final jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/36771053368)
passed. Independent saved JUnit inspection confirmed 4,243 portable and 507
Linux cases, plus the corrected nine workflow trials, without failures/errors/skips.

The guarded merge is `ed7d839d2ea9d711a81a76ddfa76eb41d928bf28` at
21:02:55 UTC on 30 September. Merge and reviewed-head trees both equal
`e09794f3b4a4306e7d95b8944aa70306320e3877`. The clean main checkout was
fast-forwarded, and all five
[post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/36776840618)
passed. PR #33 stays closed; PR #31 and its local PDF remain separate.

## Resettable HarborDesk web lab — 30 September 2026

The operator authorized the richer resettable owned scenario after PR #32.
Implementation `98c0c35` is on `feature/resettable-web-lab`, based on `875c1a6`,
in [PR #33](https://github.com/0xsl0th/recon-cockpit/pull/33).
[web-lab.md](web-lab.md) documents the separate fixture/workflow identity,
vulnerable/corrected/injected variants and mandatory authority gates. The source
uses existing Nmap/HTTP tools, the same singleton owned scope and the unchanged
3-action/60-second/18,432-byte ceiling. No model, credential, external target,
spending, release or submission is enabled. Accepted offline milestones and the
proposal/PDF remain unchanged.

Independent review covered fixture/reset, strict HTTP interpretation, workflow
predecessors, evidence replay, admission/executor checks, launcher witness binding
and legacy behavior. Corrections made before broad regression testing fix an
HTTP request-tag mismatch and structured refusal of malformed inspection
workflow values. Existing Nmap report JSON/Markdown have golden byte checks.

Focused actual Linux verification passed nine full workflow trials (three fresh
instances per variant), with expected `validated`/`not_demonstrated`/`validated`
outcomes, three successful actions, two HTTP requests and 18,432 reserved bytes
per trial. Inspection left every evidence byte and mtime unchanged. The injected
note appeared only in private decoded HTTP artifacts. Four lifecycle tests verified
repeatable fixtures, zero starting counters, boundary checks and reset/cancellation
cleanup. Five approval tests covered a synthetic PTY grant, replay refusal,
missing/forged direct consumed proof and two wrong bootstrap tags. These are
scripted test grants, not human walkthrough or acceptance.

The complete selections at implementation `98c0c35` passed **4,243 portable tests
in 295.14 seconds** and **507 Linux integration tests in 1,072.23 seconds**, with
zero failures/errors/skips in either selected suite. Independent JUnit inspection
confirmed all **4,750** cases. Reports: `/tmp/recon-web-portable-full.xml` and
`/tmp/recon-web-linux-full.xml`. All five
[hosted checks on that implementation](https://github.com/0xsl0th/recon-cockpit/actions/runs/36768846374)
also passed. Subsequent edits are checkpoint/verification text and a test-only
counter correction: the workflow requires at least the two accepted HTTP
connections, without assuming the Nmap connection was accepted before reset.
Application source remains identical to `98c0c35`. All three corrected workflow
tests (nine fresh real-tool trials) passed again; JUnit:
`/tmp/recon-web-workflow-final.xml`. Consult the
[PR #33 checks](https://github.com/0xsl0th/recon-cockpit/pull/33/checks) for the
latest head before a merge decision. No merge authorization is claimed.

Focused reports: `/tmp/recon-web-workflow-linux.xml` (six test cases including the nine
workflow trials and the initial three approval tests),
`/tmp/recon-web-approval-linux.xml` (all five approval cases), and
`/tmp/recon-web-contract-evidence-portable.xml` (149 new/legacy contract checks).
An induced malicious-output proposal and baseline/overhead comparison remain the
next separate slice. This increment alone provides no model-susceptibility result.

## PR #32 merge review — 30 September 2026

The operator explicitly authorized reviewing PR #32 and merging its latest
revision if review and checks pass. Fresh independent review of `36b2d96`
checked the new runtime/executor/launcher boundaries, adapter compatibility,
workflow and evidence behavior. The implementation review found no blocking
issues or outstanding review comments. All five
[hosted jobs on that revision](https://github.com/0xsl0th/recon-cockpit/actions/runs/36763227519)
passed. Main has no configured required checks; all available jobs are checked.
Saved local reports independently reconcile to 4,548 distinct passing cases,
including every case in the final 495-test Linux selection.

The checkpoint correction became final head `b7e1904`; runtime/tests stayed
identical to the reviewed revision. All five
[final hosted checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36764600927)
passed. The authorized guarded merge is `875c1a6` at 19:23:07 UTC on
30 September; its tree exactly matches the reviewed head. All five
[post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36765297652)
passed. PR #32 stays closed. PR #31, live work and publication remain separate.

## Reviewed adapters and owned Nmap — 30 September 2026

The operator authorized implementing the common bundled-adapter interface and
one real confined Nmap-to-HTTP workflow. Implementation `245c4d7` is on
`feature/reviewed-tool-adapters`, based on main `8ae4aad`; subsequent test-only
corrections preserve that runtime. Review and latest hosted status are in
[PR #32](https://github.com/0xsl0th/recon-cockpit/pull/32). The proposal in PR #31 remains separate.
No model calls, external targets, credentials, spending, release or competition
submission were enabled. This is follow-on development, not a reopening of the
accepted R1–R6 offline contracts or a claim of professional deployment readiness.

Independent reviews checked the shared contract, dedicated runtime/parser,
authority integration and documentation. Review corrections preserve the
original evidence deadline, pin and revalidate the runtime manifest, parse raw
XML only in the isolated parser, independently enforce the 3-action/60-second/
18,432-byte ceiling and distinguish the legacy TCP workflow from the new Nmap
profile. No blocking source findings remain. Legacy action/policy digests and
default proposal request bytes have golden compatibility checks.

The complete local portable selection at implementation `245c4d7` passed
**4,054 tests in 286.493 seconds**, without failures, errors or skips. One real
Linux file-sealing test was subsequently moved to the integration selection;
the final portable selection contains **4,053 tests**. Its parser-wrapper test
uses explicit platform doubles so macOS requires no skip. Application source is
unchanged by these test-only corrections. JUnit:
`/tmp/recon-adapters-portable-245c4d7.xml`.

The final new runtime/workflow selection passed **14 Linux tests in 34.654
seconds**: real Nmap confinement, Python/loader escape refusal, output bounds,
timeout, cancellation/reaping, isolated malformed-XML refusal, all six
Nmap-to-HTTP outcomes and dry run. Three additional approval tests passed in
**9.476 seconds**: a synthetic PTY grant permits one real Nmap launch; replay
cannot reserve another; missing and forged consumed-grant proof are rejected
before admission with zero reservations. These scripted grants are test inputs,
not human consent or operator acceptance. The real sealed-descriptor test also
passed after its classification change. Reports:
`/tmp/recon-adapters-nmap-final.xml`,
`/tmp/recon-adapters-nmap-approval-final.xml`,
`/tmp/recon-adapters-sealed-runtime.xml`.

The broad Linux regression run completed **491 cases in 999.87 seconds**:
490 passed and one failed because the exact admission-worker module allowlist
still expected the pre-refactor file set. Its corrected assertion permits only
the two additional pure contract modules; host canaries and executor modules
remain excluded. The complete **35-test admission suite passed in 50.783
seconds** after that test-only correction. Reports:
`/tmp/recon-adapters-linux.xml` and `/tmp/recon-adapters-admission-final.xml`.
The passing results across these runs cover every case in the final **495-test
Linux selection**, including the three new approval cases and reclassified
sealing check. No additional source failure, error or selected skip remains.
The full 491-case run was not repeated after this assertion-only correction.

Python 3.11 grammar, local documentation links and whitespace checks passed.
Only source, tests, the example policy and documentation are published. Private
artifacts, PDFs and the immutable accepted R6 packet remain outside this change.
The [adapter runbook](tool-adapters.md) documents runtime prerequisites, raw
artifact interpretation, lower-bound connection counts, permitted re-execution
within the sandbox and bounded read-only parser cancellation latency. The new
human walkthrough, live-model acceptance and release publication are not claimed.

## PR #30 checkpoint review correction — 30 September 2026

The operator authorized review and merge of PR #30 if its latest revision and
checks pass. Fresh independent review of `5c9b47f` found an obsolete interruption
snapshot at the top of the checkpoint, incorrectly describing the completed
package as uncommitted and still awaiting visual review. The correction removes
that snapshot, points to PR #30 and the verified final local export, and records
the current conditional merge authorization. Renderer, stylesheet, email,
proposal and private artifacts are unchanged. Refer to
[PR #30](https://github.com/0xsl0th/recon-cockpit/pull/30) for the resulting head's
review/check and merge status; the previous revision's passing CI does not cover
this correction. Submission, publication and live work remain deferred.

## Local submission draft export — 30 September 2026

The operator authorized preparing a proposal PDF, unsent submission email and
references to the existing evidence and demonstration guide. The branch
`docs/submission-draft-package` adds only delivery tooling and documentation;
it does not change application behavior or reopen the accepted offline scope.

The actual export is
`.secure-agent/submission-draft-20260930-final/recon-cockpit-propuesta-20260930.pdf`:
**eight pages**, including one landscape architecture page. Its SHA-256 is
`e8feeffab5d8133bb1a76b0d43dd3c33a600b7d0304acd0e47623e27cea0fc79`.
The proposal bytes exactly match `cba8059e084655c355301d15dfd374505352c2b3`.
All **124 headings, paragraphs and table cells** matched extracted PDF text;
Spanish language metadata and accents are preserved. All eight pages were
visually inspected, and the final raster bytes match those inspected pages.
Tables remain together, and the original architecture's **11 nodes and 13
directed edges**, including labels, are retained by the local vector rendering.
The diagram source and confirmed team section remain unchanged.

The **27 PDF links** use HTTPS; repository document links point to the full
proposal source commit rather than a moving branch. Text, annotations and
metadata contain no private filesystem paths. The repository is public; the
actual private evaluation bundles are not attached or published. Local review
notes separately identify the accepted packet and human decision, preserving
the distinction between proposal source `cba8059`, packet verification source
`070257b`, historical execution revision `not_recorded` and rehearsal `dd4bbe4`.

The prepared host's Markdown, BeautifulSoup, WeasyPrint, Graphviz and DejaVu
fonts rendered the PDF without installation or asset retrieval. The renderer
blocks URL/file asset fetches; the final manifest reports zero attempts. It
records tool versions and source/renderer/style/email/output hashes. This is
a local document export, not a hermetic environment bundle or a promise of
identical PDF bytes across exports. `validation.json` records the checks.
The unsent email copy, original Markdown, HTML, SVG and review notes accompany
the PDF locally; the PDF is the only proposed email attachment.

Targeted checks confirmed that a mismatched source revision creates no output,
an existing destination is refused without changing its files, and unsupported
diagram syntax or undefined nodes fail rather than silently omitting content.
Python 3.11 grammar, local document targets and whitespace checks passed. All
331 accepted packet files retained identical bytes, modes, identities and
modification times throughout preparation. No provider call, assessment run,
approval prompt, email send or release publication occurred. No full application
suite was repeated for this delivery task; the original verification remains
the runtime evidence. Independent read-only review of the renderer, stylesheet,
email, final manifest and PDF found no blockers.

## PR #29 review and merge — 30 September 2026

The operator explicitly requested review and merge of PR #29. Fresh independent
review of `32d44af273b5b58ba5a37d6868324b39f64c3521` found no blockers or
outstanding comments. All five
[hosted checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36671559852)
passed. Main had no configured required checks; all five available jobs were
verified. Local Markdown targets and whitespace checks passed; the four-file
documentation change preserved the original diagram and confirmed team details.

The guarded merge is `cba8059e084655c355301d15dfd374505352c2b3` at **05:18:21 UTC**;
its tree exactly matches the reviewed head. Local main was synchronized and
clean. All five
[post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36672797756)
passed. PR #29 stays closed. Publication/submission and live-model work remain
deferred; no full local application suite was repeated for the documentation.

## PR #28 review and merge — 30 September 2026

The operator explicitly requested review and merge of the current PR, then
continued work within the offline scope. Fresh independent review of
`4ced75f9bf703fffdde2abe739f9fdf4858f682d` found no blockers or outstanding
review comments. All five
[hosted checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36670287169)
passed on that head. Main has no configured required checks; all five available
jobs were verified. Saved rehearsal, accounting, packet hashes and the separate
human decision agree with the documentation. The reviewed change contains only
five Markdown files; no full local suite was repeated solely for documentation.

The guarded merge completed at **04:54:53 UTC** as
`f70e7eaae27d54b0504c655de97727adfd910f1b`; its tree exactly matches the reviewed
head. Local `main` was fast-forwarded to that merge. All five
[post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36670999757)
passed. PR #28 stays closed. This merge authorization
does not authorize publication, submission, paid calls or another PR merge.

## Unsubmitted proposal reconciliation — 30 September 2026

The follow-up branch `docs/accepted-offline-proposal` reconciles the Spanish
[competition proposal](competition-proposal.md) with the accepted offline work.
It replaces stale claims that planning/audit separation was pending and that
service continuity was unverified. Current capability, the two 18-trial profiles,
separate human rehearsal and local acceptance now agree with the saved records.
Historical execution provenance remains `not_recorded`; the verification source
pin is unchanged. The 3,878 portable packaging tests and prior 477 Linux results
remain distinct historical verifications, not newly run tests for this draft.

The [official competition page](https://www.palermo.edu/ingenieria/concurso-ciberseguridad/)
was read on 30 September: the proposal deadline remains 15 November 2026 and
final delivery 20 May 2027; the selected challenge and submission/delivery
requirements are consistent with the draft. This verification did not register,
submit, contact anyone or publish a release. The original confirmed team and
architecture diagram are unchanged.

Independent review found no blockers. Local Markdown file targets and
`git diff --check` passed. The change is limited
to the proposal, checkpoint, roadmap authorization note and this verification
record. No runtime/test file or private packet/acceptance artifact changed, and
no full local test suite was repeated solely for documentation. The draft is
left for review; live-model work, optional additions and publication remain
deferred.

## R6 offline operator rehearsal — 30 September 2026

The operator answered “Yes, open the walkthrough” and personally controlled a
real QTerminal. The assistant supplied no terminal input, approval phrase or
grant. The handoff used the existing CLI on clean merge `dd4bbe4`, owned case a
at `127.0.0.1:8080`, the approval-required discovery policy, all isolated workers
and both direct launch gates. Limits remained three steps, 60 seconds, 3,072
reserved output bytes and a 55,326 microUSD **simulation** account. There were
no paid calls, real credentials, external targets or VPN.

Preparation replayed the existing 331-file candidate without changing its
bytes, modes, identities or mtimes. Manifest SHA-256 remains
`467decaa88ddb2861f8216973961f21dcff722e62a89b4ead46c370ae67f1ad7`;
verification/reproduction source remains `070257b455f158eb06301fae143c0704ee02ee30`.
The historical evaluation execution revision remains `not_recorded`. Both
profiles still pass 18 trials and all six fingerprints agree. Changing only a
disposable private copy's report to claim operator acceptance caused inspection
to refuse with `release_packet_unavailable`. The original packet was unchanged.
A fresh dry run also passed: no action execution or approval consumption, one
settled owned TLS exchange, clean evidence replay and closed lab.

The first terminal attempt timed out at the first approval after 60.003 seconds:
zero approvals consumed, zero executions and zero lab connections/HTTP requests.
One owned TLS planning exchange settled at 778 simulated microUSD with no hold.
The operator reported distraction and requested another run. The fresh attempt
used a new directory and new grants, preserving the same scope and limits.

The fresh attempt completed at **04:33:42 UTC**, exit 0, in **50.011 seconds**.
Session `93a71c5f-353c-4719-8894-d0696e48fd11` has three distinct approval
consumptions before their matching executions, with matching action/session/
policy bindings. TCP discovery and both GETs succeeded; independent evidence
inspection exactly reproduced `seeded_diagnostic_metadata_exposed` with no
integrity issues. The lab closed after three connections and two HTTP requests.
Three owned TLS receipts record both processes reaped and all boundary checks
true; the isolated-launcher close path verifies cleanup before recording lab
closure. A subsequent host process check found no matching CLI or isolated
worker processes.

Read-only ledger inspection found three settled simulation attempts, **1,536
fixture input tokens / 384 output tokens / 2,334 simulated microUSD**, with
zero reserved funds, unresolved holds or overspend. Actual paid provider calls
and spending were **zero**. Independent audit/evidence/accounting review found
no blockers, and read-only inspection preserved saved bytes and mtimes.

Private local records:

- Preparation, dry run and timed-out attempt:
  `.secure-agent/r6-operator-20260930-i7ou70cr`.
- Successful fresh attempt:
  `.secure-agent/r6-operator-20260930-retry-w4xi91nq`, including
  `demo-start.json`, `demo-finished.json`, `audit.jsonl`, `evidence/` and
  `planning-ledger/`.

The operator subsequently confirmed in this session: **“I entered all 3 and it
seemed straight forward”**. This is the actual human observation, distinct from
the technical audit. After reviewing the linked evidence report and terminal
rehearsal, the operator separately chose **“Accept the local offline candidate”**.
The decision was recorded on 30 September. Its scope is the local
offline candidate, evidence packet/runbook and rehearsal only; it does not
authorize publication, a subsequent PR merge or live-model work. This session's
project operator supplied the observation and decision; no separate identity
attestation is claimed.

The separate human review record is `operator-review.json` in the successful
run directory. It binds the candidate path, manifest/archive hashes, verification
source revision and demo session/revision to the actual words above. The
immutable packet's pending review fields describe its creation state and have
not been changed. R5 offline scope stays complete, the local offline R6 review
is accepted, live-model work stays deferred, optional additions stay deferred,
and publication is not authorized.
No implementation changed and no full test suite was repeated for this record.

## PR #27 completed merge — 30 September 2026

Final documentation head `bbd33fd31533f4a213135d51f441a7fc78279cf9` passed fresh
review without blockers or outstanding comments and all five
[final hosted jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/36667566229).
The operator-authorized guarded merge is
`dd4bbe456d5d2b0e92a2642c19969490149e6a3d` at 04:15:01 UTC; its tree exactly
matches the reviewed head. All five
[post-merge main jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/36667987075)
also passed. PR #27 stays closed. The following pre-merge handoff is historical.

## PR #27 review and offline R5 handoff — 30 September 2026

The operator authorized review and merge of PR #27 and asked whether offline R5
was now concluded. A fresh independent review of
`c3242c04e48759381e3063dbe91943a04d679cb4` found no blockers or outstanding
reviews/comments. All five [hosted checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36666520214)
passed. Saved JUnit and CLI summaries reproduce the counts and hashes below.
Main has no configured required checks; all five available jobs were verified.

The milestone audit found no remaining necessary offline R5 blocker: the
accepted provider/accounting and authority/planning work is complete through
PR #26's offline comparison. PR #27 is R6 evidence packaging and the runbook.
Real-model integration, validation and acceptance remain explicitly deferred,
with actual R6 operator review/rehearsal still pending. No paid calls, live
activation, new capability or expanded milestone scope is authorized.

This handoff correction changes documentation only. Runtime/tests remain
identical to reviewed `c3242c0`, and the saved packet remains pinned to `070257b`.
The [PR state and checks](https://github.com/0xsl0th/recon-cockpit/pull/27/checks)
record the final checkpoint revision's hosted result before the authorized merge.
No full local suite was repeated solely for this documentation update.

## R6 offline release evidence candidate — 30 September 2026

[PR #27](https://github.com/0xsl0th/recon-cockpit/pull/27), implementation
`46fc12a`, adds the [local evidence packet and demo runbook](offline-release-evidence.md).
It independently regrades the two accepted default evaluations and their private
copies, binds all bytes to a canonical inventory, and verifies a deterministic
source archive against its Git blobs, tree and raw commit object. It does not
execute agents, install dependencies, fetch source or publish a release.

Independent review found and corrected two packaging issues: unreviewed files
beside the closed ledger are now refused, and the source repository must be the
checkout running the verifier. Otherwise an unrelated clean tree could have been
misrepresented as the verification source. Regressions cover those cases,
rehashed corrupt evidence, races, private-file restrictions, links, bounds and
pending acceptance fields. Final independent reviews have no remaining blockers.

The initial hosted run passed four jobs but Ubuntu/Python 3.13 reported a
fixture race in `test_build_is_deterministic_readonly_and_binds_real_git_objects`:
Git's background maintenance removed `.git/objects/maintenance.lock` after the
fixture's first snapshot. Archive bytes and metadata were identical. The fixture
Git helper now disables automatic maintenance and garbage collection; the full
repository bytes/mtime assertion is unchanged. All 82 source tests passed after
this correction in 2.989 seconds, followed by 30 separate fresh determinism/read-only
pytest invocations (21.39 seconds total), all passing. Reports:
`/tmp/recon-release-source-maintenance-fix.xml` and
`/tmp/recon-release-source-determinism-repeated.xml`. Production code and
Linux-selected tests are unchanged.
Failure log: `/tmp/recon-release-ci-failure.log`;
[initial hosted run](https://github.com/0xsl0th/recon-cockpit/actions/runs/36665605288).

Full local portable verification of `46fc12a` passed **3,878 tests in 249.67 seconds**, with
zero failure/error/skipped elements in `/tmp/recon-release-all-portable-final.xml`.
This includes **82 source tests** and **70 packet tests**. Python 3.11 grammar
passed for 202 tracked Python files; dependencies, local Markdown links and
whitespace checks passed. The [PR checks](https://github.com/0xsl0th/recon-cockpit/pull/27/checks)
show the latest hosted status.

```sh
.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra \
  --junitxml=/tmp/recon-release-all-portable-final.xml
```

No execution/isolation implementation changed. The accepted **477-test Linux
run** from PR #26 remains runtime evidence; this read-only packaging slice did
not launch a new kernel integration suite or count the old run as new testing.

After the test fixture correction, the actual CLI rebuilt two final packets
from the saved Linux bundles
`.secure-agent/evaluation-baseline-20260924` and
`.secure-agent/planning-evaluation-20260930`. Each has **331 files**, including
**246 source files** in a **3,082,240-byte canonical archive**. Both builds
produced identical packet bytes; a separate read-only CLI invocation exactly
reproduced the report. All original input and inspected packet bytes and mtimes
were preserved. The validated archive was also unpacked into a new private
`/tmp/recon-release-source-final-7v7q_a2x` directory. Running the inspector from that
source (confirmed by the imported module path), without Git metadata and with
the prepared existing Python environment, reproduced the same report. This is
not a fresh dependency installation or a hermetic environment test; summary:
`/tmp/recon-release-archived-source-final.json`. Both profiles pass 18 trials with all
six fingerprints matching,
51 executions, 45 successful actions, 12 correct abstentions and no unnecessary
actions. Planning reports 39,678 simulated microUSD, zero unresolved holds and
zero actual provider calls. No new model experiment was performed.

Verification/reproduction source: `070257b455f158eb06301fae143c0704ee02ee30`.
Historical execution revision: **not recorded**, explicitly preserved in the
packet. Later documentation commits do not alter this pin or claim to have
produced those saved evaluations.

| Local artifact | Value |
| --- | --- |
| Candidate directory | `.secure-agent/offline-release-evidence-20260930-final` |
| Repeated build | `.secure-agent/offline-release-evidence-20260930-final-repeat` |
| Archive SHA-256 | `799efac00b01684402658363b629e65b0ae42da69d14235c6403f9b51e9c8362` |
| Manifest SHA-256 | `467decaa88ddb2861f8216973961f21dcff722e62a89b4ead46c370ae67f1ad7` |
| Build times | 6.945 seconds and 7.037 seconds |
| Read-only inspection | 1.921 seconds |
| CLI verification summary | `/tmp/recon-release-packet-smoke-final.json` |

The candidate remains local and unpublished. Actual operator review/rehearsal
and live-model acceptance remain pending; automation has not supplied human
consent. Paid calls, real credentials, external targets and VPN remain disabled.

## PR #26 review and merge — 30 September 2026

The operator authorized review and merge of the current PR. Final head
`7e5c2ac2bb0ee4ca6742eca38d80c2f6e9142f6c` passed a fresh independent review
with no blockers or outstanding reviews/comments. All five hosted jobs passed
in [run 36663416736](https://github.com/0xsl0th/recon-cockpit/actions/runs/36663416736).
The guarded merge is `1605606736620b1fa25c399078c574e0b84ed0a1` at
03:22:20 UTC. Its tree exactly matches the reviewed head. Saved full reports
confirm the 3,726 portable and 477 Linux successes below; final documentation
commits did not change runtime/tests from `c2d4d0b`. Main has no configured
required checks; all five available checks were nevertheless green before merge.
All five [post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36664091986)
also passed.

## R5 offline planning evaluation — 30 September 2026

The new [planning evaluation](planning-evaluation.md) preserves the deterministic
baseline and independently grades the accepted owned TLS planning path, isolated
launch gates and one bounded simulation ledger. Live calls, real credentials,
external targets and paid inference remain disabled.

The actual CLI default batch completed **18/18 trials in 124,159 ms**, with 51
owned TLS exchanges/executions, 45 successful actions, 12 correct abstentions and
zero unnecessary actions. It recorded 26,112 fixture input tokens, 6,528 output
tokens and 39,678 simulated microUSD, with zero unresolved holds. All six semantic
fingerprints match the independently inspected saved deterministic baseline.
The new bundle is `.secure-agent/planning-evaluation-20260930`; inspection after
the report-size correction exactly reproduced its report and preserved all 164
file hashes and modification times. The original baseline was also unchanged.

```sh
.venv/bin/python -m recon_cockpit.secure_agent --evaluate-owned-planning \
  --policy examples/secure-agent-evaluation-policy.json \
  --evaluation-dir .secure-agent/planning-evaluation-20260930 --execute
.venv/bin/python -m recon_cockpit.secure_agent \
  --inspect-planning-evaluation .secure-agent/planning-evaluation-20260930
```

Independent review corrected a saved-rationale lookup (evidence intentionally
omits rationale), added exact initial account/engagement journal checks and
validated batch timestamps. The first real 18-trial replay exposed reuse of the
proposal parser's 32 KiB limit for the 106,835-byte aggregate. Inspection now
compares bounded canonical report bytes with freshly regraded evidence. Both
18-trial and maximum 60-trial portable runtime batches pass replay and cache
corruption checks; their two-test report is
`/tmp/recon-planning-evaluation-batches.xml` (56.30 seconds).
The strict grader's 89 tests passed in 35.60 seconds, including all six outcomes,
ledger/audit/runtime mutations and failed-prefix cost binding. CLI/runtime tests
passed 25 cases, and scheduler/storage checks passed 31.

Final full verification of implementation `c2d4d0b` passed **3,726 portable tests
in 210.53 seconds** and **477 rootless Linux tests in 972.80 seconds**, with zero
selected failures/errors/skips. These include all 147 new portable and 11 new
Linux cases. The latter verify real services and descendant cleanup, all six
outcomes, shared cost caps and fresh trial scopes, saved-record tampering,
cancellation/deadline stops and retained uncertain holds.

```sh
.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra \
  --junitxml=/tmp/recon-planning-evaluation-all-portable-final.xml
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short
```

The portable JUnit report has 3,726 cases and no failure/error/skipped elements.
The complete Linux transcript is
`/tmp/recon-planning-evaluation-all-linux.log`: 477 selected, all 477 passed.
This clean final run supersedes the explicitly interrupted pre-correction run;
no interrupted-run or unlaunched focused-run result is counted as verification.
Python 3.11 grammar passed for 198 tracked files, dependencies and local
Markdown links are consistent, and whitespace checks passed. A final host
process check found no test or isolated `/app/` workers remaining.

Independent final review found no blockers. All five
[hosted checks on `c2d4d0b`](https://github.com/0xsl0th/recon-cockpit/actions/runs/36661988927)
passed. [PR #26 checks](https://github.com/0xsl0th/recon-cockpit/pull/26/checks)
show the latest documentation checkpoint's status. This follow-up changes
only documentation; do not repeat full local suites solely for it.

The selected policy permits unattended owned actions. These runs provide no
human approval or live-model acceptance evidence. R5 real-model acceptance and
R6 actual operator review remain pending; optional additions remain deferred.

## PR #25 merge review — 30 September 2026

Reviewed exact head `c7f77914ed6b70b6b680e8eded7719cf5c7e760d`; no blockers or
outstanding comments. All five [hosted checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36659466246)
passed. The runtime tree was unchanged from implementation `30f2b2d`; saved JUnit
reports confirmed 3,579 portable / 466 Linux tests with no failures/errors/skips.
The operator-authorized guarded merge completed at 02:27:02 UTC as `636a067`.
Local main fast-forwarded, and the merge tree equals the reviewed head.

## R5 owned TLS assessment planning — 30 September 2026

Implementation `30f2b2d` in [PR #25](https://github.com/0xsl0th/recon-cockpit/pull/25)
adds the [owned TLS planning profile](owned-tls-assessment-planning.md). It composes
PR #24's saved-evidence and simulation monetary gates with a disconnected TLS
fixture. It sends only the existing closed descriptor and uses generated
synthetic credentials. Recognized usage settles before the isolated parser;
all direct launch checks remain required. No external provider call, real
credential or paid inference was used.

Full portable regression passed **3,579 tests in 95.30 seconds**, with 466 Linux
tests deselected and zero selected failures/errors/skips:

```sh
.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra \
  --junitxml=/tmp/recon-planning-tls-all-portable.xml
```

The 197 new portable cases cover exact request/profile binding, old-profile
separation, immutable session/transport lifetime, closed receipt validation,
ledger settlement/holds, audit loss, cancellation, concurrency and CLI refusal.

Focused rootless Linux verification passed **36 tests in 126.77 seconds**, with
zero failures/errors/skips:

```sh
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest \
  tests/test_secure_assessment_planning_tls_linux.py -m integration -x -v --tb=short \
  --junitxml=/tmp/recon-planning-tls-focused-linux.xml
```

This covers all six outcomes across both backends, settlement before both direct
launch gates, TLS/HTTP/credential-reflection failures, malformed or ambiguous
usage, overruns, refusal/substitution, budget/audit refusal before transport,
dry/noninteractive execution refusal, active-connection cancellation/deadlines,
and actual descendant cleanup. Worker canaries check absent host credentials,
files, inherited descriptors and authority/evidence/ledger mounts. Scripted PTYs
establish approval mechanics, not actual operator acceptance.

Independent review found and corrected two cancellation issues before final
verification: a later failed exchange could expose an earlier receipt and mask
the original stop; cancellation immediately after successful transport audit
could emit a duplicate terminal event. Regression tests now require a fresh
receipt per attempt and one terminal transport event. Final review found no
remaining blockers.

Full rootless Linux regression passed **466 tests in 904.45 seconds**, with
3,579 portable tests deselected and zero selected failures/errors/skips:

```sh
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short \
  --junitxml=/tmp/recon-planning-tls-all-linux.xml
```

No `/app` Python workers remained after the run. Runtime still matches the
implementation commit; the follow-up changes documentation and the portable
fixtures described below.
Python 3.11 grammar checks passed for all 189 tracked/new Python files;
dependency consistency, local documentation links and whitespace checks passed.
All five [hosted implementation checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36657483576)
passed. The [PR checks](https://github.com/0xsl0th/recon-cockpit/pull/25/checks)
record the final documentation checkpoint's status. None of these results
establishes real-model acceptance or completes R6.

The documentation revision `a94edf5` passed four hosted jobs, but Ubuntu/Python
3.14 exposed an existing cancellation-test timer race in
`test_secure_openai_session.py`: a 50 ms timer could cancel before broker entry,
so the test's assertion about an already reserved call targeted the wrong phase.
The test now cancels from the scripted transport wait and asserts that dispatch
and reservation have already occurred, using the real cancellation event and
unchanged stop checks. The timeout branch and production code are unchanged.
Independent review found no issue with this correction. All **232 focused
session, authority and broker portable tests passed in 2.06 seconds**, with zero
selected failures/errors/skips; three Linux cases were deselected:

```sh
.venv/bin/python -m pytest tests/test_secure_openai_session.py \
  tests/test_secure_offline_authority.py tests/test_secure_openai_broker.py \
  -m 'not integration' --strict-markers -ra \
  --junitxml=/tmp/recon-planning-tls-cancellation-portable.xml
```

The full Linux evidence remains valid because its runtime and selected tests
are unchanged. The PR checks show the corrected latest revision's hosted status.

Revision `9d2387c` passed all four Ubuntu jobs. macOS then exposed an unrelated
existing invalid-READY fixture's self-exit race: boundary validation correctly
rejected the peer, but Darwin refused a process-group signal as the child became
a zombie during cleanup. The READY test now writes both invalid frames together
and waits for a response, keeping the peer alive until the supervisor rejects
and kills it. It additionally requires an already-reaped `SIGKILL` return code;
the authority callback must still never run. Separate failed-exit and
descendant-cleanup tests remain unchanged. This stabilizes that fixture, not the
underlying Darwin cleanup exception race; no production cleanup exception is
suppressed, and actual isolated execution remains Linux-only.

Independent review accepted this narrow correction. All **106 coordinator and
broker IPC portable tests passed in 4.24 seconds**, zero failures/errors/skips:

```sh
.venv/bin/python -m pytest tests/test_secure_coordinator_ipc.py \
  tests/test_secure_broker_ipc.py -m 'not integration' --strict-markers -ra \
  --junitxml=/tmp/recon-planning-tls-ipc-portable.xml
```

## R5 bounded offline assessment planning — 29 September 2026

[PR #23](https://github.com/0xsl0th/recon-cockpit/pull/23) passed final review at
`6dc7a7d` with no blocking findings or outstanding comments and all five hosted
checks green. The user authorized its merge as `a87e5dd` at 21:57:20 UTC. The
merge tree is identical, and all five
[post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36636608649)
passed. Its runtime was already covered by 3,196 portable and 406 Linux tests;
the final documentation-only revision required no runtime correction.

The next slice, implementation `bb9e42c` on `feature/bounded-assessment-planning`
in [PR #24](https://github.com/0xsl0th/recon-cockpit/pull/24), adds a separate
repository-owned mock planning provider and closed data-release contract. Every
request follows a durable evidence eligibility decision, simulated monetary
reservation and one-use dispatch claim. Recognized usage settles before response
bytes reach the unchanged isolated parser; the complete decoded proposal must
match the eligible candidate before reaching the coordinator. The CLI requires
both direct launch gates and a fresh simulation ledger. Read
[bounded-assessment-planning.md](bounded-assessment-planning.md) for scope and
trust limits. No live provider, credential or network transport is added.

Focused Linux verification passed **24 tests in 57.56 seconds**:

```sh
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest tests/test_secure_assessment_planning_linux.py \
  -m integration -x -v --tb=short --junitxml=/tmp/recon-assessment-planning-focused-linux.xml
```

This covers all six cases with both fixture/card v1 and persistent-lab/card v2,
settled accounting before each launch, actual parser/coordinator boundaries,
read-only evidence/ledger inspection, hostile proposals and usage, budget
refusal before transport, dry/noninteractive refusal, dispatched cancellation
and lost settlement-audit acknowledgement. Scripted PTYs establish mechanics,
not human approval or operator acceptance.

Independent review found a cleanup edge when a ledger operation commits before
its acknowledgement is lost. Local phase flags could then attempt an invalid
transition and hide the original error, although funds remained held or settled
and no proposal was released. Cleanup now checks durable state; focused fault
tests cover these interrupted acknowledgements. No review findings remain.

Full portable regression:

```sh
.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra \
  --junitxml=/tmp/recon-assessment-planning-portable.xml
```

**3,382 passed, 430 deselected in 86.69 seconds.** The 186 new portable cases
cover the closed release/usage contract, provider lifetime and money failures,
and CLI prerequisites/storage.

Full rootless Linux regression:

```sh
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short \
  --junitxml=/tmp/recon-assessment-planning-all-linux.xml
```

**430 passed, 3,382 deselected in 771.15 seconds.** Both full JUnit reports were
checked for the expected count and zero selected failures/errors/skips. No test,
owned provider fixture or isolated worker processes remained. Python 3.11 grammar
(181 files), dependencies, local documentation links and whitespace checks pass.
All five hosted jobs on implementation `bb9e42c` passed; the
[PR checks](https://github.com/0xsl0th/recon-cockpit/pull/24/checks) record final
revision status. The follow-up checkpoint changes documentation only. On
29 September the operator authorized review and merge of #24. Review of
`f24d313` found no blocking issue or outstanding comments; all five final jobs
passed, and both full JUnit reports were rechecked without selected failures,
errors or skips. No runtime correction or full-suite rerun was needed. The
PR record gives the final merge state and commit; later merges and live
validation still require authorization.

The deterministic workflow/evaluation baseline, fixed ACK diagnostic and R5a TLS
boundary remain unchanged. No external provider call, real credential, paid usage
or new tool/target was introduced. This mock bridge does not complete R5 planning
transport or real-model acceptance; those gates remain before R6. Optional product
additions stay deferred and live execution stays disabled.

## R5 direct launch-approval witness — 29 September 2026

[PR #22](https://github.com/0xsl0th/recon-cockpit/pull/22) was reviewed at final
head `1c26828` with no outstanding comments or blocking findings. All five hosted
jobs passed. Fresh review passed **372 portable tests in 1.35 seconds** and
**35 Linux boundary tests in 65.48 seconds**, with no runtime corrections.
The authorized merge is `5584efe` at 06:31:48 UTC; its tree exactly matches the
reviewed head. All five [post-merge main jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/36531540371)
passed. Review reports: `/tmp/recon-audit-witness-review-portable.xml` and
`/tmp/recon-audit-witness-review-linux.xml`.

The next R5 slice, implementation `457f164` on `feature/launcher-approval-witness`
from that verified main, is published in [PR #23](https://github.com/0xsl0th/recon-cockpit/pull/23).
Its publication checkpoint changes documentation only; runtime/test evidence
remains tied to that implementation. Current hosted status is on the
[PR checks](https://github.com/0xsl0th/recon-cockpit/pull/23/checks).
It adds `--require-launch-approval` on top of the direct audit gate. The isolated
approval worker alone holds the sending endpoint after startup and sends proof
only after consuming a reviewed grant. The launcher checks exact bindings,
sequence and original expiry before admission, then freshness again after
redemption. A host claim of successful consumption cannot satisfy this gate.
See [launch-approval-witness.md](launch-approval-witness.md) for ownership and
the trusted bootstrap/worker/terminal limits. This change does not authenticate
a person's identity independently of those components.

The portable command was:

```sh
.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra \
  --junitxml=/tmp/recon-approval-witness-portable.xml
```

**3,196 passed, 406 deselected in 86.32 seconds.** The 50 new portable cases cover
source/session/policy/action/sequence/expiry binding, non-extension of grant TTL,
atomic single use, failed consumption exposing no grant, fixed bootstrap source
and CLI prerequisites. The existing consume API retains its reason-only result.

Focused Linux verification:

```sh
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest tests/test_secure_approval_witness_linux.py \
  -m integration -x -v --tb=short --junitxml=/tmp/recon-approval-witness-focused-linux.xml
```

**44 passed in 92.59 seconds.** Actual disconnected boundaries cover exclusive
endpoint custody, no consent capability in executors, forged host consumption
replies and durable consent claims, review without consumption, denial, source/
session/action/policy changes, replay, original grant expiry, expiry during
admission, extra queued proofs, producer exit and lost consumption acknowledgement.
Both bootstrap paths reject missing/extra/substituted descriptors and downgrade.
Cancellation reaps the launcher tree; dry/noninteractive modes start no launcher
or approval worker. All six workflow outcomes pass with both fixture and
persistent-lab launchers; saved evidence inspection preserves bytes and mtimes.
Policy-allowed actions require no terminal while still requiring durable intent.

Prepublication review tightened one bootstrap case: before any approval-required
launcher starts, the host closes a pending sender that was never transferred to
the approval worker. A new fixture queues forged proof before review and verifies
that EOF still prevents admission. An earlier full Linux run was deliberately
interrupted at 204 passing cases to make this correction; it is not completion
evidence. The portable and focused Linux results above are after the correction.

Full rootless Linux command:

```sh
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short \
  --junitxml=/tmp/recon-approval-witness-all-linux.xml
```

**406 passed, 3,196 deselected in 716.31 seconds.** This complete run supersedes
an operator-paused run (369 passing tests in 675.61 seconds) and a subsequent
server-interrupted run, neither of which established suite completion.

Fresh portable verification on the unchanged implementation:

```sh
.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra \
  --junitxml=/tmp/recon-approval-witness-resumed-portable.xml
```

**3,196 passed, 406 deselected in 85.76 seconds.** Both complete JUnit reports
were checked for the expected case count and zero selected failures/errors/skips.
No pytest, owned provider fixture or isolated worker processes remained afterward.
Python 3.11 grammar (175 tracked files), dependency consistency, 153 relative
documentation links and whitespace checks passed. Independent review found no
blocking issue in PR #22's merged revision or PR #23's implementation; no runtime
correction was needed. PR #22's identical merge tree and all five PR/post-merge
checks were reconfirmed. All five hosted checks on #23 implementation `457f164`
passed; use its PR checks above for the final documentation revision. This slice
was subsequently reviewed and merged with authorization as `a87e5dd`, as recorded
in the current checkpoint above.

No provider modes, tools, targets, workflow/evidence schemas or default execution
settings changed. All work uses owned/mock fixtures and synthetic credentials,
with no external provider calls, real keys or spend. Scripted PTYs verify
mechanics, not actual human acceptance. After separate review/merge authorization,
bounded assessment planning on R5a/R5b is next. R5 remains incomplete pending
that integration and explicitly gated real-model acceptance; R6 follows. Keep
completed milestones closed and optional GUI/API/tool expansion deferred.

## R5 direct launch-audit witness — 29 September 2026

PRs #20 and #21 were reviewed at `007f24f` and `0298e1a`, then merged in dependency
order with explicit operator authorization. #20 merged as `31d0a1f`; #21 was
retargeted to main with an unchanged diff and merged as `38282b9`. Both merge
trees match the reviewed trees exactly. No review comments or blocking findings
remained. Fresh review passed **277 portable tests in 0.74 seconds** and **57 Linux
boundary tests in 79.30 seconds**. Both heads had five passing hosted jobs; all
five [final post-merge main jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/36527099212)
passed. The intermediate main run was superseded by the second merge. Review
reports: `/tmp/recon-launchers-merge-review-portable.xml` and
`/tmp/recon-launchers-merge-review-linux.xml`.

The next necessary R5 slice, implementation `845a093` on
`feature/launcher-audit-witness` from `38282b9`, is published in
[PR #22](https://github.com/0xsl0th/recon-cockpit/pull/22) against main. The
production implementation is unchanged by the documentation checkpoint and
test-only CI correction recorded below. Current hosted status is on the
[PR checks](https://github.com/0xsl0th/recon-cockpit/pull/22/checks). It adds explicit `--require-launch-audit`. The audit worker alone holds a one-way
sending endpoint and emits an execution-intent witness only after fsync. The
launcher checks source, sequences, freshness and exact action/session/policy/
backend before admission or execution. Default requests and evidence schemas
are unchanged. See [launch-audit-witness.md](launch-audit-witness.md).

Focused portable verification passed **228 tests in 0.62 seconds**. The full
portable command was:

```sh
.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra \
  --junitxml=/tmp/recon-audit-witness-portable.xml
```

**3,146 passed, 362 deselected in 86.26 seconds.** The 53 new cases cover strict
source/event/sequence/time bindings, malformed intent rejection, replay and
launch ceilings, received-descriptor cleanup, truncation and CLI prerequisites.

Focused rootless Linux verification passed **35 tests in 64.86 seconds**:

```sh
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest tests/test_secure_audit_witness_linux.py \
  -m integration -v --tb=short --junitxml=/tmp/recon-audit-witness-focused-linux.xml
```

This witnesses actual endpoint custody and kernel-enforced direction, no witness
capability in an executor, descriptor substitution/duplication/omission and
bootstrap downgrade refusal, a forged host audit acknowledgement without a real
event, missing/stale/replayed/mismatched/queued-extra witnesses, fsync failure,
lost acknowledgement, writer/channel failure, cancellation cleanup and prevention
of startup after denied approval or lost controller acknowledgement. All six
workflow outcomes pass with both fixture and persistent-lab launchers, preserving
saved-evidence integrity and read-only bytes/mtimes. Dry/noninteractive CLI runs
start no launcher. Scripted PTYs verify mechanics, not actual human consent.

The full rootless Linux command is:

```sh
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short \
  --junitxml=/tmp/recon-audit-witness-all-linux.xml
```

**362 passed, 3,146 deselected in 626.77 seconds.** Both full JUnit reports contain
zero selected failures, errors or skips. No task workers or pytest processes
remained afterward. Python 3.11 grammar (171 files), dependencies, local links and
whitespace checks passed; no dependencies were added. Hosted portable CI supplements,
rather than replaces, the rootless kernel verification.

The [hosted run on `d5616d5`](https://github.com/0xsl0th/recon-cockpit/actions/runs/36529547273)
passed four jobs and exposed an existing cancellation-test race on Ubuntu/Python
3.14. Its 50 ms timer could cancel before mock exchange entry under host load,
so no call was reserved. The corrected test cancels at the actual scripted
transport wait, asserts the call is already reserved, and retains the existing
stop/no-execution/cost assertions. No production code changed. Reverification:

```sh
.venv/bin/python -m pytest tests/test_secure_offline_authority.py \
  tests/test_secure_openai_broker.py -m 'not integration' --strict-markers -ra \
  --junitxml=/tmp/recon-authority-cancel-portable.xml
```

**214 passed in 0.98 seconds.** Full Linux verification above remains applicable;
the PR checks report the corrected head's hosted portable matrix.

The direct gate proves durable intent from the selected writer, not truth of a
producer's approval claim or completed execution. Trusted bootstrap, fixed workers
and the host account/kernel remain trusted; the file is not immutable against its
owner. An unknown append/completion may already have happened and never permits
retry. Independent fresh-approval authentication, bounded provider-backed planning
and explicitly gated real-model acceptance still precede R6. R1–R4 and R5a/R5b
remain closed. All verification is offline with owned/mock fixtures and synthetic
credentials: zero external provider calls, real keys or spend. Subsequent PRs need
review and separate merge authorization.

## R5 confined persistent-lab launcher — 29 September 2026

Reviewed PR #20 head `007f24f` against verified main `e9c5496`: no blocking
findings, no outstanding GitHub comments, five hosted jobs successful. Fresh
review passed **243 focused portable tests in 0.56 seconds** and **37 Linux
launcher tests in 41.42 seconds**; no runtime correction was needed. Reports:
`/tmp/recon-launcher-review-portable.xml`, `/tmp/recon-launcher-review-linux.xml`.
PR #20 remains open; this continuation supplies no new merge authorization.

Implemented its dependent slice as `7864e09` on
`feature/isolated-owned-lab-launcher`, published in
[PR #21](https://github.com/0xsl0th/recon-cockpit/pull/21) against PR #20's branch.
The publication checkpoint changes documentation only; local test evidence stays
bound to that implementation. Current hosted status is on the
[PR checks](https://github.com/0xsl0th/recon-cockpit/pull/21/checks).
`--isolated-launcher` now also composes with persistent `--owned-lab` workflows.
The confined worker owns lab management, namespace pins, admission-client custody
and fresh executor supervision; host requests cannot choose a namespace, lab,
command, reset or replacement control. Existing owner/executor/evidence validators
and card v2 remain authoritative. See [the ownership contract](isolated-owned-lab-launcher.md).

The portable command was:

```sh
.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra \
  --junitxml=/tmp/recon-owned-launcher-portable.xml
```

**3,093 passed, 327 deselected in 80.23 seconds.** The 34 additional cases verify
strict identity/case/runtime binding, namespace/reset/authority-field rejection,
completion continuity, unchanged public SessionLimits identity/digest, dry clients,
cleanup failures without fabricated closure, and inherited hard-limit preservation.
The focused Linux run passed **20 tests in 36.75 seconds**:

```sh
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest tests/test_secure_owned_launcher_linux.py \
  -m integration -v --tb=short --junitxml=/tmp/recon-owned-launcher-focused-linux.xml
```

These exercise three actions sharing one confined lab (counters `(1, 0)`, `(2, 1)`,
`(3, 2)`), all six workflow outcomes and unchanged read-only evidence inspection,
no host lab/executor invocation, inaccessible authority files/environment,
owner failure, broken pins, lost redemption/completion, no replay/refund, active
executor cancellation/deadline/concurrent-request teardown, dry/noninteractive
CLI behavior and denial/lost-audit acknowledgement before startup. Scripted PTYs
exercise mechanics only; they do not establish real human consent.

Initial nested startup correctly refused the owner's attempt to raise an inherited
CPU hard limit. The shared resource helper now preserves stricter inherited hard
ceilings without changing wall-clock deadlines. Two test API calls and the delayed
executor fixture's missing time import were corrected before the passing focused
run; those early failures are not counted as acceptance evidence.

The complete Linux regression command is:

```sh
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short \
  --junitxml=/tmp/recon-owned-launcher-all-linux.xml
```

**327 passed, 3,093 deselected in 559.12 seconds.** Both full JUnit reports contain
zero selected failures, errors or skips. No task launcher, lab, executor, admission
or pytest processes remained afterward. Python 3.11 grammar (168 files),
dependency consistency, local documentation links and whitespace checks passed. The new PR targets the reviewed PR #20 branch; the CI
base-branch filter includes it so the focused stacked diff receives the existing
five portable jobs. Hosted CI does not substitute for rootless kernel tests.

Closure records verified teardown and the host's last acknowledged completion,
not a fresh final sample. Unknown completion can follow actual execution; neither
retry nor positive assessment evidence is inferred. Controller-established consent
and durable intent remain trusted preconditions; independent authentication and
bounded assessment planning are still R5 work, followed by gated real-model
acceptance and R6. R1–R4/R5a/R5b stay closed. External provider calls, real credentials and
spend: **zero**; live execution remains disabled by default.

Hosted CI on publication head `3f0d7d1` passed all four Ubuntu jobs, but macOS
correctly exposed a new test's assumption that RLIM_INFINITY equals `-1`. The
fixture now uses `resource.RLIM_INFINITY`, as production already did. All 34
focused portable cases passed again in 0.17 seconds
(`/tmp/recon-owned-launcher-portability.xml`). Production is unchanged, so the
full Linux evidence remains valid; see the PR checks for the corrected head's
five-job portable matrix.

## R5 confined fixture launcher — 29 September 2026

Implemented on `feature/isolated-fixture-launcher` from verified main `e9c5496`
(merged PR #19). The explicit `--isolated-launcher` option requires `--fixture`
and all three isolated approval/audit/admission options. Its confined worker owns
admission-client custody, permit redemption, executor envelopes and supervision;
a separate nested admission worker retains the PR #19 reservation state machine.
See [the contract and intentional capabilities](isolated-fixture-launcher.md).

The full portable command was:

```sh
.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra \
  --junitxml=/tmp/recon-launcher-portable.xml
```

**3,059 passed, 307 deselected in 65.22 seconds.** The 71 additional portable
cases cover strict bootstrap/runtime/request/reply schemas, forbidden command,
permit, consent/reset/budget fields, identity and deadline binding, duplicate-key/
NaN/oversize rejection, large bounded response bodies, poisoned clients, counter
receipt forgery, inert construction/dry-run and unsupported/noninteractive CLI
refusal. The affected existing CLI and assessment regressions also passed
separately: **119 tests in 1.70 seconds**.

The first focused Linux command was:

```sh
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest tests/test_secure_fixture_launcher_linux.py \
  -m integration -x -v --tb=short
```

**36 passed in 40.03 seconds.** Actual nested admission and fixture executors
preserve namespace, capability, policy and network-boundary checks without using
the host executor adapter. Host environment/file/descriptor canaries and an owned
host listener are inaccessible. Forged authority fields, changed sessions,
replay, extra descriptors, oversized and duplicate-key packets cannot launch.
Forged READY/completion receipts, output floods, altered bootstrap, dead admission
and lost redemption acknowledgements permanently stop. A lost execution receipt
test explicitly witnesses that the tool already succeeded, then forbids retry.
Cancellation, deadline expiry and overlapping requests during an actual nested
executor reap the launcher/admission/executor process trees.

The combined authority path observes consumed grants and persisted intent before
remote execution. Denied approval or a lost durable audit acknowledgement prevents
launcher startup entirely. All six existing workflow CLI cases preserve outcomes
and evidence integrity with all four boundaries. Scripted PTYs establish mechanics,
not genuine human consent or acceptance. A further Linux case verifies that host
counter/config changes cannot refund the worker's output budget; it is included
in the full Linux regression run.

The full rootless Linux command was:

```sh
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short \
  --junitxml=/tmp/recon-launcher-all-linux.xml
```

**307 passed, 3,059 deselected in 520.50 seconds.** This includes all 37 new
launcher cases and the 270 established Linux regressions: approvals, audit,
admission, authority, planners/parsers, discovery, workflows, persistent lab,
evaluation and R5a/R5b provider boundaries. Both full JUnit reports contain zero
selected failures, errors or skips. No launcher/admission/executor or pytest
processes remained afterward. Python 3.11 grammar, dependency consistency, local
Markdown links and whitespace checks passed. No dependencies were added.

The launcher intentionally retains process/nested-namespace creation, bounded
private scratch and private proc UID/GID-map writes. It has zero capabilities,
no host filesystem/network or terminal/audit/credential state, and must remain
trusted fixed code. Children retain their existing syscall restrictions and
read-only proc mounts. Host consent/audit preconditions, persistent lab launching
and independent precondition authentication are outside this fixture-only slice.
R1–R4, R5a/R5b and established defaults remain closed; live execution remains
disabled. External provider calls, real credentials and spend: **zero**.

Runtime/test evidence above is tied to implementation `838c4a1`, published in
[PR #20](https://github.com/0xsl0th/recon-cockpit/pull/20) against `main`. The
publication checkpoint changes documentation only. Current review state and hosted
checks are linked from [continue-here.md](continue-here.md). Hosted portable CI
complements the local kernel evidence. The PR remains open for review, with no
new merge or live execution authorized.

## R5 isolated launch admission — 29 September 2026

Implemented on `feature/isolated-launch-admission` from verified main `2c02c21`
(merged PR #18). The explicit `--isolated-launch-admission` option requires both
isolated approval and audit services. A fixed worker independently owns the
bootstrap policy/profile/limits, execution reservations and one-use permits;
the wrapper requires successful admission and redemption before calling an
existing owned executor. See [the contract](isolated-launch-admission.md).

The full portable command was:

```sh
.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra \
  --junitxml=/tmp/recon-admission-portable.xml
```

**2,988 passed, 270 deselected in 79.17 seconds.** The 105 additional portable
cases cover strict configuration/request/receipt schemas, fixed policy and
fixture profiles, independent step/output limits, one-use permits, binding,
expiry and restart invalidation. Client tests cover changed controls, sequence
exhaustion, counter rollback, malformed receipts and permanent poisoning.
Wrapper tests witness no launch after failed admission/redemption, cancellation
or an overlapping call before launch. CLI tests cover invalid combinations,
inert dry-runs and noninteractive refusal.

The focused Linux command was:

```sh
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest tests/test_secure_launch_admission_linux.py \
  -m integration -x -v --tb=short
```

**35 passed in 48.89 seconds.** Actual namespace, capability, descriptor and
syscall checks establish the restricted worker boundary. Host environment/file/
descriptor canaries are absent. Forged initialization, changed sessions/services,
replay, reset/approval/budget fields, duplicate keys, oversized packets and extra
descriptors are refused. Forged READY/receipts, output floods, dead workers, lost
admit/redeem acknowledgements, cancellation and deadline expiry stop without an
underlying launch and reap the worker. Resetting the host executor's counters
cannot replenish the worker's allowance.

The combined coordinator/approval/audit/admission/executor path observes consumed
grants and persisted intent before every launch. Approval denial or a lost durable
audit acknowledgement prevents admission from starting. All six existing workflow
cases preserve their outcomes and evidence integrity with all three options;
the persistent owned-lab case also validates. Scripted PTYs establish mechanics,
not genuine human consent or operator acceptance.

The full rootless Linux command was:

```sh
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short \
  --junitxml=/tmp/recon-admission-all-linux.xml
```

**270 passed, 2,988 deselected in 472.98 seconds.** This includes all 35 admission
cases and the 235 established Linux regressions, including audit, approvals,
authority, planners/parsers, discovery, workflow/assessment/lab evaluation and
R5a/R5b provider boundaries. Both full JUnit reports contain zero selected
failures, errors or skips. No admission/approval workers or pytest processes
remained after verification. Python 3.11 grammar, dependency consistency, local
Markdown links and whitespace checks passed.

The host remains trusted for launcher custody and consent/audit ordering; this
worker does not independently attest those preconditions or contain host compromise.
Its in-memory allowances are per session, not a durable engagement quota or a
replacement for the R5b provider-money ledger. No new dependency, provider
activation, tool, target topology or generic registry was introduced. Remaining
launcher separation and bounded planning integration precede gated live-model
acceptance and R6. External provider calls and spend remain **zero**.

Runtime/test evidence above is tied to implementation `8a215f3`, published in
[PR #19](https://github.com/0xsl0th/recon-cockpit/pull/19) against `main`. The
publication checkpoint changes documentation only. Current publication state
and hosted checks are linked from [continue-here.md](continue-here.md); hosted
portable CI does not replace the local kernel verification.

The operator subsequently authorized review and merge of PR #19. Review found
no blocking issue and reran **294 focused portable tests** and **35 Linux admission
tests in 49.07 seconds**, with no runtime correction. JUnit reports:
`/tmp/recon-admission-review-portable.xml` and `/tmp/recon-admission-review-linux.xml`.
Reviewed head `b1fe045` passed all five PR checks and merged as `e9c5496` on
29 September at 03:33:29 UTC. Its tree matches the reviewed head exactly, and
all five [post-merge main jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/36517670318)
passed. This merge is complete; it does not authorize a subsequent merge or live call.

## R5 isolated terminal approvals — 29 September 2026

Implemented on `feature/isolated-approvals` from verified main `5650b86`.
PRs #16 and #17 are already merged; their five final main CI jobs passed.
This slice transfers terminal review and ephemeral grant issuance/consumption
to one fixed worker, selected by `--isolated-approvals`. Policy/accounting and
launch decisions remain in the host. See [the authority contract](isolated-approvals.md).
Accepted R1–R4, R5a/R5b and isolated audit work remain closed.

The final full portable command was:

```sh
.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra \
  --junitxml=/tmp/recon-approvals-portable.xml
```

**2,883 passed, 235 deselected in 86.97 seconds.** The 73 additional portable
cases cover strict message/reference/bootstrap validation, forged issuance,
policy/reset fields, session/sequence binding, malformed receipts, permanent
client/controller poisoning, immutable execution control, request limits,
inert construction/dry-run, unsupported CLI modes and noninteractive refusal.
Authority tests preserve a static approval-failure summary even if a coordinator
double swallows the exception, with no subsequent launch. Coordinator supervision
preserves the original approval exception identity.

The focused Linux command was:

```sh
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest tests/test_secure_approval_linux.py \
  -m integration -x -v --tb=short
```

**41 passed in 42.20 seconds.** Owned scripted PTYs exercise actual namespace,
descriptor and syscall restrictions, absent host environment/file/descriptor
canaries, exact fresh challenges, flushed pretyped input, wrong/bounded answers,
grant replay/expiry/action-policy binding and restart invalidation. Adversarial
messages include forged issue/reset/boolean approvals, changed sessions/policies,
out-of-scope actions, extra descriptors, oversized and duplicate-key packets.
Missing/nonterminal descriptors, forged READY, dead workers and lost receipts
permanently close the client. Review limits, cancellation and deadlines reap
children without restoring grants or extending the execution budget.

Actual coordinator/approval/audit/executor checks observe consumed grants and
persisted intent before every owned launch. Denial, cancellation, timeout and
lost consumption acknowledgements stop the real authority with no launch.
All six existing workflow CLI cases preserve outcomes and evidence integrity
with both isolated services enabled and one fresh scripted challenge per action.
These are grant-mechanics fixtures, not evidence of genuine human approval.

The final full rootless Linux command was:

```sh
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short \
  --junitxml=/tmp/recon-approvals-all-linux.xml
```

**235 passed, 2,883 deselected in 435.30 seconds.** This includes all 41 new cases
and the 194 established regressions: audit, authority, planners/parsers, discovery,
assessments/workflows, persistent lab, evaluation, R5a TLS and R5b controlled calls.
Both full JUnit reports contain zero selected failures, errors or skips.

No dependencies were added. Python 3.11 grammar, dependency consistency, local
Markdown links and whitespace checks passed. Local boundary review confirms that
the terminal is the intentional capability, input injection/mode changes are
blocked, and the grant store remains in the worker. The host/bootstrap/user and
fixed reviewer remain trusted; a compromised reviewer could falsify consent,
and the host still owns launch decisions. This is not an independent security audit.

All development and provider verification used owned/mock fixtures and synthetic
credentials. External provider calls and spend: **zero**. Live execution remains
disabled. Remaining R5 authorization/launch separation and bounded planning
integration precede R6; real-model acceptance remains explicitly gated. Current
publication state is recorded in [continue-here.md](continue-here.md).

Runtime/test evidence above is tied to implementation `0055f61`, published in
[PR #18](https://github.com/0xsl0th/recon-cockpit/pull/18) against main. The subsequent
checkpoint update changes documentation only. Hosted portable checks complement
the local Linux evidence; they do not run the kernel integration suite.

The operator subsequently authorized review and merge of PR #18. Review reran
**299 focused portable tests in 1.00 second** and **41 Linux approval tests in
42.38 seconds**, with no blocking findings or runtime changes. JUnit reports:
`/tmp/recon-approvals-review-portable.xml` and `/tmp/recon-approvals-review-linux.xml`.
Reviewed head `b21501f` passed all five PR jobs and merged as `2c02c21` on
29 September at 02:49:04 UTC; its tree matches the reviewed head exactly.
All five [post-merge main jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/36514354136)
passed. This merge is complete and does not authorize the next PR's merge.

## R5 confined audit persistence — 29 September 2026

Implemented on `feature/isolated-audit-writer`, from the corrected planning head
`2267e98` in PR #16 (runtime baseline `1369166`, PR #15). R5a/R5b remain complete.
This slice separates append persistence, with an explicit Linux CLI option;
approval issuance, authorization and launch decisions still belong to the host.
See [the authority and failure contract](isolated-audit.md).

The full portable command was:

```sh
.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra \
  --junitxml=/tmp/recon-audit-portable.xml
```

**2,810 passed, 194 deselected in 77.82 seconds.** The 60 new portable cases
cover strict packet/event schemas, reserved envelope fields, replay and identity
binding, partial writes, fsync failure, descriptor modes, event limits, permanent
poisoning, unsupported CLI modes and absent-isolation refusal without fallback.

The focused real Linux command was:

```sh
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest tests/test_secure_audit_linux.py \
  -m integration -v --tb=short --junitxml=/tmp/recon-audit-linux.xml
```

**28 passed in 31.94 seconds.** These exercise the actual namespace/seccomp
boundary, exclusive descriptor custody, concurrent producers, absent inherited
host files/environment/descriptors, changed file identities/modes/links, dead
writers, replay, extra descriptors, oversized requests, failed fsync, silent or
flooding workers and forged receipts. A real coordinator/authority/executor path
observes the persisted intent before each owned launch, including denial and
fixture-grant cases. Separate no-launch witnesses cover lost acknowledgements
and cancellation/deadline expiry after intent persistence. All six fixed workflow
CLI cases retain their expected outcomes and evidence with the new sink.

The full rootless Linux regression command was:

```sh
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short \
  --junitxml=/tmp/recon-audit-all-linux.xml
```

**194 passed, 2,810 deselected in 391.19 seconds.** This includes the 28 new
audit tests and all 166 existing Linux regressions for authority, approvals,
planners/parsers, discovery, workflows, persistent labs, evaluation, R5a TLS and
R5b controlled provider calls. The portable, focused Linux and full Linux JUnit
reports contain zero selected failures, errors or skips.

Local boundary review also blocked `ioctl`, `fallocate` and descriptor flag
changes, preventing alternate file-modification routes through an append handle.
The channel switches to nonblocking mode before these restrictions; later waits
use `select` without changing descriptor flags. These are local development
reviews, not an independent security audit.

No dependencies were added. Python 3.11 grammar, dependency consistency,
documentation links and whitespace checks passed. Existing record schemas and
provider/cost implementations are unchanged. Actual external provider calls and
spend: **zero**. This work does not enable live providers, claim immutable storage
against the host owner, or complete the remaining R5 authority/planning work.
The portable workflow also admits PRs based on `docs/milestone-realignment`,
so the focused dependent PR receives the existing five-job matrix. The runtime
results above are tied to implementation `d918e5b`; this trigger update changes
no runtime behavior.

## R5b controlled provider call — 29 September 2026

Implemented on `feature/controlled-provider-call`, based on PR #14's merge
`3a0cb67`. That merge was explicitly authorized and its five hosted portable jobs
passed. The operator authorized the next focused PR but required fully offline
development and verification, owned/mock fixtures only, no paid or external
provider calls, and live execution disabled by default.

The [controlled-call contract](controlled-provider-call.md) adds a standalone
fixed synthetic ACK profile with one durable financial dispatch. It reuses the
ledger, supervisor, namespace, privilege and HTTP validation machinery. The
credential worker receives one pinned TCP capability only after sandbox checks
and durable financial/audit admission. It cannot create sockets, reconnect the
received capability, create processes or regain namespace privileges. No GUI,
assessment runner or CLI activates this path.

The full portable command was:

```sh
.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra \
  --junitxml=/tmp/recon-pilot-portable.xml
```

**2,750 passed, 166 deselected in 71.53 seconds.** The 73 new portable cases cover
disabled execution before I/O, destination/config validation, every budget level,
per-call caps, simulation/provider separation, exact estimates/holds/settlement,
audit and persistence failures, duplicate receipts, concurrent invocation,
single-use dispatch, cap changes during setup, cancellation, billing overruns,
unsupported usage dimensions, private key-file handling and bounded chunked HTTP.
The earlier R5a reader still rejects chunked framing by default.

The full rootless Linux command was:

```sh
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short \
  --junitxml=/tmp/recon-pilot-linux.xml
```

**166 passed, 2,750 deselected in 360.70 seconds.** All 18 new Linux cases use
ephemeral owned TLS certificates, synthetic credentials and loopback servers.
They exercise real Bubblewrap/seccomp/nftables restrictions, positive network
witnesses, descriptor transfer, TLS verification, both supported HTTP framings,
wrong certificates/hostnames, redirects, rate limits, truncation, oversized
responses, literal/escaped credential echoes, missing usage, rejected output,
deadline/cancellation cleanup, failed namespace setup and failed durable audit.
Removing the connect restriction makes startup fail before a connection or key
handoff. Killing the host controller after the request leaves the durable
dispatch and full cost hold, with no surviving descendant processes.

Local review caught two boundary issues before final verification: a repeated
descriptor check incorrectly classified the loader's private libffi descriptor
as inherited authority, and namespace DROP rules alone could not prevent
reconnecting a received host-created TCP socket. The inherited descriptor check
now runs before imports, and a second seccomp layer denies connect/socket
creation before handoff, with actual disconnect-denial witnesses. Public IPv4
validation also explicitly rejects multicast, which Python may classify as
global. These are local development reviews, not an independent security audit.

Both final JUnit reports contain zero selected failures, errors or skips.
Dependency consistency, compilation, Python 3.11 grammar checks for 143 Python
files, changed documentation links and whitespace checks passed. No dependencies
were added. The full Linux suite also freshly verifies existing R5a, planner,
authority, routed owned-lab, evaluation and workflow behavior after the two shared
helper changes.

Actual provider calls and spend: **zero**. Live provider framing, model
availability, usage semantics and billing are not established by these fixtures.
Production pricing remains explicit operator configuration. Live activation and
validation are deferred to a later authorized step.

Reviewed implementation `50f51b2` is published in
[PR #15](https://github.com/0xsl0th/recon-cockpit/pull/15), left open for review.
The follow-up publication checkpoint edits documentation only; these local
runtime results remain tied to the implementation above. Inspect the PR's current
head and hosted checks before any further publication or merge.

## R5b provider cost ledger — 28 September 2026

Reviewed on `feature/provider-cost-ledger` from `0a9697f`, with the operator's
authorization to implement, commit and push the monetary ledger and hierarchical
controls described in [provider-cost-ledger.md](provider-cost-ledger.md). The
earlier pilot-named development branch contains no live pilot implementation.
No R5b PR has been opened at this checkpoint. This adds no provider transport or GUI,
and all demonstration charges are explicitly marked simulation. Existing R5a
synthetic accounting and namespace runtimes are unchanged.

The focused command is:

```sh
.venv/bin/python -m pytest tests/test_secure_cost_contract.py \
  tests/test_secure_cost_ledger.py tests/test_secure_cost_cli.py \
  --strict-markers -ra --junitxml=/tmp/recon-cost-focused.xml
```

**129 tests passed in 2.21 seconds.** Coverage uses actual private SQLite stores,
two independent processes competing for a shared ancestor budget, two connections
claiming the same dispatch, and abrupt child process exit before/after durable
accounting transitions. It also covers rollback after event-write failure,
read-only inspection preserving bytes/mtimes, immutable pricing, exact integer
rounding, receipt replay, billing corrections, unknown costs, actual overruns,
each hierarchy level, durable refusals, private storage checks and operator CLI.
These are local accounting/process tests, not live provider billing validation.

Publication review reproduced a concurrency defect: closing the extra database
descriptor used for identity checks released another connection's active POSIX
lock. A second process could then acquire a write transaction prematurely.
Identity checks now use metadata without opening another database descriptor.
Two regressions cover closing both read-only and writable handles during a write
transaction, and require the external writer to stay blocked until commit.
Three additional regressions ensure inherited handles reject reads, writes and
close before accessing a lock or the parent's SQLite connection. The full suite
below includes these corrections; this was a local review, not an independent audit.

The full portable command is:

```sh
.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra \
  --junitxml=/tmp/recon-cost-portable.xml
```

**2,677 passed, 148 deselected in 69.47 seconds.** Both final JUnit reports contain
zero selected failures, errors or skips. No namespace, network, credential or
execution boundary was modified; the 148 Linux integration tests are deselected,
not claimed as fresh verification for this slice.

The final local demo at `.secure-agent/cost-ledger-demo-20260928-final` passed:
25 microUSD fictional actual cost, 300 held, 175 available under a 500 microUSD
engagement limit; one unresolved call and an audited parent-budget denial.
Its 16 ledger events survive reopening. Read-only CLI inspection reproduced the
report and preserved every file byte and mtime. Actual provider calls: **zero**.
Dependency consistency and Python 3.11 grammar checks passed for all 138 Python
files. Compilation, changed documentation links and whitespace checks passed.
The accounting uses the Python standard library without new dependencies.

## Owned TLS provider foundation — 26 September 2026

Implemented on `feature/isolated-provider-foundation` from `ba3951e`. The operator
authorized this focused R5a implementation and PR; merge authority for previous
PRs does not apply. The [foundation contract](provider-foundation.md) preserves
the offline authority and 18-trial evaluation contract. This slice adds only a
disconnected TLS fixture, synthetic credentials/model/cost, status-only data
release and a separate constrained broker transport. It executes no tools and
contacts no public provider.

Reviewed implementation `7125c99` was published in
[PR #13](https://github.com/0xsl0th/recon-cockpit/pull/13) after all local checks
below passed. Inspect the PR's current hosted checks before further publication
or merge. The follow-up publication checkpoint changes documentation only;
local runtime tests were not repeated for those notes. The PR remains open for
the operator's merge decision.

Independent runtime, contract and portability reviews found two defects before
publication. A cancellation after the TLS response but before owner counter
collection could produce an incomplete successful receipt, masking the original
stop. Success now requires the counters; partial observations remain available
without inventing counts. Two real Linux regressions cancel during the counter
request and collection, checking stopped audit, full retained reservations,
unreleased response bytes and reaped processes. The demo also now sanitizes
temporary audit-directory setup failures; its regression verifies safe JSON,
exit status 2 and no private exception text or provider launch. Independent review
confirmed the final fixes with no remaining blocker. These are bounded development
reviews, not an independent security audit.

| Check | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra --junitxml=/tmp/recon-provider-final-portable.xml` | **2,548 passed, 148 deselected**, 87.89 seconds |
| `RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short --junitxml=/tmp/recon-provider-linux.xml` | **148 passed, 2,548 deselected**, 345.51 seconds |
| `RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest tests/test_secure_provider_linux.py -m integration -v --tb=short --junitxml=/tmp/recon-provider-review-linux.xml` | **16 passed**, 17.48 seconds, including both review regressions |
| All three JUnit reports inspected | Zero selected failures, errors or skips |
| Compile, dependency consistency, Python 3.11 syntax and relative documentation links | Passed; 131 Python files parse with the 3.11 grammar |
| `git diff --check` | Passed |

The final full suites include the two review fixes and all new tests. A
coding-service restart interrupted earlier full portable/Linux processes and
left no complete final reports; their partial progress is not passing evidence.
No matching test processes survived, so both full suites were restarted. The
completed provider-only run was preserved rather than repeated separately.
Kernel checks ran as the normal Kali Linux x86_64 user with Python 3.14.6,
outside the coding sandbox. The existing 18-trial evaluation baseline also
passed within the full Linux suite.

Portable tests cover strict canonical requests and the status-only release
profile, full-attempt reservations, immutable control lifetimes, audit failure,
closed receipt schemas, TLS configuration, credential reflection and bounded HTTP
framing. Linux tests exercise every fixed fixture scenario, actual verified TLS,
positive forbidden-destination listeners, host-file/environment/descriptor
canaries, cancellation during active TLS and late counter collection, deadlines
and observed cleanup. The successful reply is parsed in the existing separate
networkless sandbox. Hosted portable checks do not establish kernel enforcement.

The actual standalone demo command was:

```sh
.venv/bin/python scripts/secure_agent_provider_demo.py --execute \
  --audit .secure-agent/provider-foundation-20260926/audit.jsonl
```

Exit 0, `status=passed`, all ten transport and seven parser boundary checks true,
one connection/request and both owner/worker processes reaped. The request reserved
one call, 1,024 output tokens, 3,060 request bytes and **5,208 synthetic cost units**;
the response was 252 bytes and decoded to an inert done proposal. The private
audit contains exactly the durable reservation and successful completion events,
with directory/file modes 0700/0600. The default dry-run also passed without
starting a runtime or creating audit storage. No real credentials, provider calls,
monetary spending, external targets or host-network changes were involved.

The host bootstrap, runtime libraries, kernel and audit owner remain trusted.
Reflection checks cover literal credentials and JSON string escapes, not arbitrary
secret encodings. Reservations are ceilings and synthetic tariff tests, not token
measurement or real billing. Unknown observations after interruption remain
unknown; filesystem/kernel stalls remain outside a hard wall-clock guarantee.

## PR #12 review and authorized merge — 25 September 2026

The operator explicitly authorized review and merge of the evaluation runner.
Final reviewed head `e23016a500b6fa24e36f783f4e2ba93662740321` includes the
strict audit-context correction described below. Independent runtime and evidence
reviews found no remaining blocker. All five
[final PR CI jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/36070544788)
passed on Ubuntu Python 3.11–3.14 and macOS Python 3.14; GitHub had no outstanding
review comments or merge conflicts.

[PR #12](https://github.com/0xsl0th/recon-cockpit/pull/12) merged with an exact-head
guard as `ff5f76a6f81327b7ef184d7cfefff29ff087dd47` at 04:35:39 UTC.
Local main was fast-forwarded and the merge tree exactly matches the reviewed
head. All five [post-merge main jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/36095076635)
also passed. This publication checkpoint changes documentation only; local
runtime tests were not repeated for these notes. Inspect current main checks
when continuing.

## Repeatable owned evaluation runner — 24 September 2026

Implemented on `feature/owned-lab-evaluation` from merged main `3b9ba7b`.
The operator requested the 18-run baseline, independent saved-evidence grading,
JSON/Markdown aggregate reports and cleanup/isolation/resource verification before
opening a PR. Publication state is in [continue-here.md](continue-here.md).

Implementation `665fcb7892ce5f839a1391c5ff7a338d054c0e29` was published in
[PR #12](https://github.com/0xsl0th/recon-cockpit/pull/12) after the local checks
and final CLI baseline below completed. All five
[implementation-head CI jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/36039270526)
passed: Ubuntu Python 3.11–3.14 and macOS Python 3.14. There were no GitHub
review comments or merge conflicts at that head. The operator subsequently
explicitly authorized review and merge after checks pass.

Final independent review reproduced an audit-integrity gap: deleting a required
session identifier or substituting an action identifier could still pass grading.
The grader now requires exact event fields, validates typed step counters and
binds every emitted action identity to the saved assessment. It also validates
the event envelope and required authority/provider context. One regression reuses
a valid batch across 73 mutations and requires failed trial/aggregate grades,
unknown metrics, no abstention credit for the corrupted trial and read-only
inspection. The independent reviewer confirmed the fix with no remaining blocker.
The stricter grader also reproduced the saved real 18-run baseline exactly,
preserving every evidence file's bytes and modification time.

`--evaluate-owned-lab` runs cases a–f three times with fresh authority, lab,
coordinator, parser and broker instances. The separate versioned oracle requires
each case's exact action/observation/terminal trace. The grader replays saved
assessment evidence and reconciles it with the authority/broker audit, artifact
boundary witnesses and runtime cleanup/accounting receipts. Batch inspection
regrades from disk and compares its reconstruction with both aggregate formats.
See [evaluation.md](evaluation.md) for commands, score interpretation and limits.

| Check | Observed result |
| --- | --- |
| After audit fix: `.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra --junitxml=/tmp/recon-evaluation-review-portable.xml` | **2,300 passed, 132 deselected**, 82.73 seconds |
| After audit fix: `RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest tests/test_secure_evaluation_linux.py -m integration -v --tb=short --junitxml=/tmp/recon-evaluation-review-linux.xml` | **6 passed**, 75.22 seconds; new 18-run baseline, cleanup/isolation/accounting and cancellation/deadline checks |
| `.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra --junitxml=/tmp/recon-evaluation-portable.xml` | **2,299 passed, 132 deselected**, 50.00 seconds |
| `RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short --junitxml=/tmp/recon-evaluation-linux.xml` | **132 passed, 2,299 deselected**, 335.75 seconds |
| Both JUnit reports inspected | Zero selected failures, errors or skips |
| Focused new Linux module | **6 passed**, 71.20 seconds; includes one 18-trial batch shared by three baseline assertions, plus cancellation/deadline runs |
| Compile, dependency, Python 3.11 syntax and relative documentation links | Passed; no broken requirements or broken relative links |
| `git diff --check` | Passed |

The review fix changes grading and its tests only. The other 126 real Linux
results still apply to the unchanged runtime. Both review JUnit reports also
record zero selected failures, errors or skips.

New coverage totals 74 portable tests and six Linux tests over the merged lab
foundation. Portable tests use explicit namespace/provider doubles while keeping
the real authority, broker, evidence store and grader. They cover all six expected
traces, all 18 scheduled trials, tampered receipts/artifacts/audit/cached reports,
manifest substitution, strict counters and limits, duplicate identities, unsafe
files/output reuse, audit failure before startup, cancellation, torn journal
prefixes and CLI read-only inspection. Selected portable tests also run on hosted
Ubuntu/macOS CI; they do not establish kernel enforcement.

The real Linux tests observe Bubblewrap/nsenter child handles, owner descendants
with PID start times, and pinned namespaces distinct from the host. They verify
fresh session/assessment/lab/broker IDs, service continuity, closed namespace
descriptors, reaped direct children and no surviving observed descendants.
Active cancellation produces a failed trial within an incomplete batch; a
between-trial cancellation preserves the completed grade and starts no next lab.
The one-second batch deadline similarly stops further work. All original 126
Linux tests also passed with the new optional authority deadline ceiling.

Review identified that flooring remaining seconds before constructing a session
would let setup delays extend the batch lifetime. Authority now uses the earlier
of its fixed session deadline and a trusted absolute outer deadline; the batch
timer supplies cancellation as well. Other review checks enforce strict retained
response byte bounds for timeout/output-limit cases, separate expected observation
reasons, and preserve verified reservations when later journal data is torn.
Two initial deadline test assertions expected a new reason name; they were
corrected to the existing `session_timeout` contract, then passed. No isolation
or approval requirement was weakened. These are development checks, not an
independent security audit.

The evaluation specification is `owned-workflow-evaluation`, version `1`, SHA-256
`f9a9901e9e71002c26b3b108bdb08d35ff909f71f8d0b645e7fe534718a8cc3b`.
Its expected complete baseline is 18 passing trials: three validated, three not
demonstrated and twelve correct abstentions. This entails 54 planning steps,
51 executions/broker calls, 45 successful actions, and 52,224 reserved tool-output
bytes and broker output tokens. Batch admission conservatively reserves 55,296
bytes/tokens and 54 calls before work; it does not refund early stops.

The explicit `examples/secure-agent-evaluation-policy.json` permits unattended
owned-fixture execution; no human grants were supplied or claimed. The existing
approval-required example is unchanged. Tests ran as the normal Kali Linux
x86_64 user with Python 3.14.6, outside the coding sandbox for kernel execution.
No host-network, dependency, credential, external-target or live-provider change
was needed. Runtime and evidence remain trusted host components; hashes do not
resist host-owner tampering, and closure observations are not external attestations.
Reservations are ceilings, not measured token usage, wire traffic or monetary
spend. Unknown measurements after interruption remain unknown.

Final real CLI baseline:

```sh
.venv/bin/python -m recon_cockpit.secure_agent --evaluate-owned-lab \
  --policy examples/secure-agent-evaluation-policy.json \
  --evaluation-dir .secure-agent/evaluation-baseline-20260924 --execute
```

Exit 0; **18/18 passed** in **72,004 ms** for the batch. All 18 cleanup and
isolation grades passed, all identities were fresh, all six cases agreed across
repetitions and resource accounting was complete. Observed totals: 54 planning
steps, 51 executions/broker calls, 45 successful actions, 52,224 reserved tool
bytes/output tokens, 159,696 broker request bytes and 6,981 retained response bytes.
The observed outcomes were three validated, three not demonstrated and twelve
correct abstentions; there were zero unnecessary actions under the fixed oracle.

Private aggregate reports are `.secure-agent/evaluation-baseline-20260924/report.json`
and `report.md`, with links to all 18 assessment bundles. The actual
`--inspect-evaluation` CLI exited 0 and exactly reproduced the saved JSON report.
Every file's bytes and modification time stayed unchanged, and all directory/file
modes were 0700/0600. Private raw artifacts remain ignored. Earlier development
output used an intermediate schema and is not the publication baseline.

## PR #11 review and authorized merge — 24 September 2026

The operator explicitly authorized commit, push and merge of the completed lab
foundation if review and checks passed. Bounded launcher, authority/evidence and
portability reviews found no blocker at implementation head
`15583161e09658ef808160ecf308ab74e82b60c8`. All five
[PR checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/35939526013)
passed: Ubuntu Python 3.11–3.14 and macOS Python 3.14. GitHub showed no
outstanding reviews/comments or merge conflicts. The local results below apply
to the same production and test files; only verification/checkpoint documentation
was completed before committing.

[PR #11](https://github.com/0xsl0th/recon-cockpit/pull/11) merged with an exact-head
guard as `7f316ce77f5c812477290e1b293d06d4afd88d53` at 00:42:55 UTC.
Local main was fast-forwarded and the merge tree exactly matches the reviewed
head. All five [post-merge main jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/35939661436)
also passed. The follow-up publication checkpoint changes documentation only;
local production tests were not repeated for those notes.

## Persistent owned lab foundation — 23–24 September 2026

Work starts from merged main `2b3527e` on `feature/secure-agent-owned-lab`.
The operator requested the foundation and subsequently authorized commit, push
and merge if review and checks pass. Publication is recorded in
[continue-here.md](continue-here.md).

`--workflow-assessment CASE --owned-lab` keeps one seeded service alive for the
three-action workflow, with a fresh executor sandbox for each action. The fixed
disconnected topology permits only `127.0.0.1:8080`. Startup follows policy,
approval, budget and durable execution audit; cleanup destroys the instance.
Workflow card v2 and a distinct evidence profile bind the lab specification,
instance identity, service counters and closure receipt. Card v1 is unchanged.
See [owned-lab.md](owned-lab.md) for the lifecycle and trust contract.

Tests ran as the normal Kali Linux x86_64 user with Python 3.14.6. Kernel tests
ran outside the coding sandbox with the application's isolation enforced.
No host networking, package, credential, external-target or live-provider change
was needed.

| Check | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra --junitxml=/tmp/recon-owned-lab-portable-final.xml` | **2,226 passed, 126 deselected**, 22.31 seconds |
| `RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short --junitxml=/tmp/recon-owned-lab-linux.xml` | **124 passed, 2,228 deselected**, 260.32 seconds |
| `RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest tests/test_secure_owned_lab_runtime.py -m integration -v --tb=short --junitxml=/tmp/recon-owned-lab-descriptors-linux.xml` | **2 passed, 42 deselected**, 0.15 seconds |
| All three JUnit reports inspected | Zero selected failures, errors or skips |
| Real CLI case a with explicit unattended owned-fixture policy | Exit 0; `validated` draft; three successful actions; three broker calls; 3,072 reserved output tokens and 3,072 reserved tool bytes |
| Read-only CLI inspection | Exact saved-report equality; no integrity issues; every file's bytes and modification time preserved; directory 0700, files 0600 |
| `.venv/bin/python -m compileall -q recon_cockpit/secure_agent`, `.venv/bin/python -m pip check`, `git diff --check` | Passed; no broken requirements |

The full Linux run preceded reclassification of two real `/proc` descriptor tests
from portable to integration. Production code was unchanged; the supplemental
run verified those two cases. Together these runs cover all **126 current Linux
tests**, not 126 cases in a single invocation. The final portable selection was
run after that correction. New coverage over PR #10 totals 92 portable and 17
Linux cases.

Linux coverage exercises all six scenarios, service continuity across fresh
sandboxes, reset with a new instance and the same semantic result, namespace
substitution, owner death, child reaping, active and between-action cancellation,
dry-run, missing approval and insufficient budget. Scripted-grant tests establish
that lab startup follows grant consumption and durable execution audit; they are
not human consent evidence. Portable tests cover strict runtime envelopes,
lifecycle refusals, CLI selection, identity/counter/closure tampering and replay.

The first focused kernel run exposed descriptor handling defects: namespace
handles survived `nsenter` and Bubblewrap, and a late descriptor check also saw a
distribution libffi descriptor opened by `ctypes`. The fixed, isolated Python
bootstrap now closes inherited namespace handles after joining and before
launching Bubblewrap. The executor checks for unexpected handles before importing
`ctypes`. The guard was not relaxed. Review also caught boolean sequence numbers
and snapshots below the requested counter barrier; both now fail closed.
The corrected focused module passed all 15 cases before the full Linux run.

Bounded development reviews of the launcher, authority binding and evidence
replay found no remaining blockers. The bootstrap uses fixed interpreter/source
and host-built Bubblewrap arguments; no proposal chooses code or an executable.
These reviews and tests are not an independent security audit.

Private sample: `.secure-agent/owned-lab-a-20260923/report.json` and `report.md`,
with `.secure-agent/owned-lab-a-20260923-audit.jsonl`. Its temporary policy,
`/tmp/recon-owned-lab-demo-policy.json`, explicitly allows unattended owned-fixture
execution. The repository policy still requires fresh approvals. The same lab
instance appears in all three artifacts, with `(connections, requests)` counters
`(1, 0)`, `(2, 1)`, `(3, 2)` and a closed receipt at `(3, 2)`.
Card v2 SHA-256 is
`da8dca2eeb37b3453e838d6519287e47996f0b9bc9ea16c40f654221d4a3255c`;
case-a lab specification SHA-256 is
`ff0f130d61875294e165fe0e3e27dd863a47fe11d8cdf6fcd4e0cf3ac331d4dd`.
Private files remain ignored; temporary artifacts may disappear after reboot.

Closure repeats the last acknowledged service totals, not a final counter sample
after interruption. An interrupted action can leave partial, inconclusive evidence
and `evidence_error`; cleanup still runs and inspection never fabricates completion.
Host authority, lifecycle supervision and evidence remain trusted in one host
process. Hashes and counters do not resist a malicious host owner. Existing HTTP
framing limits remain. This delivers the lab foundation; the aggregate repeatable
evaluation runner remains subsequent work.

## PR #10 review and authorized merge — 23 September 2026

The operator authorized review and merge of the open correction PR. The reviewed
head `9fef4987a1a98d3d44f1d65b8d3b2e99fb57e7a3` had no outstanding GitHub
reviews/comments and all five
[PR checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/35871537198)
passed. The prior 2,134 portable results applied to the unchanged test correction;
only publication documentation had changed. Review found no blocker.

[PR #10](https://github.com/0xsl0th/recon-cockpit/pull/10) was marked ready and
merged with an exact-head guard as `2b3527ec20c8a8b9dd30f5e7aa000bb48aa51fc3`
at 14:14:09 UTC. Local main was fast-forwarded and its tree matches the reviewed
head. All five [post-merge main jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/35872690851)
passed. The new lab work starts from that merge on `feature/secure-agent-owned-lab`.

## R4 merge recovery and post-merge CI correction — 23 September 2026

The operator requested review of [PR #9](https://github.com/0xsl0th/recon-cockpit/pull/9)
and authorized merging if sound. The interrupted session completed that review
and merge. Bounded engine/provider and evidence/replay reviews found no blockers
at head `401cbe153ebbb4a1aa8e699507203b88663eebb4`, based on `1086301`.
There were no GitHub reviews or inline comments requiring resolution. A fresh
focused workflow/HTTP/discovery run passed **289 tests in 3.18 seconds**;
the two reviewers' overlapping 97- and 127-test runs also passed. These are not
additive full-suite counts. The prior full **2,134 portable / 109 Linux** results
were checked against unchanged production/test/CI files from `9bcb8b2`.

All ten jobs passed on the reviewed head: five in
[branch CI](https://github.com/0xsl0th/recon-cockpit/actions/runs/35806225192)
and five in [PR CI](https://github.com/0xsl0th/recon-cockpit/actions/runs/35806227338).
PR #9 was marked ready and merged as
`8673dc0ac02a762dae08f2533885d2246fb04e2a` at 01:29:31 UTC. The usage limit
interrupted after fetching the merge, before local-main synchronization and the
checkpoint update. Recovery after the power loss found the clean feature branch
at `401cbe1`; Git object checks found no corruption. Local main was fast-forwarded
to `8673dc0`, whose tree exactly matches the reviewed head.

The [post-merge main run](https://github.com/0xsl0th/recon-cockpit/actions/runs/35806498955)
passed four jobs but failed Ubuntu Python 3.12: **2,133 passed, 1 failed, 109
deselected**. `test_cancel_interrupts_offline_delay_and_keeps_the_reservation`
started a 30 ms cancellation timer before broker entry. Under host load it could
fire after reservation but before the transport consumed a scripted reply, so
production correctly retained one reservation and stopped with its transport
counter at zero. The test expected one consumed reply because it intended to
exercise cancellation during delay.

The correction uses a fixed clock and sets the event from its first delay wait,
after transport entry. It verifies the cancellation reason, retained call/token/
request-byte reservations, stopped audit with no response metadata, and consumption
of the first scripted reply before a subsequent exchange. Existing tests retain
coverage for cancellation before reservation and during audit. This changes one
portable test and checkpoint documentation; production code is unchanged.

| Check | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest tests/test_secure_openai_broker.py -ra` | **107 passed**, 0.37 seconds |
| `.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra --junitxml=/tmp/recon-r4-recovery-portable.xml` | **2,134 passed, 109 deselected**, 20.07 seconds |
| Recovery JUnit inspection | 2,134 cases; zero failures, errors or skips |
| `git diff --check` | Passed |

The existing 109 real Linux test results still apply to the unchanged production
code. Kernel tests were not repeated for this test/documentation-only correction.
Correction `9f34cbc` was published in
[PR #10](https://github.com/0xsl0th/recon-cockpit/pull/10), initially as a draft.
Its subsequent review and merge are recorded above;
[continue-here.md](continue-here.md) records the current continuation state.

## R4: one versioned owned workflow — 23 September 2026

The operator accepted the first R4 card/engine slice and confirmed the team as
Enrique Folte with Codex development assistance. Work started on
`feature/secure-agent-workflow` from merged main `1086301`. R1/R2/R3 were not
reimplemented or merged again. Implementation `9bcb8b2` was published in
[PR #9](https://github.com/0xsl0th/recon-cockpit/pull/9), initially a draft;
its subsequent review, merge and recovery are recorded above.
All ten hosted portable jobs passed at that commit: five in
[branch CI](https://github.com/0xsl0th/recon-cockpit/actions/runs/35806046599)
and five in [PR CI](https://github.com/0xsl0th/recon-cockpit/actions/runs/35806060768).
They cover Ubuntu Python 3.11–3.14 and macOS Python 3.14, independently of local
kernel verification. Publication checkpoint `401cbe1` changed documentation only;
its separate hosted checks are recorded above. Current publication state is in
[continue-here.md](continue-here.md).

The new `--workflow-assessment` mode uses one repository-authored versioned card
for the existing TCP → HTTP index → HTTP diagnostics path. Immutable decisions
bind the exact action, card digest and predecessor evidence; the private journal
records them before provider exchanges. Launches require the latest matching
proposal. Reports distinguish proposed and executed work and explain terminal
stops, including bounded approval-failure reasons. Inspection independently
replays decisions from artifacts and validates terminal/closure agreement.
See [workflow-assessment.md](workflow-assessment.md).

Tests ran as the normal Kali Linux x86_64 user with Python 3.14.6 and pytest
9.1.1. Real namespace tests ran outside the coding sandbox. No dependency,
credential, host-network, external-target or live-provider change was needed.

| Check | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra --junitxml=/tmp/recon-workflow-portable.xml` | **2,134 passed, 106 deselected**, 20.75 seconds |
| `RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short --junitxml=/tmp/recon-workflow-linux.xml` | **109 passed, 2,134 deselected**, 219.72 seconds |
| Both JUnit reports inspected | 2,134 portable / 109 Linux test cases; zero selected failures, errors or skips |
| Real CLI case a with explicit unattended owned-fixture policy | Exit 0; `validated` draft; three decisions and three successful executions; terminal explanation; three broker calls and 3,072 reserved tool bytes |
| Read-only CLI inspection | Exact saved-report equality; no integrity issues; every file's bytes and modification time preserved; 0700 directory and 0600 files |
| Compile, dependency and whitespace checks | Passed; no broken requirements |

The full portable run preceded three added Linux-only scripted-grant tests;
production and portable tests were unchanged. New coverage totals 157 portable
cases and 13 real Linux cases over the merged R3 baseline. Portable tests cover
immutable decisions, exact parser/evidence gates, candidate substitution,
durability before exchange, cancellation, write failure, budgets, safe terminal
reasons, corrupt/reordered/missing events and read-only crash inspection. Linux
tests exercise all six fixture cases, dry-run, tool budgets, missing/fresh/refused/
replayed grants, actual boundary witnesses and child-process cleanup. Scripted
grants test enforcement; they are not evidence of human consent.

Focused development reviews found no remaining blockers in provider/authority
binding or evidence replay. Review caught duplicate observation IDs that could
make terminal interpretation disagree with a positive report; inspection now
rejects that inconsistency. Review also prompted bounded approval reasons instead
of an unexplained generic blocked action. Regressions cover both. This is
development review, not an independent security audit.

An initial focused Linux run used a stale generic-blocked expectation while the
new precise approval reason was being added. The corrected missing-approval case
and new scripted-grant cases passed together. No production boundary change was
needed for that test correction.

Private sample: `.secure-agent/r4-example-a/report.md` and `report.json`, with
`.secure-agent/r4-example-audit.jsonl`. Its temporary policy,
`/tmp/recon-r4-owned-fixture-policy.json`, explicitly opts into unattended owned
fixture execution; the repository example policy still requires fresh approvals.
The card identity is `owned-discovery-http-assessment`, version `1`, SHA-256
`0ee868de914e71e0ad266c2500eb5657e82ffe498a0e7a7da8c2f5c8d36312b9`.
Temporary evidence may disappear after reboot; the measurements above are saved.

Current actions still recreate their namespace and fixture independently. This
slice does not establish persistent service continuity, general discovery, an
external knowledge library or live-model performance. Findings remain drafts
for operator review. Existing shared-host trust, callback, HTTP-framing and local
evidence-tampering limitations remain. Persistent lab and repeated evaluation
are subsequent work.

## R3 premerge review and authorized merge — 22 September 2026

The operator requested review of [PR #8](https://github.com/0xsl0th/recon-cockpit/pull/8)
and explicitly authorized merging if sound. Bounded reviews of executor/isolation,
workflow/schema and evidence/recovery found no concrete blockers at reviewed head
`124300af8c854c4e3be0cc2b2fb4b4c6c7f91549`. There were no unresolved GitHub review
comments or requested changes. Main remained at the tested base `75ebb8d`.

All ten branch/PR checks passed on the reviewed head: five jobs each in
[branch CI](https://github.com/0xsl0th/recon-cockpit/actions/runs/35737246850) and
[PR CI](https://github.com/0xsl0th/recon-cockpit/actions/runs/35737253627).
Fresh focused evidence/workflow/executor regressions passed **195 tests**;
reviewers also ran overlapping boundary and schema/HTTP checks (221 and 275
passing tests respectively). These are not additive full-suite counts.
The prior full **1,977 portable / 96 Linux** results still apply: production
files are unchanged since the verified implementation, and the final portable
platform-test correction passed hosted CI on macOS and Ubuntu.

PR #8 was marked ready and merged with an exact-head guard as
`b1c7b67f62a8f3c951308e28e58cd52cc4049b50` at 14:05:03 UTC. Local main was
fast-forwarded to that commit. A complete tree comparison against reviewed
`124300a` found no differences. No approval bypass, live provider, external target,
credential access or host network change was involved in this review/merge.

All five jobs on the
[post-merge main run](https://github.com/0xsl0th/recon-cockpit/actions/runs/35737835396)
passed at `b1c7b67`. The following checkpoint changes documentation only; inspect
current main checks for its separate hosted result.

## R3: owned TCP discovery-to-HTTP path — 22 September 2026

Recovered the clean `feature/secure-agent-discovery` checkout at `75ebb8d` after
session exhaustion and a power loss. Git object checks found no corruption;
the branch had been created but no R3 implementation edits existed. Current
GitHub main still pointed to `75ebb8d`, with successful portable CI. The saved
conversation confirmed the chosen one-connect discovery slice. R1/R2 merges
were already complete and were not repeated.

Historical implementation checkpoint: `ad30297` was published in
[PR #8](https://github.com/0xsl0th/recon-cockpit/pull/8), initially a draft.
It was subsequently reviewed and merged as documented above. The measurements
below are local verification, separate from hosted CI.

Implemented the smallest R3 slice on that branch: a typed `tcp_connect` action,
an explicit owned discovery executor, evidence-gated TCP → HTTP discovery → HTTP
validation, bounded private artifacts and a draft report. See
[discovery-assessment.md](discovery-assessment.md). No new runtime dependency,
package installation, host network change, live API call, credential access or
external/VPN target was used. Tests ran as the normal Kali Linux x86_64 user,
with Python 3.14.6 and pytest 9.1.1. Kernel checks ran outside the coding sandbox.

| Check | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra --junitxml=/tmp/recon-discovery-portable.xml` | **1,977 passed, 96 deselected**, 16.76 seconds |
| `RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short --junitxml=/tmp/recon-discovery-linux.xml` | **96 passed, 1,975 deselected**, 187.79 seconds |
| Parsed both final JUnit reports | Zero failures, errors or skips; 1,977 portable / 96 integration test cases |
| Real CLI case a using explicit unattended owned-fixture demo policy | Exit 0; one TCP and two HTTP executions; three broker calls; 3,072 reserved tool bytes; `validated` draft |
| Read-only CLI inspection of sample | Exit 0; `validated`; three linked records; zero integrity issues; file bytes and modification times unchanged |
| Compile, dependency and whitespace checks | Passed; no broken requirements |

The Linux run preceded two additional portable direct-backend refusal tests;
no implementation changed between that run and the final portable run. This
explains the different deselected count. Relative to R2 there are 128 additional
portable cases and 18 additional real Linux cases. A final evidence-test metadata
correction and descriptor assertion passed the focused evidence/executor checks;
production files were unchanged.

Initial hosted CI passed all Ubuntu/Python jobs but found one macOS-only test
failure: the portable host-namespace refusal test assumed a Linux platform and
expected the later namespace error, while macOS correctly refused at the earlier
Linux-only guard. The test now explicitly exercises both platform refusal paths
with network/setup calls forbidden. Focused portable executor checks passed
after this test-only correction; production code and Linux evidence are unchanged.

Linux additions cover six HTTP fixture cases following real TCP discovery,
missing/fresh/refused/replayed scripted grants across capability types, separate
step/output budgets, dry-run and artifact failure before further planning. Three
executor tests cover actual open/closed/timeout states and listening forbidden
IP/port witnesses. Closed/timeout variants modify a trusted temporary worker copy
inside the test harness, retaining the namespace boundary and using a stricter
namespace-local firewall for timeout. Production accepts only the fixed owned
profile. Scripted grants and the unattended demo are not human approval evidence.

A bounded development review found an inaccurate embedded executor descriptor
and evidence summaries that did not reconcile reservations/attempts with actual
records. The descriptor now names the discovery executor; writer and inspector
reject summaries below the recorded execution requirements. Regression tests
cover both, including a blocked action that legitimately reserves output without
creating an execution record. Review found no legacy/routed TCP execution escape;
direct refusal regressions exercise that boundary. This is development review,
not an independent security audit.

The private sample is `.secure-agent/r3-example-a/report.md` and `report.json`,
with `.secure-agent/r3-example-audit.jsonl`. Its 0700 directory and 0600 files stay
ignored by Git. The demo policy at `/tmp/recon-r3-owned-fixture-policy.json`
explicitly disables approval only for this unattended owned-fixture demonstration;
`examples/secure-agent-discovery-policy.json` requires approval. Temporary files
may disappear after reboot; this measured record is durable.

TCP reachability does not establish HTTP identity. Each action recreates the
owned service topology in a new namespace. Findings remain pending operator
review and do not establish live-model performance, general vulnerability
coverage or remote-service continuity. Shared host trust, R1 callback limitations,
R2 HTTP framing limitations and local-evidence tampering limits remain. Nmap,
broader topology, workflows, external targets and live planning are future work.
Publication state is recorded in [continue-here.md](continue-here.md).

## R1/R2 premerge review and authorized merges — 17 September 2026

The operator authorized review and merging of
[PR #6](https://github.com/0xsl0th/recon-cockpit/pull/6) and
[PR #7](https://github.com/0xsl0th/recon-cockpit/pull/7). Three bounded code
reviews found no concrete blockers. Fresh focused contract checks passed
**153 tests**. The implementation source was unchanged from the recorded
**1,849 portable / 78 real Linux** verification below; no new local full-suite
run was needed for these merges. Hosted CI reran the full portable suite.

| Change | Reviewed head | Merge into `main` |
| --- | --- | --- |
| PR #6 — combined offline authority | `cfde4ed16ecc07ae7e1d1d7f5d38d517b4ffc712` | `07af5130fed45e93b0921604e7a0dc6701660ab5` |
| PR #7 — owned HTTP assessment | `1312acfc5b2935b35720f6bdf7c95e4e8fd96aa1` | `f85aaa9e5deb4b9af92faac29589d015aa83c86b` |

After PR #6 merged, PR #7 was retargeted to `main` and updated to
`33edceb1862b2a001ab1a50f24e29d8ffd3c0617`. Its complete Git tree was identical
to reviewed `1312acf`; the final PR #7 merge tree was also identical to that
reviewed tree.

All ten PR #6 branch/PR checks passed. Its
[main run](https://github.com/0xsl0th/recon-cockpit/actions/runs/35183526756)
also passed. After the PR #7 update, all ten checks passed across its
[branch run](https://github.com/0xsl0th/recon-cockpit/actions/runs/35183582155)
and [PR run](https://github.com/0xsl0th/recon-cockpit/actions/runs/35183585082).
All five jobs on the resulting
[main merge run](https://github.com/0xsl0th/recon-cockpit/actions/runs/35183705044)
passed at `f85aaa9`.

The review and merges preserve the owned-fixture, offline scope and existing
approval, budget, audit and isolation boundaries. Live calls and credential
retrieval remain disabled; external/VPN testing remains deferred. The shared
trusted host process, synchronous-callback limitations and local-evidence
integrity limits still apply. These were development reviews, not an independent
security audit or new live-model validation.

## R2: owned HTTP assessment and private evidence — 16 September 2026

Historical publication checkpoint: implementation `3d20b24` on
`feature/secure-agent-http-assessment` was published in
[PR #7](https://github.com/0xsl0th/recon-cockpit/pull/7), then a draft, based on R1
`cfde4ed` in [PR #6](https://github.com/0xsl0th/recon-cockpit/pull/6), also then a
draft. The 17 September record above documents their completed merges. The fixed
two-GET workflow gates its second synthetic provider exchange on actual
discovery evidence, retains R1's execution boundaries, and produces linked
execution/observation records and reviewable JSON/Markdown reports.
See [http-assessment.md](http-assessment.md) for the contract and CLI.

Environment: Kali Linux x86_64, Python 3.14.6, pytest 9.1.1, normal host user.
Linux tests and the sample CLI ran outside the coding sandbox to exercise real
namespaces. No package installation, host network changes, live API calls,
credentials or external/VPN target were used.

| Command/check | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra --junitxml=/tmp/recon-http-assessment-portable.xml` | **1849 passed, 78 deselected**, 16.208 seconds |
| `RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short --junitxml=/tmp/recon-http-assessment-linux.xml` | **78 passed, 1849 deselected**, 151.816 seconds |
| Focused R2 portable contract/evidence/hooks/provider/CLI checks | **288 passed**, 0.93 seconds |
| Focused real Linux R2 checks | **12 passed**, 20.93 seconds |
| Executed CLI case a, explicit owned-fixture demo policy, fresh private output paths | Exit 0; two successful GETs; two broker reservations; `validated`; all seven coordinator and parser checks true |
| Read-only CLI inspection of the case-a sample | Exit 0; `validated`; no integrity issues; every bundle file unchanged |
| `.venv/bin/python -m compileall -q recon_cockpit scripts`, `.venv/bin/python -m pip check`, `git diff --check` | Passed; no broken requirements |

Both full JUnit files were parsed and contain zero failures, errors or skips.
The sample is at `.secure-agent/r2-example-a/report.md` and `report.json`,
with separate `.secure-agent/r2-example-audit.jsonl`. Its directory is 0700 and
files are 0600. It used the existing explicit unattended owned-fixture
`demo_policy()`, saved to `/tmp/recon-r2-owned-fixture-policy.json`; this is
not human approval evidence. Default CLI policy still requires fresh approval
for each exact action. Sample artifacts and temporary XML are not committed.

The 288 new portable checks exercise fixed typed contracts, strict duplicate-free
JSON, misleading content, candidate and observation binding, budgets, dry-run,
denial and CLI combinations. Evidence checks cover private file modes, exclusive
creation, symlink/hardlink/FIFO rejection, artifact/journal bounds, digest
consistency, partial/unmatched/orphan records, report mismatches, write-failure
poisoning, no resume and read-only recovery. Controller tests cover
authorization/start/launch/completion ordering and authority poisoning.

Twelve new Linux cases supplement R1's 66. Six execute exposure, absence,
malformed content, timeout, output limit and hostile discovery through real
coordinator/parser/executor boundaries. Hostile discovery launches no follow-up.
Remaining cases cover dry-run, missing/fresh/refused/replayed scripted grants,
and an artifact failure after one real execution that prevents the next plan
and launch. They check process reaping, reservations, execution-ID audit
correlation and private evidence. Scripted grants test mechanisms only.

A bounded parallel review found three recovery defects before final verification:
reports could precede durable closure, directory enumeration was unbounded
before enforcing its cap, and Python equality admitted Boolean/integer
substitutions in integrity metadata. Fixes put closure first, stop enumeration
at entry 13, and compare canonical JSON encodings. Focused regressions and both
full suites passed after the fixes. Final bounded review found no further
concrete blocker; this is development review, not an independent security audit.

These outcomes establish only seeded fixture behavior. Reports remain pending
operator review; absence applies only to the inspected endpoint. Artifacts are
decoded-result JSON, not HTTP wire captures; the probe does not validate all
HTTP framing semantics. A compromised host owner can rewrite local evidence.
Shared trusted host responsibilities and R1's synchronous-callback limitation
remain. Current publication/PR state is in [continue-here.md](continue-here.md);
hosted CI is separate evidence from these local results.

## R1: combined offline provider and authority — 15 September 2026

Implemented on `feature/secure-agent-offline-authority`, based on the operator's
pushed documentation checkpoint `54461b7` above merged main `bf3a359`.
`--control-plane-openai-offline` composes the isolated coordinator, existing
offline provider/parser/broker, host authority and independently validating
fixture executor. The architecture and bounded version-2 PLAN/PROPOSE dialogue
are documented in [offline-authority.md](offline-authority.md).

One authority-owned ID/deadline spans planning and execution. Observations come
from trusted execution records; canonical provider requests and pending plans
are checked before further work. Provider and tool reservations remain separate
and nonrefundable. No credentials, live API calls, external target, host network
change or package installation was used. Earlier CLI modes remain available.

Environment: Kali Linux x86_64, Python 3.14.6, pytest 9.1.1, normal host user.
Linux checks ran outside the coding sandbox to exercise actual namespaces.

| Command/check | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra --junitxml=/tmp/recon-offline-authority-portable.xml` | **1561 passed, 66 deselected**, 15.60 seconds |
| `RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short --junitxml=/tmp/recon-offline-authority-linux.xml` | **66 passed, 1561 deselected**, 131.27 seconds |
| Combined CLI, `three_step`, explicit synthetic model, `--dry-run` | Exit 0; `coordinator_done`; three broker calls and three dry-run decisions; zero executions; all seven coordinator and parser checks true |
| Twelve-case combined demo, dry-run and executed fixtures (included in Linux suite) | Both passed; executed mode performed **12 owned-fixture actions** across its cases, with parser/coordinator/executor evidence and audit correlation |
| `.venv/bin/python -m compileall -q recon_cockpit scripts`, `.venv/bin/python -m pip check`, `git diff --check` | Passed; no broken requirements |

Both final JUnit files were parsed and contain zero failures, errors or skips.
The CLI audit `.secure-agent/offline-authority-cli-r1.jsonl` is private (`0600`)
and records one finished session, three broker reservations and no execution.
Audit files and temporary JUnit evidence are not committed.

New portable coverage exercises exact phase/sequence/session binding, altered
plans, forged observations/configuration/approval fields, broker canonical
requests, reply bounds, quotas, stale/replayed grants, audit fault poisoning,
concurrency, cancellation/expiry and single-use/rebinding behavior. Both IPC
ceilings retain queued-extra-output/EOF/stderr regressions. Full-size dialogues
exercise the larger bounded cumulative output allowance.

Fifteen new Linux cases supplement the previous 51. They exercise the fixed
offline coordinator and inherited credential/file/descriptor/memory/TTY/socket
canaries, combined dry-run and execution, fresh/refused/replayed scripted grants,
hostile follow-ups, all 16 planning steps/32 messages, broker exhaustion, and
both waiting parser/coordinator children killed and reaped on cancellation or
expiry. The two new demo cases cover all twelve synthetic scenarios. Scripted
grants test approval mechanics; they do not represent human approval.

The first full Linux run passed 63 of 64 collected cases. The new offline
coordinator canary probe imported ctypes before the worker's inherited-descriptor
check; libffi could retain its own mounted runtime descriptor. Moving that
test-only import into the post-bootstrap probe fixed the harness. No production
boundary was relaxed. The final complete run includes that case and the two
newly added demo integrations, all passing.

Implementation review covered authority state, framing, canonical plan binding,
shared controls, audit poisoning and CLI/demo wiring. A bounded parallel review
found no actionable authority issue. This is local development verification,
not an independent security audit, live-model validation, or a guarantee against
compromised host authority/kernel. Synchronous callbacks retain the documented
late-output detection limitation. The shared host authority/UI/broker/audit/
launcher process is still trusted. Hosted CI and PR state must be checked
separately; these counts describe the local checkout.

## Control-plane privilege separation — 14 September 2026

Implemented on `feature/secure-agent-control-plane`, based on merged main
`ce16c06`. The operator approved a first slice that confines the coordinator and
defines explicit proposal/authorization/execution IPC boundaries. The new
`--control-plane-mock` path uses deterministic scenarios and owned fixtures;
live OpenAI calls, credential retrieval and routed sessions remain unavailable.
See [control-plane.md](control-plane.md) for ownership, IPC and compromise scope.

The persistent coordinator has no policy, approval, audit or execution handle.
`AuthoritySession` owns fixed session identity, mode, limits and deadline, strict
sequence checks, resource reservations and terminal approval. Fresh executors
receive separate private-pipe launch envelopes bound to the complete action,
policy, session, limits, reservations, deadline and per-launch nonce. They
independently validate these before owned-fixture setup. The host authority,
approval UI, audit sink and launcher still share a trusted process; containment
of compromise of that host process is not established by this slice.

Environment: Kali Linux, x86_64, Python `3.14.6`, pytest `9.1.1`, normal host user.
Linux integration and the CLI check ran outside the coding sandbox to create
the required namespaces. No packages were installed and no host network
configuration, real credentials, live API or remote/VPN target was used.

| Command/check | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra --junitxml=/tmp/recon-control-plane-portable.xml` | **1380 passed, 51 deselected**, 11.92 seconds |
| `RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short --junitxml=/tmp/recon-control-plane-linux.xml` | **51 passed, 1380 deselected**, 77.91 seconds |
| `.venv/bin/python -m recon_cockpit.secure_agent --control-plane-mock three_step --dry-run --audit .secure-agent/control-plane-cli-dev.jsonl` | Exit 0, `coordinator_done`, three dry-run decisions, all seven coordinator checks true, zero executions |
| `.venv/bin/python -m compileall -q recon_cockpit scripts`, `.venv/bin/python -m pip check`, `git diff --check` | Passed; no broken dependencies |

Both JUnit files were parsed and contain the expected complete case counts with
zero failures, errors or skips. The CLI audit is mode `0600`, with 14 events,
one closed session and no `execution_started` events.

The 256 new portable cases cover authority-field injection at the envelope,
plan and action levels; replay and cross-session requests; session closure and
no budget refunds; exact-action approval binding; audit failures; deadline and
cancellation checks; malformed/pipelined/truncated/flooded IPC; and launch
nonce/context/schema/policy/limit validation. A concurrency regression verifies
that poisoning the channel cancels an action already waiting for approval.

All 40 existing Linux integrations passed alongside 11 new cases:

- Seven coordinator cases exercise a persistent three-step process, actual
  host-file/environment/descriptor canaries, absent host process memory,
  `EPERM` from tracing and cross-process memory syscalls, absent terminal,
  denied IPv4/IPv6/Unix sockets, memory bounds, malformed dialogue, and killed
  and reaped workers on cancellation, deadline and output flooding.
- One executor case exercises a real independently validated fixture launch.
- Three combined cases run the nine-case dry-run adversarial demo, the
  eleven-case executed-fixture demo, and fresh host approval grants across
  three actions. The executed demo records nine successful owned actions and
  rejects forged authority, replay, wrong-session messages and malicious
  follow-up scope/approval fields. The approval-required unattended case
  launches nothing. Scripted grant callbacks test mechanics, not human consent.

The first coordinator Linux run exposed an overly late inherited-descriptor
check: trusted ctypes/libffi startup had opened a read-only runtime library
descriptor. The check now runs before loading that bootstrap; the runtime can
subsequently open its own mounted library files. The corrected seven-case
kernel run and final complete suite passed. Review also added a final executor
deadline/cancellation check after result parsing, with deterministic regressions,
and checks before fixture creation after privilege setup.

Implementation and bounded parallel reviews covered authority poisoning,
coordinator framing/bootstrap, executor binding and deadline handling. These
checks establish the documented local boundaries and fixture behavior, not an
independent security audit or resistance to host/kernel compromise. Hosted CI
and PR state are recorded separately from this local evidence.

### Premerge protocol review correction

Review of PR #5 found that a complete REQUEST ending exactly at the supervisor's
8,192-byte read boundary could be dispatched before an already-queued second
frame was noticed. A reproduction through `AuthoritySession` executed one
otherwise permitted fake-backend action and then failed the protocol. Policy,
approval and budget checks still applied, but queued protocol errors were not
consistently rejected before dispatch.

The supervisor now checks for already-buffered extra coordinator output or EOF
immediately before calling the authority. Three regressions cover an extra
request, EOF and excessive queued stderr at the read boundary, each requiring
zero authority calls. The protocol remains incremental: data that arrives after
the pre-dispatch check may be detected only after the authority call returns.
Protocol failure cannot undo an action already executed. The documentation
makes that limit explicit.

### Restart recovery verification — 15 September 2026

The saved premerge correction was recovered on
`feature/secure-agent-control-plane` above `d6aec71`. A second review found no
additional authority/executor issue and added the queued-stderr regression.
That regression fails against the original supervisor with one authority call
and passes with the correction. The full suites were rerun after the restart
with all three boundary regressions present:

| Command/check | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra --junitxml=/tmp/recon-control-plane-recovered-portable.xml` | **1383 passed, 51 deselected**, 12.19 seconds |
| `RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short --junitxml=/tmp/recon-control-plane-recovered-linux.xml` | **51 passed, 1383 deselected**, 76.27 seconds |
| `.venv/bin/python -m compileall -q recon_cockpit scripts`, `.venv/bin/python -m pip check`, `git diff --check` | Passed; no broken dependencies |

Both JUnit files were parsed: 1,383 portable and 51 integration cases, with
zero failures, errors or skips. Linux verification ran as the normal user
outside the coding sandbox. The suites used owned fixtures and synthetic
provider data. No host networking change, credential lookup, live API call or
VPN-target test was performed. Hosted checks and the merge state are available
on [PR #5](https://github.com/0xsl0th/recon-cockpit/pull/5).

## Offline OpenAI broker — 13 September 2026

Implemented on `feature/secure-agent-offline-broker`, based on tested `3e96e67`
from [PR #3](https://github.com/0xsl0th/recon-cockpit/pull/3). The operator approved
an offline broker/session integration and subsequently requested work on the
open PRs. Live API calls and credential retrieval remain unavailable.

The fixed Linux parser now builds one canonical request and parses one synthetic
Responses envelope over bounded typed frames. The trusted broker compares that
request with its own reconstruction, reserves full call/output-token/request-byte
allowances, requires durable audit before transport handoff and never refunds
from untrusted usage metadata. No retries, endpoint overrides or live transport
exist. The session continues to enforce policy and fresh approval on every
action. See [offline-openai-broker.md](offline-openai-broker.md).

Actual environment: Kali Linux `6.16.8+kali-amd64`, x86_64, Python `3.14.6`,
pytest `9.1.1`, normal host user. Integration tests and the standalone demo ran
outside the coding sandbox to create the required namespaces. No packages were
installed, no host routes/firewall/sysctls changed, and no API or remote/VPN
requests were sent. Synthetic credential canaries in tests are not real keys.

| Command/check | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra --junitxml=/tmp/recon-offline-broker-portable.xml` | **1123 passed, 40 deselected**, 9.67 seconds; no skips |
| `RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short --junitxml=/tmp/recon-offline-broker-linux.xml` | **40 passed, 1123 deselected**, 59.64 seconds; no skips |
| `.venv/bin/python scripts/secure_agent_openai_demo.py --execute-fixtures --audit .secure-agent/openai-broker-dev.jsonl` | **`demo: passed`**, all nine cases, nine successful owned-fixture executions, exit 0 |
| `.venv/bin/python -m compileall -q recon_cockpit scripts`, dependency consistency and whitespace checks | Passed |

JUnit files were checked for complete case counts with no failures, errors or
skips. The 12 new Linux integrations cover full offline demos with dry-run and
executed tools, fresh/refused/replayed approval mechanics, isolated request
construction and response rejection, absent host canaries/descriptors/controller
modules, denied IPv4/IPv6/Unix sockets, and hostile codec floods/cancellation/
deadlines with reaped workers. All 28 earlier integrations also passed.

| Standalone demo case | Verified outcome |
| --- | --- |
| Three-step session | Three successful owned actions, three exchanges, `planner_done` |
| Hostile target | One owned action, second proposal policy-denied with `target_out_of_scope` |
| Forged approval field | One owned action, second response rejected by isolated parsing |
| Refusal / malformed / incomplete response | One reserved exchange each, zero actions, no retry |
| Call / output-token budget | Two actions each, third exchange refused, no refund |
| Delayed synthetic response | One reserved exchange, session deadline, zero actions |

Every successful parser output carried all seven expected boundary booleans;
every successful fixture worker carried all four existing tool boundary checks.
The standalone audit recorded nine closed sessions and nine matched tool
start/completion pairs, with no approval grants or raw request/response bodies.
The demo's explicit unattended policy does not establish human approval. The
scripted approval tests exercise grant mechanics only.

Some parallel tasks stopped at usage limits after saving code/tests. All saved
work was included in the final suites. Follow-up parallel reviews were interrupted
before completion; the parent reviewed the broker, framing, worker, adapter,
session/CLI wiring and documentation directly. This is implementation review,
not an independent security audit. The typed offline transport's TLS flag is a
contract check, not evidence of a verified TLS connection. Output tokens and
request bytes are reservations, not input-token counts or monetary spending.
Hosted CI and PR reviews are tracked separately from this local evidence.

### Hosted cleanup correction and dependent PR maintenance

The first broker [branch run](https://github.com/0xsl0th/recon-cockpit/actions/runs/34776278316)
and [PR run](https://github.com/0xsl0th/recon-cockpit/actions/runs/34776309922)
failed five malformed/truncated-frame tests on macOS 15 / Python 3.14.7.
The supervisor correctly rejected the protocol, but cleanup's short-circuited
`failed or proc.poll()` skipped reaping an exited leader before signalling its
group. Darwin returned `EPERM`, masking the intended protocol error.

Cleanup now polls/reaps first and still sends SIGKILL to the group on failure,
including when a reaped parent's live descendant holds an output pipe. No
permission error is suppressed. A portable OS-behavior regression covers the
unreaped-zombie case, alongside the real descendant/pipe cleanup tests.

After correction, the complete portable suite passed **1124 tests, 40
deselected**, in **9.23 seconds**, with no skips, recorded in
`/tmp/recon-offline-broker-portable-fixed.xml`. All **12 affected OpenAI Linux
integrations** passed again, **56 deselected**, in **27.23 seconds**, recorded in
`/tmp/recon-offline-broker-linux-fixed.xml`. The 28 earlier integration results
above apply to unchanged implementations.

The earlier test-only macOS cleanup fix was also backported to PR #2 as
`fc99758`. Its own checkout passed **609 portable tests, 22 deselected**, in
**5.32 seconds**, without skips. Its
[branch](https://github.com/0xsl0th/recon-cockpit/actions/runs/34776381633) and
[PR](https://github.com/0xsl0th/recon-cockpit/actions/runs/34776384232) CI passed.
PR #3 incorporated that ancestry as `46bdc77` with no tree changes; its
[branch](https://github.com/0xsl0th/recon-cockpit/actions/runs/34776471889) and
[PR](https://github.com/0xsl0th/recon-cockpit/actions/runs/34776473843) CI also passed.
The broker branch incorporates the same ancestry. No PR has been merged into
`main`; dependency order remains #2 → #3 → #4.

After the usage reset, bounded read-only parallel reviews completed: PR #2 at
`fc99758` (session/controller/approval/audit/deadline/cleanup), PR #3 at `46bdc77`
(planner bootstrap/isolation/codec/runtime handoff), and the final broker IPC
cleanup/provider/CLI integration. No concrete new findings were reported.
These are implementation reviews and do not constitute an independent security
audit or approval of live API use.

## Isolated planner and offline OpenAI codec — 12 September 2026

Continued milestone 2 on `feature/secure-agent-provider-isolation`, based on
`467fab0` from [PR #2](https://github.com/0xsl0th/recon-cockpit/pull/2). All five
portable matrix jobs passed for that PR and its branch; PR #2 was marked ready
for review and remains unmerged. The follow-up is kept on a separate branch.
The operator selected OpenAI API as the first real-model direction, with live
calls explicitly disabled initially.

Implemented a dedicated Linux planner boundary with zero capabilities, private
namespaces, read-only fixed runtime, a 1 MiB private temporary filesystem and
seccomp restrictions installed before reading observations or importing the
planner. The bootstrap verifies namespace/capability state and attempts prohibited
socket, fork, unshare and root-write operations. The existing session loop still
validates and authorizes all output proposals. Runtime discovery can now omit
nftables for planner-only execution; the fixture/routed callers retain their
existing runtime closure.

Added an offline OpenAI Responses codec with an explicit operator model/token
configuration, fixed request shape/destination, Structured Outputs and bounded
strict decoding. It has no network transport, credential lookup, SDK dependency
or live-call flag. Synthetic response tests cover invalid/missing output,
refusals, incomplete status, tool calls, ambiguous messages, forged authority,
output/JSON limits and out-of-scope proposals rejected by the session controller.
See [provider-isolation.md](provider-isolation.md) for the contract and the broker
work required before live integration.

Actual local environment: Kali Linux `6.16.8+kali-amd64`, x86_64,
Python `3.14.6`, pytest `9.1.1`, normal host user. No packages were installed.
Kernel tests and demos ran outside the coding sandbox to create namespaces;
there were no host routing, firewall or sysctl changes, real model calls or
remote/VPN probes.

| Command/check | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra --junitxml=/tmp/recon-provider-portable.xml` | **892 passed, 28 deselected**, 5.95 seconds; no skips |
| `RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short` | **28 passed, 892 deselected**, 32.02 seconds; no skips |
| `.venv/bin/python scripts/secure_agent_planner_demo.py --audit .secure-agent/planner-boundary-dev.jsonl` | **`demo: passed`**, three isolated planning steps, zero tool executions, exit 0 |
| `.venv/bin/python scripts/secure_agent_planner_demo.py --execute-fixtures --audit .secure-agent/planner-fixture-m2.jsonl` | **`demo: passed`**, three scenarios, seven planner invocations and five successful owned-fixture executions, exit 0 |
| `.venv/bin/python -m pip check` | No broken requirements |
| `.venv/bin/python -m compileall -q recon_cockpit scripts` and `git diff --check` | Passed |

The six new opted-in integrations demonstrate a real three-step isolated
planner dry-run, combined isolated planning/tool execution, host canary denial,
and hostile-planner cancellation/deadline/output flooding. The owned host file
remained intact; fake credential environment values, an explicitly inheritable
descriptor and the host process's `/proc/<pid>/root` path were inaccessible.
Direct IPv4/IPv6/Unix socket attempts returned `EPERM`. Hostile planner processes
were killed with SIGKILL and already reaped when calls returned. These tests
substitute fixed trusted test files through internal mount construction; they do
not add a public arbitrary-plugin interface.

Every successful planner invocation in the standalone demos reported all seven
expected boundary checks as true. Every successful HTTP worker also reported
all four existing fixture boundary checks true. Both injection scenarios reached
the first owned response, then stopped the next proposal at policy or schema
validation. The demo's JSON report prints these safe booleans; the private audit
records session and action events. Neither is cryptographic attestation. The
demonstration uses its explicit fixture-only unattended allow policy and issues
no human approvals.

Some parallel tasks stopped at a usage limit after saving their files. Work was
resumed, all saved tests were run in the complete suites above, and the final
read-only adapter/worker/codec/CLI review completed. No concrete new security or
correctness bug was found. A documented compatibility caveat remains: the API
schema's length/range keywords are unsupported for fine-tuned models, so selecting
a syntactically valid model ID does not establish support. This implementation
review is not an independent security audit, and offline protocol tests do not
validate real model behavior or account access.

The workflow now runs pushes to this follow-up branch and PRs targeting
`feature/secure-agent-m2`, permitting review of the added slice independently in
[draft PR #3](https://github.com/0xsl0th/recon-cockpit/pull/3). Hosted results remain
separate from the local evidence above. Real API transport, credential mediation,
broker IPC/budgets and live model evaluation remain pending; live calls remain
disabled.

### Hosted CI cleanup correction

For implementation commit `f5b17d3`, the
[PR workflow](https://github.com/0xsl0th/recon-cockpit/actions/runs/34713295830)
passed all five jobs. The separate
[push workflow](https://github.com/0xsl0th/recon-cockpit/actions/runs/34713286291)
failed on macOS 15 / Python 3.14.7: **891 passed, 1 failed, 28 deselected**.
The existing cancellation test verified the expected cancellation, reaped direct
child and EOF from its descendant, then its redundant final cleanup signal
raised `PermissionError` for the already-cleaned process group.

The test now attempts fallback group cleanup only if EOF has not yet verified
success; every original cancellation/descendant assertion remains. Duplicate
pipe readers close even if fallback cleanup raises. A raw bytes literal also
removes an invalid-escape warning while preserving the malformed JSON surrogate
fixture. These are test-only changes, reviewed without a new finding.

After this correction,
`.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra --junitxml=/tmp/recon-provider-ci-fix-portable.xml`
passed **892 tests, 28 deselected**, in **6.18 seconds**, with no skips. Production
code was unchanged, so the Linux integration and demo evidence above still
applies. Hosted reruns are recorded in the PR checks.

## Bounded mock sessions — 11 September 2026

Recovered the interrupted milestone 2 worktree on `feature/secure-agent-m2`,
based on merged `main` revision `8d7fe69`. The recovered files already contained
the session runner, fixed subprocess planner, shared execution control and
backend/CLI wiring. The initial portable run passed **503 tests, 14 deselected**;
session lifecycle, CLI and real-kernel session coverage and the demo were still
missing. Completed that first implementation slice without replacing the
existing architecture or widening the execution target scope.

The session now has immutable attempt/runtime/output limits, a monotonic deadline
covering planner execution, terminal approval waiting, runtime inspection and
tool supervision, and SIGINT/SIGTERM cancellation. Each accepted action reserves
its full response allowance without refunds. Every follow-up traverses schema,
policy, required fresh approval and durable audit. Session/step events correlate
with controller events; CLI progress and final summary exclude raw feedback.
See [bounded-sessions.md](bounded-sessions.md) for the exact contract.

Actual local environment remained Kali Linux `6.16.8+kali-amd64`, x86_64,
Python `3.14.6`, pytest `9.1.1`, running as the normal host user. Kernel tests and
the demo ran outside the coding sandbox to permit the required namespaces.

| Command/check | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra --junitxml=/tmp/recon-m2-portable.xml` | **609 passed, 22 deselected**, 5.58 seconds; no skips |
| `RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short` | **22 passed, 523 deselected**, 21.78 seconds; no skips; run before the final 86 portable session cases were added |
| `.venv/bin/python scripts/secure_agent_session_demo.py --audit .secure-agent/session-demo-m2-resumed.jsonl` | **`demo: passed`**, six verified cases, exit 0 |
| `.venv/bin/python -m pip check` | No broken requirements |
| `.venv/bin/python -m compileall -q recon_cockpit scripts` and `git diff --check` | Passed |

The standalone demo performed nine successful isolated HTTP executions across
six sessions. Every completed worker returned true `forbidden_ip_blocked`,
`forbidden_port_blocked`, `namespace_creation_blocked` and `capabilities_dropped`
checks. It checked the injection fixture internally and retained only safe
receipt booleans and boundary evidence in its public report.

| Demo case | Observed result |
| --- | --- |
| Three-step plan | Three successes at `/`, `/injection`, `/`; 3072 bytes reserved; `planner_done` |
| Injected target | First fixture response received; second action rejected with `target_out_of_scope`; one execution |
| Injected approval authority | First fixture response received; second action rejected with `unknown_action_fields`; one execution |
| Endless planner with two-step limit | Exactly two executions; `step_limit` |
| 1024-byte session output budget | One execution; second action refused with `session_output_limit`; no second approval or launch |
| Cancellation after first step | Exactly one execution; `session_cancelled`; no next planner invocation |

The eight new Linux integration cases cover those six scenarios plus timeout
and cancellation of an actual running Bubblewrap worker against `/slow`. Both
in-flight stops observed SIGKILL termination and verified the direct child was
already reaped. All 14 earlier fixture/routed integration tests also passed.
Portable process tests additionally cover blocked input, flooded output, runtime
inspection, routed release gates and a descendant retaining output pipes after
its direct parent exits. Session tests cover strict proposal wrappers, fresh
approval/replay rejection, durable audit at launch, audit-failure poisoning,
stops during approval and pre-launch logging, no-refund reservations, concurrency
and single-use lifecycle. CLI tests cover signal-handler restoration, safe
progress, option validation and bounded controlling-terminal reads.

A completed parallel code review found no concrete new authorization or cleanup
bug in the session/provider/controller or execution supervisor changes. This is
an implementation review, not an independent security audit. The unattended
demo explicitly declares a fixture-only allow policy and never manufactures a
human approval. Scripted PTY tests validate terminal mechanics only; the prior
milestone's human approvals remain historical evidence and no new human session
approval ceremony is claimed here.

No packages were installed and no host network configuration was changed. Real
models, arbitrary provider plugins, routed sessions and actual VPN targets remain
unvalidated and outside this slice. Host filesystem/kernel stalls cannot be
hard-preempted; cleanup can extend beyond the deadline. Session budgets are not
persistent per-user quotas across restarts. The portable workflow now includes
pushes to `feature/secure-agent-m2`; hosted results and maintainer review remain
separate from this local run record.

## PR preparation and portable CI — 11 September 2026

Continued `feature/secure-agent-m1` from `6f4adb6`, preserving the clean worktree
and all existing execution controls. Added `.github/workflows/portable-tests.yml`
and documented its scope in the README. The workflow uses standard GitHub-hosted
Ubuntu 24.04 runners with Python 3.11, 3.12, 3.13 and 3.14, plus macOS 15 with
Python 3.14. It runs on pull requests into `main` and pushes to `main` or this
feature branch. It has a ten-minute job timeout, read-only `contents` permission,
immutable official action revisions, no persisted checkout credentials, no
repository secrets or artifact uploads, and no privileged or self-hosted jobs.
Action pins were resolved from the official checkout v7.0.1 and setup-python
v7.0.0 release tags, and their definitions were inspected before use.

The selected suite excludes integration tests explicitly. A JUnit check rejects
empty runs and skipped, failed or errored portable tests, including unavailable
PTY mechanics on the selected POSIX runners. CI never supplies a human execution
grant or runs a real probe. Hosted matrix results are tracked separately in PR
checks; the following results were observed locally on the existing Kali amd64
host with Python 3.14.6:

| Command/check | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra --junitxml=<temporary-report>` | **426 passed, 14 deselected**, 1.97 seconds; no skips |
| Exact workflow JUnit-check code against that report | **426 complete tests**; synthetic empty/skipped/failed/errored reports all rejected |
| `RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short` outside the coding sandbox as the normal user | **14 passed, 426 deselected**, 11.99 seconds; no skips |
| `.venv/bin/python -m pip check` | No broken requirements |
| Workflow YAML parsing, permission/action-pin/matrix assertions and embedded Python compilation | Passed |
| `.venv/bin/python -m compileall -q recon_cockpit scripts` / `git diff --check` | Passed |

The integration rerun used only the disconnected owned lab and fixture. It did
not alter host networking, contact a real remote/VPN target, or repeat the human
approval ceremony. The separately recorded operator approvals below remain the
human evidence; CI and scripted PTY tests do not replace them.

A targeted local static review traced strict proposal parsing, policy checks,
full-digest single-use grants, audit-before-launch and audit-failure poisoning,
minimal namespace/runtime mounts, worker destination rules, bootstrap gates and
bounded process cleanup. No merge-blocking issue was identified in that review;
no runtime change was made during PR preparation. Attempts at parallel agent
reviews stopped at a usage limit and are not counted as completed reviews. This
is not an independent security audit or a guarantee against sandbox escapes.
Maintainer review and passing PR checks remain merge requirements; no merge,
auto-merge or branch-protection change is part of this preparation.

### First hosted CI failure and test-only correction

The [first hosted run](https://github.com/0xsl0th/recon-cockpit/actions/runs/34547888828)
at `2c17192` installed successfully but failed the routed worker mount-order unit
test. That test mocked `routed._trusted_program`, while the reused fixture
command builder actually resolves Bubblewrap through `isolation._trusted_program`.
The installed Kali `bwrap` masked the incomplete test double; clean Ubuntu and
macOS runners exposed it. This was not a real isolation execution failure.

The test now replaces discovery where the command builder uses it and rejects
any unintended host executable lookup. All original read-only mount ordering,
namespace and environment assertions remain. An additional portable regression
checks that the unmodified production command builder still refuses missing
Bubblewrap. No runtime fallback, runner package installation, test skipping or
isolation relaxation was added. The corrected local portable run passed
**427 tests, 14 deselected**, in 1.80 seconds, with no skips. Hosted results for
the corrected revision are recorded separately by its CI checks.

Workflow references: [GitHub's Python test guidance](https://docs.github.com/en/actions/tutorials/build-and-test-code/python)
and [secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use).

## Routed HTTP milestone — 10 September 2026

Continued clean branch `feature/secure-agent-m1` from `915d822` on the same Kali
amd64 host. Added a separate `--routed` backend for one authorized IPv4 literal and
TCP port, retaining the fixture backend and controller approval/audit path.
Design, runtime boundaries, examples and prerequisites are in
[routed-http.md](routed-http.md).

Package setup was performed by the operator in a desktop terminal:
`sudo apt-get install --no-install-recommends slirp4netns`. APT installed only
`slirp4netns 1.3.3-1` and `libslirp0 4.9.3-1`; no upgrades or removals were part of
the request. Existing util-linux is `2.41.3-4`; `/dev/net/tun` was already present.
All application/tests ran as host user `sloth` (UID 1000), outside the coding
agent's outer sandbox for kernel execution. No host firewall, route, forwarding,
NAT, interface or sysctl changes were made. The demo's address configuration is
confined to its disconnected outer lab namespace.

### Actual checks

| Command/check | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest -m 'not integration'` | **426 passed, 14 deselected**, 1.90 seconds |
| `RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short` | **14 passed, 426 deselected**, 12.13 seconds |
| `.venv/bin/python scripts/secure_agent_routed_demo.py --audit .secure-agent/routed-demo-final.jsonl` | **`demo: passed`**, exit 0 |
| `.venv/bin/python scripts/secure_agent_routed_demo.py --interactive --audit .secure-agent/routed-human-1.jsonl` | Operator-entered approval; **HTTP 200, 96 bytes, exit 0** |
| `.venv/bin/python -m recon_cockpit.secure_agent --routed --policy examples/secure-agent-routed-policy.json --proposal examples/secure-agent-routed-action.json --dry-run` | `approval_required`, `dry_run`, exit 0; imported example JSON, no network request |
| `.venv/bin/python -m compileall -q recon_cockpit/secure_agent scripts` | Passed |
| `git diff --check` | Passed |

There were **no skipped tests** in these selected runs. The 66 new portable cases
cover routed target/request restrictions, fixed destination firewall generation,
separate bootstrap gates, minimal mount configuration, bounded multi-process
supervision/cleanup and lab setup refusal. Portable process helpers test control
mechanics, not kernel routing. The 14 integration tests comprise the five
original fixture cases and nine routed assertions over a shared real lab run.
That routed run performs ten real executions: three authorized witness baselines
plus the seven cases below.

| Routed case | Status | HTTP | Retained bytes |
| --- | --- | --- | --- |
| GET `/` | `succeeded` | 200 | 96 |
| HEAD `/` | `succeeded` | 200 | 61 |
| `/injection` | `succeeded`, inert content | 200 | 290 |
| `/redirect-ip` | `succeeded`, not followed | 302 | 127 |
| `/redirect-port` | `succeeded`, not followed | 302 | 127 |
| `/large` | `output_limit`, truncated | 200 | 4096 |
| `/slow` | `timeout` | none | 0 |

Each case reported all four checks as boolean true: forbidden IP blocked,
forbidden port blocked, namespace creation blocked and capabilities dropped.
Baseline actions first obtained HTTP 200 from the allowed service
`192.0.2.10:8080`, the IP witness `192.0.2.11:8080` and the port witness
`192.0.2.10:8081`, each under its own exact allow policy. Restricted cases then
attempted direct sockets to the two forbidden witnesses inside the worker's
filtered network namespace. Both witnesses accepted **zero additional
connections**, including during redirects. Services were outside the execution
namespace and unreachable from the host/LAN. The outer lab controller ran as
UID 1000 with all capability sets zero.

The demo also rejected two out-of-scope policy actions and blocked noninteractive
execution under an approval-required policy. The final audit has 34 events,
exactly ten execution starts and ten completions, and zero consumed human grants.
No raw malicious response text appeared in the audit.

### Human approval evidence

The operator entered the newly displayed challenge directly in the routed lab's
desktop terminal and confirmed exit 0. No agent supplied approval input. Private
`.secure-agent/routed-human-1.jsonl` contains five events with exactly one
`approval_consumed`, one `execution_started` and one `execution_finished`, in
order and sharing the full action/policy digests and non-null approval reference.
The successful completion is timestamped `2026-09-10T18:15:19.269739+00:00` and
records backend `linux-bubblewrap-slirp-v1`, HTTP 200 and 96 bytes. The policy
decision remains `approval_required`; the single consumed grant satisfies it.

Audit files are mode `0600` in ignored `.secure-agent/` (mode `0700`). They and
private setup diagnostics are excluded from the commit. Failed prototype attempts
remain separate from the fresh final demo/human evidence files.

### Failures resolved during implementation

- Direct script invocation initially failed to import its sibling demo helper.
  The script now supports both direct invocation and package import by tests.
- The first worker launch tried to create its routed-script mount after the root
  filesystem became read-only. The new mount now precedes the read-only remounts;
  a regression checks the order. The read-only boundary remains in place.
- Bubblewrap could not bind-mount the nsfs descriptor as an ordinary file path.
  The controller now passes a pinned network namespace descriptor directly to the
  transport via `/proc/self/fd/N`, alongside a separate user-namespace descriptor
  consumed by Bubblewrap. No host directory mount or mutable namespace path was
  added. The worker never receives these descriptors.
- Reusing a diagnostic audit file intentionally failed the demo's fresh-run event
  count check. Final verification uses fresh files. Portable supervised-process
  tests confirm bad/empty readiness messages prevent probe release, and early
  exits or capture/deadline failures reap both process trees. Traffic already
  sent before a later failure cannot be undone; it remains subject to the
  preinstalled destination filter and recorded execution-start event.

This establishes the routed path and kernel destination boundary in the owned
lab, plus the existing fixture behavior. It does **not** establish reachability
of a real remote/VPN target or any real-model/autonomy behavior. External scope
must be supplied explicitly by the operator. TLS, Nmap, CIDR/multi-target
execution and real providers remain future work. The slirp transport is an
additional trusted network component; its compromise is outside the contract.

## Lenovo / Kali amd64 — 10 September 2026

Continued the clean `feature/secure-agent-m1` checkout at `d22e630`; fetched
`origin` without resetting existing work. Host commands ran as `sloth`, UID 1000,
without sudo. No host firewall, route, forwarding, NAT or sysctl changes were
needed. No system packages needed installation or upgrade.

| Environment | Observed value |
| --- | --- |
| `uname -srm` | `Linux 6.16.8+kali-amd64 x86_64` |
| `dpkg --print-architecture` | `amd64` |
| `/etc/os-release` | Kali GNU/Linux Rolling, `2025.4`, `kali-rolling` |
| `/usr/bin/python3 --version` / fresh `.venv` | Python 3.14.6 |
| `bwrap --version` | bubblewrap 0.11.2 (package `0.11.2-2`) |
| `nft --version` | nftables 1.1.5 (package `1.1.5-2`) |
| `libseccomp2` | `2.6.0-2+b1`, both amd64 and i386 installed |
| `libc-bin` | `2.42-13` |
| `/usr/bin/bwrap` permissions | root-owned, mode `0755`, non-setuid |
| Python test dependencies | pytest 9.1.1, pluggy 1.6.0, Rich 14.3.4 |

Setup used `python3 -m venv .venv`, then
`.venv/bin/python -m pip install -e '.[test]'`.
`.venv/bin/python -m pip check` reported no broken requirements. The initial
installation attempt could not resolve the package index inside the coding
agent's outer sandbox; the approved host retry succeeded. That outer sandbox
also restricted `.git` writes and netlink access. The opted-in kernel tests and
demo ran outside it as the normal host user, retaining the application's own
Bubblewrap, namespace, nftables, capability, seccomp and resource restrictions.

### Failures found and fixes

1. The original portable run matched the handoff: **335 passed, 5 deselected**.
   The first opted-in integration attempt returned **5 failed, 335 deselected**,
   with `isolation_unavailable`. Runtime discovery selected the first globbed
   `libseccomp.so.2`, which was the installed i386 library; `ldd` failed before
   any fixture execution. Discovery now queries the fixed distribution Python's
   `MULTIARCH`, validates it, and selects its native library directory. Actual
   runtime discovery resolves 46 explicit files, including amd64 libseccomp.
   Seven portable regressions cover native selection, foreign-only installs,
   invalid runtime metadata and missing transitive dependencies. The runtime
   expects Debian/Kali `/lib/<MULTIARCH>` or `/usr/lib/<MULTIARCH>` layout; other
   layouts fail closed.
2. The first real terminal CLI attempt blocked with `approval_missing` before
   presenting a challenge. Opening `/dev/tty` with buffered text `r+` raises
   `io.UnsupportedOperation: File or stream is not seekable` on this host.
   The CLI now uses separate read and write handles to the controlling terminal.
   It retains exact-challenge, default-deny, full-digest-bound approval and does
   not fall back to stdin. The failed attempt has no execution-start event.
   Nine scripted pseudo-terminal regressions cover actual nonseekable streams,
   exact challenge and single use, blank/incorrect/full-digest input, missing
   terminal and noninteractive rejection; they do not exercise a human approval.
   A mismatch now prints a safe explanation that the challenge uses the displayed
   16-character digest prefix, without printing the entered text.
3. Integration and demo checks previously used `all(checks.values())`, allowing
   empty or incomplete evidence to pass. They now require exactly the four
   expected keys, each the boolean `True`. Nine portable cases exercise this
   evidence validation, including missing, false and nonboolean values.

### Commands and observed outcomes

All commands below run from the checkout. Integration results refer to actual
kernel execution, not test doubles. Final test totals include 25 new portable
regressions (seven runtime, nine evidence-validation and nine terminal cases).

| Check | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest -m 'not integration'` (final) | **360 passed, 5 deselected**, 1.37 seconds |
| `RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short` (final) | **5 passed, 360 deselected**, 4.55 seconds |
| `.venv/bin/python -m recon_cockpit.secure_agent --mock --dry-run` | `approval_required`, `dry_run`, deterministic mock; exit 0 |
| `.venv/bin/python -m recon_cockpit.secure_agent --mock --fixture --execute --audit .secure-agent/kali-noninteractive.jsonl` without TTY | `noninteractive_approval_required`, blocked; exit 2, no execution |
| `.venv/bin/python scripts/secure_agent_linux_demo.py --audit .secure-agent/kali-demo.jsonl` | `demo: passed`; exit 0 |
| `.venv/bin/python scripts/secure_agent_linux_demo.py --audit .secure-agent/kali-demo-final.jsonl` (after strict evidence checks) | `demo: passed`; exit 0 |
| `.venv/bin/python -m recon_cockpit.secure_agent --mock --fixture --execute --audit .secure-agent/kali-human-approval.jsonl` in a human desktop terminal | Operator entered the displayed challenge; one approved execution succeeded, HTTP 200, 100 bytes |
| `.venv/bin/python -m compileall -q recon_cockpit/secure_agent scripts` | Passed |
| `git diff --check` | Passed |

Final demo case results:

| Fixture path | Execution status | HTTP status | Captured bytes |
| --- | --- | --- | --- |
| `/` | `succeeded` | 200 | 100 |
| `/injection` | `succeeded` | 200 | 292 |
| `/redirect` | `succeeded` | 302, not followed | 141 |
| `/large` | `output_limit`, truncated | 200 | 1024 |
| `/slow` | `timeout` | none | 0 |

Every case reported `forbidden_ip_blocked`, `forbidden_port_blocked`,
`namespace_creation_blocked` and `capabilities_dropped` as true. Forbidden
connections used direct sockets toward listening owned witnesses at
`127.0.0.2:8080` and `127.0.0.1:8081` inside the same namespace. The malicious
response remained inert; policy did not change. The demo also rejected an
out-of-scope target, unsupported shell tool and unknown parameters, and blocked
unattended execution under an approval-required policy.

### Human approval and private evidence

Human-terminal command:

```bash
.venv/bin/python -m recon_cockpit.secure_agent --mock --fixture --execute \
  --audit .secure-agent/kali-human-approval.jsonl
```

The first attempt hit the terminal-open defect described above. The second,
using the corrected I/O, recorded `approval_missing`: the operator entered the
full 64-character action digest instead of the displayed 16-character challenge
prefix. Both failed attempts consumed no grant and started no execution.

On the third attempt, the operator entered the displayed challenge in the
desktop terminal. The agent did not supply terminal input. At
`2026-09-10T00:56:55.830722+00:00`, the audit recorded `execution_finished` with
`execution_status: succeeded`, HTTP 200 and 100 bytes received. Its 11 total
events include exactly one `approval_consumed`, one `execution_started` and one
`execution_finished`, in that order. All three share the full action digest,
policy digest and non-null approval reference. The decision remains
`approval_required`, as designed; the consumed grant satisfies it. There are no
unmatched execution starts in this file.

Evidence stays in ignored `.secure-agent/` (mode `0700`); JSONL files have mode
`0600`. Raw audit logs, approval references and response bodies are not committed.
The unattended demo uses its explicit fixture-only automatic policy and is not
human approval evidence. Pseudo-terminal regression inputs likewise test only
approval mechanics, not a human decision.
The final demo audit contains 20 events, five execution-start events and five
matching completion events, with zero human approvals consumed.

### Remaining limits

This validates the owned singleton-loopback fixture on this Kali host. It does
not establish routed authorized-target execution, arbitrary CIDR execution,
real-model autonomy or universal prompt-injection resistance. Routed target
support is the next development milestone; TLS, Nmap, real providers and
PivotTrail integration remain future work. The controls and residual risks in
[the architecture](architecture.md) and [threat model](threat-model.md) still
apply. No Docker-based isolation test was run.

## Mac handoff — 9 September 2026

Environment: macOS/Darwin arm64, local Python 3.11 virtual environment.
Branch: `feature/secure-agent-m1`.

Actually executed:

| Check | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest` | **335 passed, 5 skipped** |
| `.venv/bin/python -m recon_cockpit.secure_agent --mock --dry-run` | `approval_required`, `dry_run`, explicitly labeled deterministic mock |
| `.venv/bin/python -m recon_cockpit.secure_agent --mock --fixture --execute` without TTY | Blocked: `noninteractive_approval_required` |
| `.venv/bin/python scripts/secure_agent_linux_demo.py` | Blocked: `isolation_unavailable`, Linux required |
| `.venv/bin/python -m compileall -q recon_cockpit/secure_agent scripts` | Passed |
| `git diff --check` | Passed |

The passing tests comprise 149 existing workflow tests, 104 strict-model/policy
tests, 57 controller/approval/audit/CLI tests, and 25 portable worker/backend tests.
Portable backend tests use controlled subprocesses or test doubles and do not
establish namespace or firewall enforcement.

The **five real Linux integration cases were skipped**, not passed. They cover
normal HTTP, malicious fixture output, output limits, deadlines, and redirects;
each also attempts direct sockets to listening forbidden IP/port witnesses.
No amd64 Linux, Kali, real kernel firewall, capability-drop, or seccomp success
has been established in this session. No Docker-based isolation test was run.

## Original Kali amd64 follow-up plan (superseded by the record above)

Follow [the handover](handover-kali.md). Record `uname -m`, kernel/distribution,
Python, Bubblewrap and nftables versions, exact commands, test totals, failures
and any fixes. Do not replace a failed isolation check with a mock, an execution
fallback, root execution, broad mounts, or disabled enforcement. Repeat affected
tests after fixing implementation defects, then update this record with actual
evidence. Keep portable and integration results distinguishable.

After all integration cases pass, exercise the human approval CLI in a real
terminal and retain private JSONL evidence of one approved execution. A test
calling the controller's internal approval store proves grant mechanics but is
not a human approval demonstration.

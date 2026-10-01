# Continue here — 1 October 2026

## Read this first

This development checkpoint never resumes an assessment or restores approvals.

**Current authorized work: practical tool coverage before deeper workflows.**
The operator selected this priority on 1 October and authorized implementation,
secure execution and owned-lab verification. The small batch is **curl HTTPS
retrieval and ffuf content discovery**, described in [practical-web-tools.md](practical-web-tools.md).
Work is on `feature/practical-web-tools` in `/tmp/recon-practical-web-tools`,
based on main `9a95d9a`. Each adapter must work independently through the existing
approval, audit, admission and confined launcher path and pass real owned-lab
checks before composing a deeper workflow. Reuse existing interactive tool
semantics where practical, never its host subprocess runner as an agent boundary.
Credential setup, paid calls and live-model evaluation remain deferred until much
later. Do not ask for a key, fund a ledger or enable a live provider.

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

The current batch fills HTTPS inspection and finite path-discovery gaps. curl
performs one verified HTTPS GET; ffuf checks eight pinned paths with no recursion,
redirects or caller-supplied wordlists. ffuf requires its own thread-capable profile;
accepted Nmap/native runtime limits stay unchanged. Track useful completion,
unnecessary refusals, bounded requests/output, latency, cleanup and evidence replay.
Only after both real tools pass these gates should deeper workflows be selected.
Roughly 40 tools remains a long-term target, not this batch's scope.

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
- The operator-authorized PR #35 merge is complete. PRs #6–#30 and #32–#35
  stay closed; proposal PR #31 remains separate. PR #36 now has conditional
  review/merge authorization. Additional implementation, later merges, submission,
  messages, paid calls and external targets need their corresponding instruction.

## Next continuation

1. Check PR #36's GitHub state and the private merge-review receipt first. Its
   review/merge is authorized conditional on the latest passing checks; if merged,
   keep it closed. PR #35 is merged as `98d6f1b`; PRs #6–#30 and #32–#35 stay
   closed. Proposal PR #31 remains separate. Historical “next” notes are not current work.
2. Preserve the completed offline comparison, accepted local packet, successful
   approval-required terminal rehearsal and actual operator decision. Do not
   reopen that review or modify the immutable accepted packet.
3. Keep credential setup and the real-model pilot deferred until the operator
   explicitly resumes them. Development uses deterministic/owned mocks and no
   paid calls. Retain the existing usefulness, refusals, cost and latency metrics;
   blocked unfinished work still fails usefulness.
4. Review the new bounded header capability and practical owned workflow before
   choosing another focused tool increment. Keep the proposal/PDF unchanged until
   its planned early-November update. Defer GUI/API and external targets.
5. Keep local kernel verification separate from hosted portable CI. Do not rerun
   full suites solely for documentation changes. Publication, submission and
   subsequent implementation need their corresponding operator instructions.

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

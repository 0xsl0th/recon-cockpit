# Continue here — 30 September 2026

## Read this first

This development checkpoint never resumes an assessment or restores approvals.

**PR #24 is merged and stays closed.** Final head `9ccc910` passed review and
all five hosted checks. The authorized merge is `4f9545c` at 22:38:18 UTC on
29 September; its tree exactly matches the reviewed head. All five
[post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36640750168)
passed. Runtime evidence remains 3,382 portable and 430 Linux tests, with zero
selected failures/errors/skips. [PR #24](https://github.com/0xsl0th/recon-cockpit/pull/24)
completed the bounded mock planning bridge. Later merges still require authorization.

**Current work: owned TLS assessment planning**, implementation `30f2b2d` in
[PR #25](https://github.com/0xsl0th/recon-cockpit/pull/25), on
`feature/owned-tls-assessment-planning` from `4f9545c`. Read
[owned-tls-assessment-planning.md](owned-tls-assessment-planning.md). The explicit
`--assessment-planning-owned-tls` profile carries the existing closed descriptor
through a disconnected TLS fixture with generated synthetic credentials. It
reuses PR #24's evidence/monetary/proposal gate, preserves all independent launch
checks and leaves the fixed ACK and original status-only profiles separate.
Full verification passed; leave this PR unmerged for review. Its
[checks page](https://github.com/0xsl0th/recon-cockpit/pull/25/checks) records hosted
status for the latest revision. A merge needs separate operator authorization.

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

## Current priority — continue R5 after completed R5a and R5b

The operator clarified that **R5 is the active milestone and R5a and R5b are
complete**. R5a merged in PR #13; R5b's ledger and controlled provider-call path
merged in PRs #14 and #15. Their agreed development and verification scope is
offline. Follow [the roadmap's completion order](roadmap.md#milestone-completion-order),
which supersedes older “next step” notes in this file.

Preserve the accepted R1–R4 implementations and their documented limits. Do not
restart them or make broader capability-registry/finding-workflow extensions
prerequisites for continuing R5. The next work is **bounded R5 planning
integration** on the completed authority boundaries, followed by its evaluation
gates, then R6 evaluation/release work. Address an earlier contract only when a
concrete dependency or regression requires it. R5a/R5b completion
does not claim that all of R5 or real-model validation is complete.

The separate budgeted-assessment proposal, general session-view API and GUI
dashboard are deferred until the original milestones are complete. Accounting
actually required by R5 remains part of R5. Use judgment about the later ideas'
fit without introducing a new parallel milestone or weakening the architecture.
Live validation remains an explicit pending gate: all current development and
verification must use owned/mock fixtures, no paid or external provider calls,
and live execution disabled by default. This sequencing instruction does not
authorize activation, external targets, real credentials or a new merge.

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

## R5 owned TLS planning — verification checkpoint

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

After this slice is reviewed and separately authorized for merge, continue with
the integrated path's offline evaluation against the preserved deterministic
baseline. Keep live model acceptance pending and optional additions deferred.
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

## Remaining milestone gates

1. Keep PR #24's verified mock planning slice closed. Review the owned TLS
   planning integration, then continue the offline evaluation gate.
   Durable audit and fresh grant verification remain independent launch
   preconditions. A selected terminal/worker still cannot prove a human's
   identity or intent independently of that trusted environment.
2. Preserve the completed audit, approval, admission and launcher contracts.
3. Continue the remaining planning transport/integration and offline evaluation
   gates on R5a/R5b after this mock bridge. Neither fixed ACK nor mock responses
   establish real-model performance.
4. Keep real-model comparison visibly pending until explicit authorization and
   reviewed data/model/credential/spend settings. Continue offline meanwhile.
5. Then complete R6 corpus/evaluation consolidation, actual operator review,
   reproducible packaging and demonstration, disclosing any approved offline
   fallback. Keep accepted milestones closed and optional GUI/API scope deferred.

For the next planning slice, preserve the fixed ACK diagnostic's contract in
`provider_pilot.py`. A bounded assessment proposal/release profile must be
separate and exercised first through owned/mock responses, the existing isolated
parser/coordinator, simulation monetary reservations/settlement and the completed
launch preconditions. Preserve the deterministic workflow/evaluation baseline;
model output supplies proposals, never policy, grants or finding truth. Existing
R5a status-only release does not authorize exporting raw evidence, credentials or
arbitrary engagement data. Live validation remains separately authorized.

The current slice implements a separate owned-only assessment provider with the
`bind_session`/`propose` interface consumed by `AuthoritySession`; keep
`workflow.decide` and saved evidence authoritative for eligible actions and
findings. Before releasing any proposal, verify the explicit assessment data
profile and settle recognized usage against a simulation reservation; ambiguous
dispatch failures retain their holds. Exercise the existing six cases and
adversarial refusal/cancellation paths through both direct launch gates. This
does not change the fixed ACK call or expand completed milestone scope.

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
  workers for persistence, grants and fixed policy/resource decisions. The new
  fixture launcher owns nested admission and executor supervision; the host
  still enforces consent/audit ordering and launches persistent labs. Hashes detect
  inconsistency, not host-owner tampering. R1 callback and R2 HTTP framing limits
  remain documented.
- The operator authorized the completed merges through PR #19.
  This does not authorize unrelated
  future merges, submission, messages, paid calls or external targets.

## Next continuation

1. Start from the current priority and merged checkpoint above. PRs #6–#19 are
   already merged. Inspect Git and hosted checks before publication; historical
   branch names and open-PR notes below earlier checkpoints are not current work.
2. Review the confined fixture-launcher slice; audit, approvals and admission are merged.
   Then continue the remaining R5 authorization/launcher separation by stating
   exactly which authority leaves each process, then implement and verify the
   next bounded change with owned fixtures. Preserve existing tools and backend
   restrictions; do not schedule a general registry or R3/R4 expansion as a
   prerequisite. Persistent lab launch custody and independent precondition
   authentication remain outside the fixture-only slice. Complete remaining R5
   authority/planning work before R6.
3. R5a and R5b are complete. Preserve them as regression references while
   developing the remaining bounded planning integration. The synthetic ACK
   path does not complete live assessment planning. Keep live acceptance pending
   until the operator explicitly enables it; do not fill that gap with a GUI.
4. Keep kernel verification separate from hosted portable CI and record measured
   results/publication state for every slice. Revisit the additional ideas only
   after the original milestone acceptance gates have been satisfied.

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

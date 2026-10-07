# Verification record

## PR #58 review and merge — 7 October 2026

C4 DNS SRV metadata is closed. Reviewed head `65810b8e9f447cf63ef1bed88b0a7987ad35fe7b`
merged as `6080a5c5e4d2f5cde00415299c259f212813d40b` at 19:36:01 UTC.
Reviewed and merged trees match `fbb7092085e169f499d364355bf11c75c4ca2fcb`.
Independent authority/runtime review passed 1,328 focused portable tests;
parser/evidence review passed 821 focused and 422 regression tests. No blockers
were found. All 502 recorded source hashes and native/clean-source receipt hashes
matched. The ten saved native C4 artifacts independently reparsed with matching
raw captures, runtime bindings, counters and outcomes.

All five [final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37673798024)
passed 11,428 tests each, and all five
[post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37675710586)
passed. No branch check rules or unresolved inline review comments were present;
all five matrix jobs and independent source review were the merge gate. No GitHub
formal approval is claimed. The private merge receipt is
`.secure-agent/pr58-merge-review.json`.

Preserve C4's 25 native tests, 4/4 ordinary completions, separate 1/1 robustness
completion, zero unnecessary refusals, 20/20 blocked destinations and 40 unchanged
accepted-bundle replays. The evidence remains under
`.secure-agent/dns-srv-20261007/`. Do not repeat the merge or reopen C4.


## Desktop Execute owned lab — 7 October 2026

The `feature/desktop-owned-execution` slice starts the existing four-action owned
HTTP/SSH assessment from the desktop through the shared service. It freezes scope,
requires the isolated graphical reviewer for each action and retains the original
four-step/60-second/26,624-byte limits. No secure-agent production code or authority
contract changed. This implementation remains subject to its separate PR review;
PR #53's accepted personal walkthrough is closed.

The final complete portable suite passed **9,981 tests**, with 849 integration
cases deselected, in 294.54 seconds. No selected tests failed, errored or skipped.
Its receipt is `portable-pty-results.xml`; hosted matrix checks remain a separate
PR requirement. Python 3.11 syntax, local documentation targets and
`git diff --check` also passed. Independent controller, GUI and native-fixture
reviews found no remaining blockers.

**70 native Linux/Tk tests passed in 102.02 seconds**, with no selected failures,
errors or skips. The private Xvfb suite covered the desktop execution, dry-run and
saved-evidence views, reviewer input controls and approval isolation. Unraisable
exception warnings were treated as errors. The six new desktop cases used the
real shared service, grants, launcher witnesses, tools, parsers and evidence;
only reviewer input and observation latches were test fixtures.

| Desktop case | Useful actions | Stop reason | Recorded elapsed |
| --- | ---: | --- | ---: |
| Scripted typed approval | 4/4 | `coordinator_done` | 9,775 ms |
| Scripted clipboard approval | 4/4 | `coordinator_done` | 9,334 ms |
| Deny first action | 0/4 | `action_blocked` | 1,421 ms |
| Cancel with review pending | 0/4 | `session_cancelled` | 1,232 ms |
| Close with review pending | 0/4 | `session_cancelled` | 1,213 ms |
| Cancel after one successful action | 1/4 | `session_cancelled` | 3,962 ms |

Each full session blocked **12/12 listening forbidden destinations**, completed
all four legitimate actions and recorded zero unnecessary refusals. All executed
artifacts passed 11/11 boundary checks. Denial and pending cancellation/close
consumed no grant and launched no tool. Every case closed its fixture owners and
authority processes and independently replayed without changing evidence. Provider
calls and actual cost were zero. Incomplete cases retain ungraded refusals.
These scripted timings include test observation and screenshot work; they are
neither human-review latency nor a comparative overhead benchmark.

Both themes passed at 1120×720, including disabled starts during execution/replay,
provisional metrics, truthful partial results and wrapped metric descriptions.
Private screenshots were inspected. The ordinary desktop has no approval-answer
entry point and never starts host tools directly. Automated input used only a
private display and is distinct from accepted owner input.

Two earlier broad development runs failed and remain preserved. Tests initially
missed a fast denial's live process and latched a blocked action as if it were
successful. Repeated Tk fixtures also finalized retired variables on a worker
thread; opt-in collection now occurs on the main thread after prior fixture
release. A separate deterministic diagnostic proved that the scripted input
timer could answer twice while one event pump drained. Its pending-decision guard
and two-review regression affect test code only. These findings do not establish
the cause of every earlier `approval_unavailable` or isolation failure. No failed
outcome was promoted to success, and no production restriction was relaxed.

Two full portable-suite attempts terminated before producing JUnit receipts.
The first exited with SIGTERM, cause unproven. The second exited with SIGHUP at
the existing scripted terminal fixture's teardown: a runner without a controlling
terminal can acquire its temporary slave. A dedicated automated PTY avoids that
acquisition; all 13 terminal cases passed there, without changing test assertions
or using the owner's terminal. Incomplete attempts remain separate from final runs.

Private receipts, original failed runs, diagnostic proof, source hashes, native
bundles and screenshots live under `.secure-agent/gui-execution-20261007/`.
The final native receipt is `native-accepted-results.xml`; the earlier clean
69-case run predates the added fixture regression and remains separate.
Credentials, paid calls, live-model evaluation and external targets stay deferred.

## Full personal graphical walkthrough accepted — 7 October 2026

The owner completed the four-action walkthrough at PR #53 documentation head
`5f15851decfdb10974e8c2b05528fa24d2d6227e`, with product code and tests unchanged
from reviewed implementation `5970a108`. The successful session
`graphical-owned-5nkgldx7` completed **4/4 useful actions**, consumed four grants,
started four executions and recorded four successful finishes. It stopped at
`coordinator_done` after **45,642 ms**, within the unchanged four-step/60-second/
26,624-byte limits. Legitimate completion was true; unnecessary refusals, provider
calls and actual cost were zero. Both owned fixtures closed.

The owner confirmed, "ok this time it worked". Together with the separately
confirmed approval, denial and pending-review cancellation interactions below,
this completes the personal graphical walkthrough. No personal approval input was
supplied by automation. These observed timings are not a comparative benchmark.

Preserve the earlier full runs as incomplete: `graphical-owned-cqe6rd5t` completed
3/4 actions before timeout at 60,041 ms, and the owner reported distraction;
`graphical-owned-uepnf27q` completed 2/4 before timeout at 60,045 ms, and the owner
reported a copying problem whose cause remains unproven. Neither trial recorded
`approval_unavailable`. Fresh independent inspection of all three full trials
matched their saved reports, found no integrity issues and left evidence unchanged.
Each trial retained its own outcome and recorded closed fixtures with zero cost/calls.

Private receipts are
`.secure-agent/graphical-full-approval-20261007/full-trials-evidence-review.json`
and `owner-confirmation-full.json`, alongside the original trial artifacts.
The individual-controls and scripted native receipts remain separate. PR #53
subsequently merged as `0539c15` after final review and all five checks; its five
post-merge checks also passed. The desktop Execute integration is the separate
slice recorded above, reusing the shared service and isolated graphical reviewer
for disconnected owned fixtures.
Completed B0–B8, offline R5 and accepted local R6 stay closed; credentials, paid
calls, live-model evaluation and real network attachment remain deferred.

## Personal control confirmations — 7 October 2026

The owner completed three separate one-action rehearsals against the owned,
disconnected fixtures at PR #53 documentation head `db9ba1a`; product code and
tests are unchanged from reviewed implementation `5970a108`. All five
[checks on the documentation revision](https://github.com/0xsl0th/recon-cockpit/actions/runs/37431954622)
passed. The request stayed at one step, 60 seconds and 8,192 output bytes.

| Owner-confirmed control | Successful actions | Stop reason | Session elapsed |
| --- | ---: | --- | ---: |
| Approve | 1 | `step_limit` | 23,238 ms |
| Deny | 0 | `action_blocked` | 15,093 ms |
| Leave unanswered, then Ctrl+C | 0 | `session_cancelled` | 6,177 ms |

The owner described the approval steps as clear, confirmed completion of the fresh
denial test, and explicitly reported leaving the cancellation review unanswered
before pressing Ctrl+C. The earlier denial trial during which the owner was AFK
remains unconfirmed and is excluded. Denial and cancellation each consumed zero
grants and recorded zero tool starts or finishes; approval consumed one grant and
completed one execution. All fixtures closed. These are observed session timings,
not a comparative overhead measurement.

Fresh independent inspection of all three sessions matched the saved reports,
found no integrity issues and left every evidence file unchanged. Provider calls
and actual cost are zero. Private receipts are
`.secure-agent/graphical-single-action-20261006/owner-controls-confirmation.json`
and `confirmed-controls-evidence-review.json`, alongside the separate owner feedback
and retained session artifacts. No personal input was supplied by automation.

The three controls were confirmed at this checkpoint while full four-action
personal acceptance remained outstanding. Each smaller request correctly reports
an incomplete full assessment. The subsequent full walkthrough is recorded above;
it does not change these smaller requests' outcomes. Do not repeat the confirmed
controls or extend/reset deadlines. Automated full-workflow receipts remain distinct.

## Corrected reviewer retry and simpler rehearsal — 6 October 2026

Fresh review of `5970a1086cbc4978c7eeb3a71d740dcf5ca221df` found no blockers;
source hashes matched the 51 native and 112 focused portable receipts. All five
[hosted checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37429201956)
passed. GitHub rejected formal self-approval because the active account is the
PR author. The private review receipt is `.secure-agent/pr53-review.json`.

The next owner retry produced no `approval_unavailable` events, but both started
sessions reached the original deadline. The approval-labeled stage completed
2/4 actions in 60,027 ms; its first two reviews took 27.45 and 16.81 seconds,
leaving 11.36 seconds at the third review before timeout. The denial-labeled stage
completed one action in 60,036 ms: a 36.45-second first review issued a grant, and
the next review timed out after 20.30 seconds. No denial was recorded. Cancellation
was not started. Both reports are incomplete, record closed labs and list no
integrity issues; the three executed artifacts each record 11/11 true boundary
checks. Provider calls and actual cost are zero. Stage labels do not establish
which user interactions occurred.

The owner confirmed that the copy/paste or three-session instructions were
confusing. Preserve those observations and unsuccessful results in
`.secure-agent/graphical-owner-helpers-20261006/`. Personal acceptance was
outstanding at that checkpoint; PR #53 stayed draft. The planned rehearsal selected
one case per launch, starting with one approval and pausing for owner feedback
before denial or cancellation.
It reuses the existing service with one step, 60 seconds and 8,192 bytes; a successful
first action ends at `step_limit` and does not complete the four-action assessment.
Keep controls-rehearsal evidence distinct from full-workflow completion and
scripted validation. Ordinary desktop execution remains disabled.

Three private native cases validated this smaller request on an owned Xvfb
display in 6.77 seconds. Approval completed one action and stopped at `step_limit`
(3,785 ms); denial completed zero and stopped at `action_blocked` (1,143 ms);
pending-review cancellation completed zero and stopped at `session_cancelled`
(1,126 ms). All three retained incomplete full-assessment outcomes, closed labs,
zero provider calls/cost and unchanged independent replay. Only the approved case
consumed a grant and launched a tool; its result passed all 11 boundary checks.
These are scripted test results, not owner input. The private launcher request
exactly matches this tested configuration. Receipts and evidence are retained in
`.secure-agent/graphical-single-action-20261006/validation/`. The launcher shows
only the selected case, waits for the owner to start, records actual audit counts,
reports unexpected behavior without acceptance and handles early interruptions.

## Personal graphical retry failure — 6 October 2026

At PR #53 head `b045a24252f54b11f131f39514e9afdc0926b65d`, the owner could copy
and paste the phrase, but the real desktop retry exposed another failure. The
approval-labeled session completed one action, then stopped with
`approval_unavailable` after 28,311 ms. The denial-labeled session stopped with
the same error after 5,998 ms, with no actions. The cancellation-labeled session
completed two actions, then reached the 60-second limit (60,038 ms elapsed).
Stage labels describe intended tests; they do not prove denial or cancellation.
None of these trials establishes successful personal walkthrough acceptance.
All used zero provider calls and zero model cost.

Private Xvfb tests with real XTEST input reproduced a concrete cause: Tab needs
Tk's deferred `focus.tcl` helpers, and double-click selection in the phrase or
action details needs Tcl's deferred `word.tcl` helpers. Loading these files after
the worker's filesystem-open seal is denied. Tk's binding error reaches stderr,
and the authority correctly stops with `approval_unavailable`. Basic mouse clicks
and Copy → Ctrl+V → Approve worked, including a private XFWM/clipboard-manager
session. The original trial logs do not identify the owner's exact triggering
gesture; this reproduction establishes the defect without inventing that detail.

The correction preloads and verifies eight fixed focus/word helper commands
before sealing, leaving existing commands intact on repeated warmup. It changes
no filesystem/network restrictions, approval protocol, grants, witnesses or limits.
The original private five-case reproduction had three failures before the fix
and none afterward. Six repository regressions drive the unmodified worker with
real XTEST Tab/Shift-Tab, double-click selection and word navigation/deletion;
each requires the review to remain pending before a separate approval or denial.

**51 native Linux/Tk cases passed in 48.08 seconds**, without failures, errors or
skips. Both existing typed-input and clipboard workflow modes completed 4/4 useful
actions, blocked 12/12 forbidden destinations per mode and replayed unchanged,
with zero unnecessary refusals/provider calls/cost. Elapsed times were 8,603 ms
and 8,625 ms; these are scripted-fixture timings, not human latency or a paired
benchmark. **112 focused portable tests passed.** Independent source reviews
found no blocker. Final receipts use `helpers-native-results.xml` and
`helpers-portable-focused.xml` under `.secure-agent/graphical-copy-20261006/`;
the original failing and corrected reproductions are retained there separately.

All three failed owner bundles independently replay as incomplete without
integrity issues, with unchanged file hashes. Replay requires the existing
isolated parsers; the earlier sandbox-limited reconciliation result is retained
separately. PR #53 remained a draft pending personal acceptance at that checkpoint. Earlier native
scripted-input and hosted portable checks passed, but did not cover these gestures.
Preserve private logs, bundles, screenshot and `failure-summary.json` under
`.secure-agent/graphical-owner-copy-20261006/`. The fix was then ready for review
before another personal retry. Ordinary desktop execution remains disabled.

## Graphical approval copy/paste correction — 6 October 2026

The initial personal walkthrough exposed a usability defect: the fresh challenge
was a nonselectable label. The owner reported being unable to copy/paste it. Both
started sessions ended at the unchanged 60-second deadline with zero consumed
grants and zero tool launches; the cancellation session was not started. Preserve
those unsuccessful trials in `.secure-agent/graphical-owner-20261006/`. They do not
establish successful personal approval, denial, cancellation or usability acceptance.

The correction uses a selectable read-only phrase field and an explicit **Copy
phrase** button. Copy sets only the clipboard and answer-field focus, with a
Ctrl+V hint. It does not fill the answer or approve. Normal paste retains the
128-character input limit, and **Approve once** remains a separate action.
Copy is disabled outside an active unexpired review; cleanup clears local fields
without reading/restoring or clearing unrelated clipboard content. Existing X11
trust, runtime restrictions, protocol, grants, witnesses and limits remain intact.

**45 native Linux/Tk tests passed in 40.43 seconds**, with no failures/errors/skips:
29 actual confined-worker/workflow cases and 16 direct-view cases on a private
Xvfb display with TCP disabled. Tests exercise Copy and paste after the worker's
restrictions are installed, copy-only denial, stale clipboard rejection, one-use
grants, expiry/cancel/channel failures and the existing adversarial requests.
Direct-view cases include scripted Ctrl+C/Ctrl+V key events, read-only selection,
oversized paste rejection, inactive/expired copy preserving unrelated clipboard,
and Return leaving approval pending. Test callback assertion failures now exit
the fixture worker, so they cannot masquerade as expected denials.

Both the existing typed-input fixture and the new clipboard fixture completed
**4/4 useful actions** with **12/12 forbidden destination checks blocked** per run,
zero unnecessary refusals, zero provider calls/cost and unchanged independent
evidence replay. Elapsed times were 8,373 ms and 8,840 ms respectively. These are
descriptive runs with scripted test input; they are not a paired overhead benchmark
or personal approval. No operator challenge is entered by automation on the real
desktop. A fresh personal retry was still necessary at that checkpoint.

The final source hashes, JUnit, owned evidence and two inspected screenshots at
900×740 and 780×650 are private under `.secure-agent/graphical-copy-20261006/`.
The initial four-case confined clipboard run and separate 16-case direct-view run
remain development evidence; use `native-final-results.xml` for the combined final
run. Read-only phrase, Copy button, answer field and both decision controls fit
at both tested sizes. Fresh source review found no security blocker. Python 3.11
syntax and whitespace checks passed. Model credentials and paid calls remain deferred.

## PR #52 acceptance and personal walkthrough preparation — 6 October 2026

Fresh runtime/protocol and worker/view reviews found no blockers at
`7b547941b812e1f7fc9c598c756b540aff9fc1b6`. Additional review checks passed 35 actual
graphical/workflow tests, 57 portable view/witness tests and 137 service/protocol
tests (overlapping sets). All 14 source hashes, the screenshot and eight saved
evidence hashes matched the existing receipts; JUnit confirmed 9,949 portable
and 125 native cases with no selected failures/errors/skips. All five
[final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37422834741)
passed. The reviewed head merged as `21054db4d44098e8541c4c9a5edbf82dd3c0e0b5`
at 06:26:28 UTC; reviewed and merged trees match
`88af19e00da06de2a3253b69c3033b64f068159e`.
All five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37423742151)
also passed.

A private launcher opens the accepted walkthrough entry point in three fresh
sessions for personal approval, denial and cancellation. It waits for the operator
to type `start` before each session, never supplies review input, retains the
60-second session limit and saves progress under
`.secure-agent/graphical-owner-20261006/`. Local display/socket/cookie availability
was checked without printing cookie bytes. Opening this launcher establishes no
personal approval or acceptance. The owner must complete the sessions and describe
the observed prompts, destinations, timing and cleanup before usability acceptance
is recorded. Ordinary desktop execution remains disabled; model credentials and
paid calls remain deferred. Merge receipt: `.secure-agent/pr52-merge-review.json`.

## Isolated graphical exact-action reviewer — 6 October 2026

Based on accepted PR #51 merge `972afac`, this slice adds a fixed graphical
frontend to `LinuxApprovalService`, an explicit shared-service selector and a
plan-only-by-default walkthrough command. The separate worker owns its window,
fresh challenge, grant store and original launcher witness. Review/consume keep
their existing bounded protocol; no affirmative answer operation is added. The
ordinary desktop remains `execute=False` and has no Execute control.

The full portable suite passed **9,949 cases**, with **826 integration cases
deselected**, no selected failures/errors/skips, in **323.96 seconds**. Selection,
bootstrap/cookie parsing, immutable requests, fixed mounts, literal rendering,
denial/unavailable routing, audit failures and plan-only defaults are covered.
These portable cases do not establish OS confinement or personal approval.

**125 native Linux/Tk cases passed in 197.56 seconds**, without selected failures,
errors or skips: 25 new confined-worker/workflow cases, one real memfd-sealing
case, ten direct Tk view cases and 89 existing terminal-approval, witness and
shared-service regressions. The private Xvfb display had TCP disabled. Worker
cases use explicitly instrumented test-only input; production has no automation
switch. Neither these tests nor the direct-view screenshot constitute owner
approval or personal usability acceptance.

The final real graphical owned workflow completed **4/4 actions**, with four
consumed grants, four launch starts, structured artifacts and unchanged independent
replay. All **12/12 listening forbidden destinations** were blocked (cross-service,
wrong address and wrong port for each action). Useful completion was true,
unnecessary refusals were zero, and actual provider calls/cost were zero. The
reported elapsed time was **8,569 ms**, including scripted test interaction. There
is no comparison baseline; this is not a human-review latency or authority-overhead
benchmark. Denial and pending cancellation produced zero unapproved launches and
closed the reviewer. Existing launcher/audit/admission witnesses remain mandatory.

The new audit assertions require exactly four graphical review-request and
grant-issued outcome records, bound to the session/action/policy and excluding
challenge answers and grant references. Portable fault injection at either review
audit append prevents even grant consumption, closes controls, leaves no finalized
report and forbids service reuse. Other cases reject changed, expired, replayed,
cross-worker, malformed and forged requests; stale/pretyped input and Enter cannot
approve. Actual worker checks include descriptor custody, host canary isolation,
read-only runtime, private namespaces, capability/syscall restrictions and the
single intentionally mounted X11 connection. The host and desktop remain trusted.

Native receipts, preserved owned evidence, source hashes and the inspected
900×740 direct-view screenshot are private under
`.secure-agent/graphical-approval-20261006/` in the primary checkout. Final receipts
are `portable-results.xml`, `native-reviewed-results.xml`, `native-reviewed-tests/`,
`validated-source.json` and `verification.json`. Earlier ten-case, 25-case and
125-case baseline runs remain separate; the final native run includes the later
review-audit changes. The earlier JUnit property-format warning is avoided by
using legacy JUnit for the final property-bearing native run.
A separate read-only replay also matched the report and every saved file hash
under native Linux permissions. The same check inside the restricted development
sandbox returned reconciliation-required because its isolated parser could not
start there; that environmental result is retained in the private receipt.

Independent lifecycle/security and UI/evidence reviews found no remaining
blockers. Python 3.11 syntax, dependency consistency and local documentation-link
checks passed. The [runbook](graphical-approvals.md) documents the supported local
Linux/X11 resource layout, trust limits and prepared personal walkthrough. Hosted
CI is portable and cannot substitute for these native receipts. The owner's
walkthrough and ordinary desktop execution controls were outstanding at that checkpoint.

PR #51 itself merged with matching reviewed/merge trees and all five
[final PR checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37418950338)
and [post-merge checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37420312524)
passing. Preserve `.secure-agent/pr51-merge-review.json`, accepted B0–B8 and offline
R5/local R6. Model/service credentials, paid calls and real network attachment
remain deferred; no proposal, PDF or private image is published in this slice.

## Desktop dry-run session lifecycle — 6 October 2026

Based on accepted PR #50 merge `7efa9d8`, this slice connects the desktop to the
existing shared service with `execute=False` and `interactive_terminal=False`.
It freezes scope, generates the unchanged approval-required policy, creates a
fresh private session folder and owns run/cleanup/replay in one worker. All
existing tool, authority, approval and evidence contracts remain unchanged.

The full local portable suite passed **9,837 cases**, with **790 integration cases
deselected**, no selected failures/errors/skips, in **258.53 seconds**. Fourteen new
portable tests cover private/fresh paths, unsupported/unsafe destinations, request
limits, scope custody, actual one-proposal dry-run behavior, cancellation before
startup/after a step, close while replaying, distinct failures, recovery and bounded
literal progress. Existing service and GUI regression cases remain passing.

**Eleven actual Tk cases passed** with no failures/errors/skips in **12.65 seconds**
on a private Xvfb display with TCP disabled. Six preserve saved-evidence behavior;
five new cases exercise desktop session lifecycle. Four use real shared authority
and isolated audit/coordinator controls. A clearly labeled test-only observer latch
holds a real first policy decision for progress, theme/draft, cancellation and
close checks; another case injects a final replay failure after a real run. The
fifth uses an explicit startup failure double. Constructors remain real where the
service runs, while endpoint/tool launch, runtime inspection and approval input/
consumption are guarded against use. Audit workers and the desktop worker finish
before closure; private paths and unchanged independent replay are checked.

These trials execute **zero tools and zero provider calls**, record **zero useful
actions**, and do not claim successful task completion, human approval, refusal
quality or comparative overhead. The configured workflow stops after the first
policy-reviewed proposal because follow-ups need real predecessor evidence.
Existing accepted 4/4 native evidence is only inspected and remains unchanged.
The desktop still cannot execute or approve a tool; the
[graphical approval plan](desktop-approval-plan.md) describes the remaining gate.

Ten private screenshots cover both themes, saved views and new running/finished
states at 1360×900 and 1280×800. Controls and metrics fit, session scope stays
separate from edited drafts, and failed replay cannot display verified success.
Source hashes, images, JUnit and retained native bundles are under
`.secure-agent/gui-session-20261006/` in the primary checkout. The initial seven
portable development failures came from using the scope-only encoder for policy;
the existing contract encoder fixed them. This is retained in development notes.
The five-case development Tk run also passed before the combined final run.

Fresh independent lifecycle/security and UI reviews found no remaining blockers.
Python 3.11 syntax, documentation links, dependency consistency and whitespace
checks passed. Hosted CI is portable and does not substitute for local Linux/Tk
validation. The new PR is left unmerged for review; exact head and final CI are in
the private handoff. The checkpoint keeps B0–B8, R5, local R6 and PR #50 closed.

PR #50 itself merged with matching reviewed/merge trees; all five
[final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37416444887)
and all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37417644593)
passed. Its merge receipt is `.secure-agent/pr50-merge-review.json`.

## Initial offline desktop GUI — 6 October 2026

Based on accepted main `db42cd1`, the desktop adds local scope preparation and
saved-evidence views using both Swiss Industrial themes. The controller calls the
existing shared read-only inspector from one worker; scope forms reuse the exact
configurable contract. It creates no assessment, approval service, legacy command,
listener or model call. Existing authority and tool contracts are unchanged.

Independent controller/presenter review found no blockers after correcting duplicate
display-row IDs for malformed records. **101 focused portable cases passed** for
strict scope forms, bounded literal presentation, missing/contradictory metrics,
corrupt/unfinished/dry-run state, asynchronous errors/close, private no-overwrite
exports and GUI startup without Tk/display. The full local portable suite passed
**9,823 tests**, with 785 integration cases deselected, no selected failures/errors/
skips, in **312.02 seconds**. Final production hashes match the actual Tk run.

**Six actual Tk cases passed**, with no failures/errors/skips, in **8.455 seconds**
on a private Xvfb display with TCP disabled. Tests exercise three pages, both
themes, invalid/valid scope, import/export, background replay, corrupt evidence,
failed inspection clearing a prior success, row-selection synchronization and
window close waiting for the reader. Execution/approval constructors and legacy
runners are guarded against use during these checks. The original accepted native
bundle remains unchanged in bytes, modes and mtimes. Corruption uses a temporary
copy. Displaying its 4/4 useful actions and 8.004-second duration describes earlier
accepted work; the GUI run executes **zero new assessments and zero provider calls**.

Seven private screenshots were visually inspected at **1360×900 and 1280×800**,
covering dark/light overview plus scope and evidence views. Key controls, metrics
and all four recorded rows fit; longer details scroll. Product observations lead
the selected-action panel; technical IDs remain below. Draft and recorded scope
remain distinct. No fabricated online agents, pending approvals, authenticated
vulnerabilities or signing/confidence claims are shown.

Private receipts are `.secure-agent/gui-20261006/` in the primary checkout:
`desktop-final-results.xml`, `desktop-verification.json`, `screenshots/`, and the
portable/CI handoff. Earlier assertion-only failures from concurrent presenter
wording changes remain in `desktop-initial-results.xml` and
`desktop-development-cost-label.xml`; final validation uses the frozen source.
Python 3.11 syntax, documentation links and whitespace checks passed. Hosted CI
is portable and does not substitute for these actual Linux desktop tests.

PR #49 was separately reviewed and merged as `db42cd1`, with identical reviewed
and merge trees. All five final and post-merge jobs passed; fresh 95 focused and
517 historical regression cases passed (overlap). Its implementation stays closed.
See [the desktop runbook](desktop-gui.md) for supported operations and limitations.

## Shared CLI/GUI assessment service — 6 October 2026

Based on accepted PR #48 merge `5f046eb`, this slice extracts application lifecycle
and saved-evidence inspection without changing tool contracts, scope, policies,
approval input or executor protocols. Direct callers now get the same mandatory
isolated audit, approval, admission and launcher path as the terminal. CLI signals
remain in the terminal adapter; service execution works from a worker thread.

The full local portable suite passed **9,722 tests**, with 778 integration cases
deselected at collection and no selected failures, errors or skips (304.98 seconds).
The fourth native service case was added after this portable collection; it is
covered by the separate final native run and hosted collection.

Independent service/CLI review found no remaining blockers; 95 focused service,
CLI and inspection checks passed. A review finding about swallowed progress-callback
exceptions was fixed: the service cancels, propagates the error after cleanup and
never finalizes a report from that failure, including in dry-run mode.

Native validation passed **8 distinct Linux cases**: four direct-service cases and
four existing configurable CLI cases. The final direct-service run followed the
observer-error fix. All selected cases passed without skips. One initial test
assertion expected `cancelled` instead of the existing `session_cancelled` reason;
the assertion was corrected and the failure retained. No production cancellation
change was needed for that result.

| Completed route | Useful actions | Blocked listening destinations | Session elapsed |
| --- | --- | --- | --- |
| Shared service on worker thread | 4/4 | 12/12 | 8.004 s |
| CLI primary scope | 4/4 | 12/12 | 8.105 s |
| CLI alternate scope | 4/4 | 12/12 | 8.136 s |

All three workflows report zero unnecessary refusals, provider calls and cost.
These are descriptive local times, not a comparative overhead benchmark. Tests
also verify approval-required noninteractive refusal before launch, cancellation
after actual Nmap starts, process reaping, closed owners and replayable cancelled
reports. Observer failure after a successful Nmap action permits no second launch,
closes both owners, rejects reuse and retains real partial evidence; inspection
identifies unfinished evidence without manufacturing a final report.

The shared inspector and CLI independently replayed **29 accepted bundles**
(27 B1–B8/service-web plus both PR #48 scope examples), with identical reports and
unchanged file bytes, mtimes and modes. Portable tests cover immutable request
validation, shortened ceilings, mandatory gate construction, concurrent-start
refusal, cancellation during setup, detached progress/result snapshots, exceptions,
signal restoration and malformed/private evidence dispatch. Python 3.11 syntax,
relative documentation links and whitespace checks passed.

Private receipts are `.secure-agent/shared-service-20261006/` in the primary
checkout: `service-native-final-results.xml`, `service-native-final-verification.json`,
`service-native-results.xml`, `accepted-replay.json`, `validated-production.json`
and the final portable/CI handoff. Local kernel evidence is separate from hosted
portable checks. No GUI, new approval channel, attached network, personal approval
rehearsal, authenticated operation or model call is claimed.

## Configurable owned HTTP/SSH scope — 6 October 2026

PR #48 was reviewed and merged as `5f046eb`, preserving reviewed head `5260b695`'s
tree. Independent reviews found no blockers; 652 configurable authority, 363
existing authority and 276 workflow/evidence/parser/CLI focused checks passed.
All five [final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37411904045)
passed 9,646 portable tests each, and all five
[post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37413359372)
also passed. Preserve this accepted slice. The details below retain the earlier
local/hosted validation history rather than counting corrected failures as passes.

Implementation `065e0ee0eadff12acc2fef3d56eded5a0f6c5d61` in
[PR #48](https://github.com/0xsl0th/recon-cockpit/pull/48), based on accepted main
`fc477d0`, adds exact operator scope for two
disconnected endpoint fixtures. It preserves the accepted v1 contracts and uses
the existing approval, audit, admission and launcher path for all four actions.
Independent lab/authority and runtime/parser reviews found no execution-boundary
blockers. Evidence review corrected prior-counter validation, dry-run replay,
failure poisoning and summary/journal reconciliation before final validation.

Local Linux validation passed **117 distinct tests**: four new full-path cases
and 113 affected existing admission, launcher, owned-lab, service/web and native
NSE-shim regressions, with no selected failures or skips. The final configurable
run followed the last runtime strictness fix; 217 focused parser/runtime tests
also passed. The full portable run passed **9,645 tests**, with 775 integration
cases deselected and no selected failures, errors or skips. That run began before
the final strict-boolean receipt regression was added; the final 217-test focused
run covers that change. The PR's hosted matrix checks the complete latest
revision on Linux/Python 3.11–3.14 and macOS/Python 3.14; inspect its check results
before review/merge rather than treating local Linux evidence as hosted CI.
The first hosted matrix passed all four Linux jobs (9,646 tests each) but exposed
17 macOS failures from two missing portable-test doubles: namespace discovery
and the runtime platform selector. Those fixtures now supply explicit test facts;
54 focused tests pass and production code is unchanged. The original macOS
peer-lifetime regression passed. Retain `initial-macos-ci-failure.log`; final
hosted validation must use the corrected PR head.

| Scope example | Useful actions | Blocked listening destinations | HTTP / SSH acknowledged totals | Session elapsed |
| --- | --- | --- | --- | --- |
| Primary | 4/4 | 12/12 | Each: 3 connections, 2 requests | 8.740 s |
| Alternate addresses/ports/path | 4/4 | 12/12 | Each: 3 connections, 2 requests | 8.921 s |

Both useful runs reported **zero unnecessary refusals, zero provider calls and
zero cost**. Incomplete or denied sessions do not earn success; unnecessary
refusals remain ungraded for those sessions. Timings are local session durations,
not measurements against an unprotected baseline. Required noninteractive
approval prevented launcher startup; cancellation after native Nmap started
reaped its descendants and owners. Both new useful reports replayed unchanged,
and all **27 accepted B1–B8/service-web bundles** replayed with identical report
content and unchanged bytes, mtimes and modes.

Private receipts are under `.secure-agent/configurable-owned-20261006/` in the
primary checkout: `configurable-linux-reviewed.xml`, `regression-linux-results.xml`,
`native-reviewed/`, `accepted-replay.json`, `portable-results.xml` and the current
`handoff.json`/`verification.json` receipts.
Development failures are retained: an empty header descriptor-list bootstrap
issue was fixed, and the initial Linux test assertion incorrectly assumed SSH
stdout began with the key rather than its legitimate banner. Those failed runs
are not final acceptance evidence. No live model, real-network, authenticated
service or personal walkthrough acceptance is claimed.

PR #47 was separately reviewed and merged as `fc477d0`, matching its reviewed
tree; all five final checks passed. Post-merge checks passed on attempt 2 after
a macOS test-peer lifetime race. This slice fixes only that fixture lifetime,
retaining exact rejection/kill assertions and descendant cleanup behavior.

## Owned Nmap service → ffuf → headers workflow — 6 October 2026

Implementation `a1a186bdf2b1d42059716365de80abae9e0cd723`, based on accepted
main `0d5cbdc`, adds one separate shared-lab workflow in
[PR #47](https://github.com/0xsl0th/recon-cockpit/pull/47). Existing capability
parameters, executable arguments, parsers and catalog recipes remain unchanged.
Complete HTTP identification gates finite discovery; complete non-wildcard portal
evidence gates the final fixed header GET. Both executable manifests are pinned
before execution. Admission, launcher, backend and native/owner phases enforce
the ordered profile and cumulative limits independently.

The complete portable run passed **8,776 tests**, with 771 integration cases
intentionally deselected and no selected failures, errors or skips. Linux
validation passed **128 distinct cases**: nine new workflow/authority cases and
119 affected existing Nmap, ffuf, headers, admission and launcher regressions.
Independent CLI/evidence and runtime/authority reviews found no blockers; their
973- and 991-test focused runs overlap the full suite. Hosted CI is portable;
these native enforcement results are local Linux evidence.

| Clean-source owned case | Useful outcome | Actions | Requests / connections | Combined output bytes | CLI process wall time |
| --- | --- | --- | --- | --- | --- |
| Vulnerable | `gaps_observed` | 3/3 | 10 / 11 | 4,113 | 7.589 s |
| Corrected | `reviewed_headers_present` | 3/3 | 10 / 11 | 4,238 | 7.660 s |
| Injected metadata | `gaps_observed` | 3/3 | 10 / 11 | 4,377 | 7.590 s |

Useful completion was **3/3 workflows and 9/9 actions**, with **zero unnecessary
refusals**. All **18/18 deliberate forbidden-IP/port witness attempts** were
blocked; none reached an unauthorized destination. Every retained result reports
its required enforcement checks, and all three labs closed with matching totals.
The injected ffuf artifact retains the hostile Content-Type parameter in its
line-delimited JSON; normalized observations and fixed follow-up actions exclude
that instruction. Raw tool/header reparsing and read-only report replay matched.
All **24 accepted B1–B8 bundles** also replayed without changing bytes or mtimes.

Actual provider calls and cost were **zero**. No real credentials were read or
live integration enabled. Timing includes local CLI startup and the secure path;
the internal `elapsed_ms` values are 7,101, 7,154 and 7,094 respectively. There is
no comparison arm, so neither measure establishes authority overhead. This is
deterministic hostile-content handling, not evidence of model susceptibility or
an induced out-of-scope proposal. Header observations do not prove exploitability.

Validation used an explicitly unattended synthetic policy; the shipped policy
still requires fresh personal approval for each action. Automated witnesses and
negative approval tests do not constitute an operator rehearsal or acceptance.
The initial native fixture rejected Nmap's first empty TCP reset. The fix permits
only that first reset before any application bytes; partial/later resets and
other errors still fail closed. Negative fixture tests cover that distinction.
The first combined Linux receipt retains one test-only failure from treating
ffuf NDJSON as one JSON document; all nine new Linux tests subsequently passed.
Two auxiliary-verifier assertion errors (parameter-map indexing and assuming
empty ffuf diagnostic output) are also retained separately. They required no
production changes and do not count as final validation.

Private evidence is `.secure-agent/service-web-20261006` in the primary checkout:
`verification.json`, `validation-summary.json`, archived `verification-script.py`,
`validation/`, `runs/<case>/evidence`, retained `development/` failures and the
latest `handoff.json`. Hashes and runtime commitments establish local consistency,
not host-owner tamper resistance. [The runbook](service-web-assessment.md) states
scope, commands, completion criteria and report limits. The workflow is open for
review; B0–B8, offline R5 and accepted local R6 remain closed. Credentials, paid
calls, live-model evaluation, optional tools and broader benchmarking remain deferred.

## PR #46 catalog acceptance — 6 October 2026

[PR #46](https://github.com/0xsl0th/recon-cockpit/pull/46) merged at 02:24:31 UTC
as `0d5cbdc67b87cb2c8fc43522dfbe86e59e875352` after fresh review of `ef1cadb`.
The reviewed and merged tree is `705d6866c9a2dfe61ce081cbbd629fe75c1edf89`.
Fresh reviews found no blockers; 213 focused tests passed and all 19 saved dry-run
bundles replayed unchanged. All five [final PR checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37403185851)
and all five [post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37403977730)
passed. The catalog is accepted; preserve its recipes and inert behavior.
Private merge receipt: `.secure-agent/pr46-merge-review.json`.

## Read-only secure-tool catalog — 6 October 2026

Implementation `8abb502df13f75530babba4cb6e110b079cb5808` adds `--list-tools`
and `--describe-tool TOOL_ID`. The catalog derives identity/schema/profile/parser
metadata from the registry and exact recipe actions from existing pure contracts.
A reviewed mapping supplies executable families, normal selectors, policies,
runbooks and report caveats. All 20 accepted capabilities and 11 external programs
are represented; shared TCP/HTTP examples produce 19 distinct recipes.

The new CLI branch returns before policy, audit, evidence or execution handling.
Every explicitly supplied non-catalog option is rejected, including policy/audit
values equal to defaults and abbreviated execution flags. Listing/describing does
not inspect host prerequisites or read credentials. Tests run the catalog from an
empty working directory without installed tools, check a non-Linux platform and
use a fresh-process guard against runtime imports, user-data reads, networking,
process launch and file writes. The catalog is descriptive and cannot grant
execution authority.

Validation passed the complete **8,399-test portable suite**, with no failures,
errors or selected skips, in 243.50 seconds. The 762 integration cases were
intentionally deselected. This includes **213 new catalog cases** (66 contract
and 147 CLI cases); the earlier 503-case focused CLI regression run overlaps the
complete suite. Python 3.11 grammar, dependency consistency, local documentation
links and `git diff --check` also passed.

On the same clean implementation, all **19/19 distinct generated recipes** ran
through the existing isolated Linux path with their shipped approval-required
policies, all seven gates and explicit `--dry-run`. They completed as dry runs,
recorded zero successful actions, remained inconclusive with
`dry_run_has_no_execution_evidence`, and produced no tool result artifacts.
Every saved bundle independently replayed without integrity issues or changes
to bytes, modes or mtimes. No personal approval was requested or synthesized.
These checks validate recipes and isolated preparation/evidence behavior; they
are not new native tool executions or comparative performance measurements.
Actual B0–B8 execution evidence remains in the accepted records below.

Private receipts are in `.secure-agent/tool-catalog-20261006` in the primary
checkout: `validation/portable.xml`, `validation-summary.json`, the archived
`verification-script.py`, `recipe-verification.json` and `runs/<tool>/evidence`.
The portable JUnit SHA-256 is
`e79cb3fcdc0beb5dadcf4225c884b003e816be796cce92770c05ae5dcf4588ed`;
the verifier SHA-256 is
`fb9d7102783e6c5313606fa6c6a0e00462115f30c90c7d41d97449dae18449e5`.
Local hashes detect inconsistency, not host-owner tampering. Final review and
hosted-check outcomes are recorded in the PR and private handoff; PR #46
subsequently accepted the catalog as recorded above.

No accepted action, policy, workflow card, parser, executable/runtime profile,
lab fixture or evidence format changed. The other production change is the
catalog CLI branch and updated help. Credentials, paid calls and live-model
work remain deferred; live/paid model calls and actual cost were zero. The shared
TCP/HTTP dry run still records an existing offline simulated broker exchange;
this is not a claim of zero local planner/provider activity. Deeper workflow and
benchmark work, optional tools, accepted R5/R6 scope and the proposal/PDF remain
outside this slice. See [the catalog runbook](secure-tool-catalog.md).

## PR #45 acceptance and coverage closure — 6 October 2026

[PR #45](https://github.com/0xsl0th/recon-cockpit/pull/45) merged as `47d70a2`
at 01:59:42 UTC after fresh review of `9edec213`. The reviewed and merged trees
are identical (`8e08e6db6420c81b1880e815eaf8639d6ce53768`). All five
[final PR checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37401053840)
passed, as did all five
[post-merge main checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37401942532).
No outstanding review comments or blockers remained at merge.

Fresh runtime/authority review passed 1,338 focused portable checks and verified
35 recomputed policy-denial scenarios through both admission and launch
consumption, without reservations. Independent parser/evidence review passed
998 focused portable checks and replayed all 24 saved B1–B8 bundles with matching
reports, no integrity issues and unchanged bytes, modes and mtimes. These focused
runs are overlapping review checks, not additions to the 8,186-test portable suite
or the 252 distinct selected Linux cases recorded below. Actual native runs were
already validated on the unchanged implementation; the final revisions only
corrected documentation.

The private merge receipt is `.secure-agent/pr45-merge-review.json`; the B8
`handoff.json` now records `accepted_merged`. B0–B8 are closed under the
[explicit G1–G6 reconciliation](secure-tool-coverage.md#gate-reconciliation--accepted-b0b8),
with 20 capabilities and 11 external programs. Kerbrute results remain untrusted
client reports, not verified account facts. The read-only catalog is a separate
follow-on; accepted profiles, offline R5/local R6 and proposal/PDF stay unchanged.

## B8 synthetic Kerberos coverage — 6 October 2026

[PR #44](https://github.com/0xsl0th/recon-cockpit/pull/44) accepted B7 at `fcb9419`
after fresh review of `f81c444`; its merge tree matches the reviewed revision.
All five [final checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36965365612)
and all five [post-merge checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/36966387286)
passed. Fresh reviews passed 1,147 runtime/policy and 836 parser/evidence tests;
twelve additional recomputed-policy cases confirmed GET enforcement. All 21
B1–B7 bundles replayed unchanged. Private merge receipt:
`.secure-agent/pr44-merge-review.json` in the primary checkout. B7 stays closed.

B8 was implemented and lab-verified in [PR #45](https://github.com/0xsl0th/recon-cockpit/pull/45);
its subsequent acceptance is recorded above. The clean implementation
revision is `de40f283a449a639f299a4d4ed7f4fb685b99186`. The separate
`kerbrute_userenum_v1` capability queries only two compiled synthetic names against
an error-only owned KDC. The candidate brought main from 19 capabilities/10
programs to 20/11 when accepted. All 77 accepted B1–B7 specs, cards,
descriptors and actions remain exact; an aggregate regression pins their hash to
`d52fefa1868fb80d2b632c5d246e64350d8e6ba833c16083a112b09d9c3a0cae`.
See [the runbook](kerberos-tools.md) for the bounded invocation and limitations.

### Actual native behavior and metrics

| Scenario | Structured result | Connections / validated AS-REQs | Meaning |
| --- | --- | --- | --- |
| Normal | Tool reports exists, unknown | 2 / 2 | Complete finite reporting task. |
| All unknown | Tool reports unknown, unknown | 2 / 2 | Complete finite reporting task, no authenticated absence claim. |
| Spoofed error text | Tool reports unknown, unknown | 2 / 2 | Native error-string ambiguity demonstrated; not verified negative discovery or successful injection detection. |
| Denied, generic hostile, malformed | Inconclusive despite native exit zero | 2 / 2 each | Complete valid reports are required before useful work is counted. |
| Stalled | Timeout, inconclusive | 1 / 1 | Five-second native deadline and cleanup enforced. |

The two legitimate clean-source reporting tasks completed **2/2**, with **zero
unnecessary refusals**. The separate spoof trial demonstrated the known ambiguity
**1/1**. All three clean trials closed their labs and independently reparsed and
replayed their evidence without changing bytes or mtimes. All **6/6** explicit
forbidden-IP/port witness attempts were blocked, with zero unauthorized destination
successes. No provider call, cost, live integration or real credential read occurred.

Clean-source CLI times were **2,982 ms normal**, **2,854 ms all unknown** and
**2,875 ms spoof**. These local timings include secure infrastructure, under
concurrent development validation; they are descriptive, not an authority-overhead
benchmark. Complete normal output is 649 bytes; all-unknown and spoof output are
654 bytes, with empty stderr. Each action retains the 8,192-byte combined cap,
one-action/60-second session, fixed endpoint and two-request ceiling.

The four-file runtime totals 11,406,848 bytes, with digest
`be1306080d3125bae70b8ab9e50eb730c464e5f6b190827facddd39c959edd0d`.
The B8-only launcher tag permits a 2 GiB virtual address-space ceiling; the native
worker retains sixteen tasks, 64 descriptors, zero filesystem writes and
`GOMAXPROCS=1`/`GOMEMLIMIT=64MiB`. Actual negative kernel tests confirmed widened
UDP permission and a widened task cap trigger their production witnesses before
exec, and both normal/Kerberos launcher-tag substitutions stop before reservations.
No prior tool's limits or authority were expanded.

### Validation and retained receipts

The complete hosted suite passed **8,186 portable tests**. Local receipts cover
8,162 full-run passes and 584 final focused passes; twelve parametrized fixture
case IDs changed when empty PA-DATA support landed, so their raw ID union must
not be counted as additional distinct tests. Local validation also passed
**252 distinct Linux tests**, with no selected failures,
errors or skips. The Linux union is 11 B8 workflow/gate/cleanup tests, four
additional B8 kernel tests and 237 accepted-tool/launcher regressions. The latter
includes all 77 accepted B1–B7 native scenarios. Pytest emitted only the known
JUnit `record_property` compatibility warnings.

| Receipt | Passing cases | SHA-256 |
| --- | --- | --- |
| `validation/portable.xml` | 8162 | `5e87ab22011e03848334ea2ccf2afb0fe3f03e5813ea24833bafd75e6268f09a` |
| `validation/final-focused.xml` | 584 | `4968ef31e491b8787dcc72061bc4576c3ded7faaec3ba888abb5fc13a001c2cc` |
| `validation/b8-linux.xml` | 11 | `fa70a7c0e933bd6c0114e2662623db2de27cedcc4e47ce84de37351f64340a7c` |
| `validation/b8-extra-linux.xml` | 4 | `dc318c581a724ad55ddfb08749f5b6cc043a6d4ff510e28a52d5d9c55f3f4289` |
| `validation/regression-linux.xml` | 237 | `0f84395e6567a5abc5b83bab795f0250d36de96e3671152ea3cd875d58a52c0a` |

Python 3.11 grammar validation, dependency consistency, local Markdown-link
checks and `git diff --check` passed. Hosted PR checks run the complete portable
suite on Linux Python 3.11–3.14 and macOS Python 3.14; final CI status is recorded
in the PR and the private handoff, separately from local kernel evidence. The
[first completed final-code CI](https://github.com/0xsl0th/recon-cockpit/actions/runs/37400333462)
passed all five jobs at `7c65170`; the subsequent correction changes only
documentation counts. All five final checks passed at `9edec213` before the
authorized merge recorded above.

Independent reviews covered runtime/launcher, fixture, parser, authority,
counters, evidence and current documentation with no remaining blockers. Actual
Kerbrute output matched the strict parser in every scenario. The spoof and genuine
unknown logs differ only in timestamps/elapsed time: the normalized observation
therefore keeps `semantics: tool_report_only` and `authentication_verified: false`.
The Markdown report carries the same caveat and both per-principal reports.

Private evidence remains `.secure-agent/kerberos-tools-20261002` in the primary
checkout; its name records when work began, with final validation on 6 October.
`verification.json`, the archived `verification-script.py`, validation JUnit/logs,
review receipts and `runs/<case>/evidence` contain the exact source and artifacts.
The verifier hash is
`180e2a7e30dcbad9ea70d651e57511a62a02bf8c46ea9c0ec6b0db2b4c25bdb6`.
It replayed all 21 accepted B1–B7 bundles unchanged. These files remain local and
ignored by Git; automated unattended grants are explicitly synthetic test
instrumentation, not human acceptance or reusable approval.

Two initial development failures remain retained: Go could not reserve memory
under the inherited 256 MiB launcher cap, and the strict KDC initially rejected
the serializer's exactly empty PA-DATA container. The fixes are scoped to B8's
checked launcher tag and acceptance of omitted/exactly empty PA-DATA; credential
entries remain forbidden. Two failed kernel-test instrumentation receipts are
also retained separately from the final passing tests. No failed or skipped run
is counted as completion.

B8 subsequently passed G6 and closed the finite coverage milestone, as recorded
above. Optional tools, deeper workflow composition, comparative benchmarking,
model credentials, paid calls and live evaluation remain deferred during the
read-only catalog follow-on.
The accepted offline R5/local R6 and proposal/PDF remain unchanged.

## B7 finite Nmap service identification — 2 October 2026

B6 was accepted by [PR #43](https://github.com/0xsl0th/recon-cockpit/pull/43) at
`02a7d7f`; all five final and post-merge checks passed. Fresh independent reviews
passed 1,267 runtime/policy tests and 854 parser/evidence tests. All eighteen
saved B1–B6 bundles replayed unchanged, and the merged tree exactly matches the
reviewed revision. Completed milestones remain closed.

B7 is implemented and lab-verified in [PR #44](https://github.com/0xsl0th/recon-cockpit/pull/44),
pending review/merge. It adds a separate `nmap_service_identify_v1` capability through the existing
single-action secure network-tool path. See [the runbook](nmap-service-tools.md)
for fixed probes, output semantics and the explicit NSE suppression review.
The accepted TCP-only Nmap profile and all 71 B1–B6 definitions remain unchanged.
Main has 18 accepted capabilities/10 external programs; this candidate adds one
capability backed by the same Nmap executable family, pending review and merge.

Actual confined Nmap 7.95 runs, through all seven launch gates, observed:

| Owned case | Result | Accepted connections | Metadata events |
| --- | --- | --- | --- |
| HTTP | `http`, advertised nginx `1.26.0` | 2 | 1 fixed GET |
| SSH | `ssh`, advertised OpenSSH `9.7` | 2 | 1 banner reply |
| Unknown | Unidentified by the finite probe set | 2 | 1 fixed GET |
| Hostile text | Unidentified; fingerprint text excluded from findings | 2 | 1 fixed GET |
| Malformed service bytes | Unidentified; no service identity invented | 2 | 1 fixed GET |
| Silent service | Unidentified after bounded probe wait | 2 | 1 fixed GET |

Each completed XML capture is 1,376–1,621 bytes with empty stderr, all ten native
boundary witnesses true and a closed owned lab. These results do not distinguish
the causes of nonmatching responses or prove absence, harmlessness, authenticated
identity, installed software versions or vulnerabilities. The fixture has no
login, application backend or external egress. No provider/paid call occurred.

Review and actual execution resolved four issues before handoff:

- Nmap normalizes absent script arguments to an empty string. The pinned shim
  now requires that exact value, retaining all script/rule/phase restrictions.
- Nmap requires `tcpwrappedms` of at least 100 ms; the finite probe file now
  meets that bound. The earlier 50 ms trial failed before service probes.
- Evidence reports explicitly preserve identified versus unidentified outcomes.
- The owner rejects a second metadata operation before request dispatch, while
  preserving the allowed empty scan/NULL-probe reconnect sequence.

The initial failed trials remain private development evidence. They are not
counted as useful completion. Independent reviews checked runtime/filesystem
closure, parser, authority, counters, evidence and documentation. No remaining
blocker was found. Native Lua tests exercise the actual suppression shim;
script arguments, scripts and broader scan phases are rejected.

Local portable validation passed **7,799 distinct tests**: a complete 7,761-test
run plus 38 added B7 evidence checks in the final focused run (368 passed,
including repeated existing cases). There were no selected skips, failures or
errors. Tests cover rehashed invented identities, altered XML scope, missing
runtime/closure/artifact evidence, parser custody and dry runs. Syntax checks
passed for 357 Python files using Python 3.11 grammar; dependency and whitespace
checks passed. All ten targeted B7 Linux workflow/gate/cleanup tests passed.
The remaining 287 Linux checks also passed: 71 accepted network workflow cases,
64 network enforcement cases, 140 affected legacy launcher/web/Nmap cases and
12 actual Lua suppression-shim checks. Together these are **297 distinct Linux
tests**, with no selected skips/failures/errors. The private JUnit receipts and
`validation-summary.json` record counts, hashes and durations.

Clean source `5120dccb2bb527ce0e3490f5643b37e4b2543d90` completed three final CLI
trials with all seven gates: **2/2 identified tasks**, **1/1 honest unknown-response
task**, zero unnecessary refusals and six of six forbidden-destination witnesses
blocked (zero unauthorized destination successes). Every trial used two accepted
connections and one metadata event, produced matching independently replayed
raw/normalized evidence and closed its lab. All eighteen accepted B1–B6 bundles
replayed without changing bytes or mtimes. `verification.json` binds the clean
source and archived verifier. The final handoff commit changes documentation only.

| Final trial | CLI elapsed | Result |
| --- | --- | --- |
| HTTP | 3,262 ms | Identified HTTP/nginx `1.26.0` |
| SSH | 2,859 ms | Identified SSH/OpenSSH `9.7` |
| Unknown response | 3,281 ms | Unidentified by the reviewed probes |

Latest-revision hosted checks must pass before an authorized merge. B7 remains
review-pending rather than accepted main coverage.

Private receipts are under `.secure-agent/nmap-service-tools-20261002` in the
primary checkout, including `review.json`, `handoff.json`, `debug/` and
`validation/`. Raw captures and audit records stay local. Automated grants are
synthetic test instrumentation, not operator acceptance. Trial times are
descriptive CLI wall time, not a comparative authority-overhead benchmark.

B8 synthetic Kerberos principal enumeration with an owned KDC remains the next
required coverage gap. Deeper workflows and comparative benchmarking stay
deferred until required coverage is complete. Model credentials, paid calls,
live evaluation and proposal/PDF changes remain deferred until much later.


## Secure coverage B6: Docker health/version and WinRM endpoint metadata — 2 October 2026

PR #42 was reviewed and merged as `38cbd43`; all five final PR checks and all
five post-merge main checks passed. The merge tree exactly matches reviewed head
`b682b3c`. Fresh runtime/fixture and parser/evidence reviews passed 549 and 641
focused tests, validated all four B5 artifacts and replayed nine prior bundles
unchanged. Keep B0–B5 accepted. B6 implements three independently invoked curl
profiles: `curl_docker_ping_v1`, `curl_docker_version_v1` and
`curl_winrm_metadata_v1`. See [docker-winrm-tools.md](docker-winrm-tools.md).
Main remains at 15 accepted secure capabilities backed by 10 external programs;
accepting B6 would bring those counts to 18 and 10. [PR #43](https://github.com/0xsl0th/recon-cockpit/pull/43) is the review handoff;
B6 still requires review and an authorized merge.

Each profile fixes one HTTP/1.1 GET to `127.0.0.1:8080`: `/_ping`, `/version` or
`/wsman`. The two Docker endpoints are separate capabilities, preserving the
single-request/action contract. Policy must explicitly allow GET as well as the
fixed tool, target and port. Curl imports no host configuration or credential,
uses no proxy or retry and does not follow redirects. No Docker socket, daemon,
container backend, SOAP implementation, authentication exchange or remote session
exists in the owned fixture. Native memory/process/file/network limits remain
unchanged.

Actual curl preserves complete response framing on stdout with empty stderr in
normal cases. Ping returns HTTP 200 and `OK`; version returns bounded JSON fields.
A complete empty JSON object establishes only that this response has no reviewed
version fields. WinRM's HTTP 401 advertises Negotiate/NTLM without attempting
login; its HTTP 405 response with no challenges does not prove authentication is
disabled. All useful cases use one accepted connection and one validated GET.
The closed response shapes establish synthetic endpoint metadata, not genuine
Docker/WinRM identification, general service compatibility or professional
engagement readiness.

All six forbidden-IP/port redirect scenarios retain raw HTTP 302 evidence and
remain inconclusive; curl never follows them, and the forbidden witnesses receive
no connection. These are client redirect-refusal checks, separate from the native
kernel destination witnesses. Hostile metadata cannot grant authority or become a
finding. Failed, malformed, stalled and truncated output cannot invent useful
results or absence; zero process exit alone is insufficient. Real oversized-header
capture, cancellation, fresh-grant consumption/replay denial, missing-proof
refusal, private-file isolation and teardown were exercised for all three profiles.

Two implementation findings were resolved before handoff. Initial native attempts
failed closed before tool execution because the owner-only fixture imported its
sibling by name under isolated Python. It now uses the existing explicit file-loader
pattern, with a portable `python -I -S` regression outside the repository. Final
review also required the B6 fixed GETs to honor the policy method list, matching
existing ffuf behavior: empty/HEAD-only policies deny and POST-only remains invalid.
Recomputed launch commitments without GET also deny. Independent runtime/fixture,
parser/evidence and final policy reviews found no remaining blockers. All 50
B1–B5 specifications, cards, descriptors and actions remain byte-identical.

The native suite passed **71 network workflow**, **64 network enforcement** and
**140 affected legacy** checks: **275 distinct selected Linux checks**, with no
selected skips, failures or errors. All **36 B6 cases** (21 protocol and 15
enforcement) were rerun successfully after the explicit-GET policy change; these
are repeats within the 275, not extra distinct tests. Legacy checks cover the
shared owner/admission/launcher and existing HTTP/header, Nmap, curl and ffuf paths.
The complete final-source portable suite passed **7,444 tests** without selected
skips, failures or errors; its receipt is `validation/portable-final.xml`. The
earlier pre-policy-tightening run is retained separately. Python 3.11 syntax,
dependency consistency, local documentation links and whitespace checks passed.

Clean-source execution at `1e58600781ca4e98b6a72952d15808f7787b0e9d` completed
**5/5 legitimate tasks**, with **zero unnecessary refusals**, closed owners,
independent raw reparsing and identical read-only replay. Docker ping took 2.791
seconds; version normal/empty took 2.896/2.860 seconds; WinRM challenge/no-auth
advertisement trials took 2.773/2.810 seconds. Each used one connection and GET.
All thirteen accepted B1–B5 bundles replayed identically without changing file
bytes or modification times. `verification.json` records exact source, runtime,
action/policy/artifact bindings, raw hashes, counters, timings and compatibility.
These five synthetic correctness trials are not a statistical service-coverage
or comparative performance claim.

Private receipts are under `.secure-agent/docker-winrm-tools-20261002` in the
primary checkout. JUnit files are in `validation`; `linux-validation-summary.json`
records counts, digests and timings. Initial failed bootstrap captures remain
under `debug` and are not acceptance evidence. Hosted checks must pass on the
latest PR revision before a later authorized merge. Automated test grants are
synthetic validation, not human approval or local-release acceptance. Provider
calls and actual provider cost remain zero. Descriptive CLI elapsed times are
not comparative security overhead measurements.

B7 bounded Nmap service identification is next because the accepted TCP-only
profile does not identify a service; review and pin its finite probe/NSE behavior
before enabling it. B8 synthetic Kerberos enumeration and its owned KDC follow.
Deeper workflows and comparative benchmarking stay deferred until required
coverage is complete. Model credentials, paid calls and live-model evaluation
remain deferred until much later. Offline R5/local R6 and the separate proposal/PDF
remain closed.

## Secure coverage B5: anonymous FTP listing and SMTP capabilities — 2 October 2026

PR #41 was reviewed and merged as `6623aa0`; its five final PR checks and five
post-merge main checks passed, and its merge tree matches reviewed head `670c891`.
B0–B4 remain accepted. B5 adds `curl_ftp_list_v1` and
`curl_smtp_capabilities_v1` through the existing secure execution/evidence path.
See [ftp-smtp-tools.md](ftp-smtp-tools.md). This candidate is lab-verified and
pending review in [PR #42](https://github.com/0xsl0th/recon-cockpit/pull/42) and an authorized merge. Main remains at 13 accepted secure
capabilities backed by 10 programs; accepting B5 would yield 15 capabilities
backed by the same 10 programs.

Both actual native clients are curl with fixed arguments and no host configuration,
credentials, proxy or retry. FTP uses a fixed public anonymous identity and one
NLST; control and passive data share the predeclared `127.0.0.1:8080` listener.
No firewall endpoint is added, and active mode/EPSV are disabled. The complete
native control transcript through `226` is retained on stderr and names on stdout.
SMTP records greeting/EHLO replies and QUIT on stdout. Curl's harmless HELO
fallback after a rejected EHLO was observed; that refusal cannot prove useful
capability discovery. The fixture has no file or mail backend.

Normal and empty FTP cases each use two accepted connections and one validated
NLST. Normal and no-extension SMTP cases each use one connection and one EHLO.
Empty results require complete native success framing. Hostile text is preserved
only in raw evidence and leaves the result inconclusive. Denied, malformed,
partial and stalled replies likewise cannot prove absence. Both forbidden FTP
passive destinations (IP and port) are blocked by the unchanged kernel filter;
no forbidden witness receives a connection and no NLST is recorded. Native
output pressure, cancellation and cleanup retain existing bounds. Process exit
zero alone never counts as useful completion.

Independent runtime/fixture and parser/evidence reviews found no remaining
blockers. They identified and corrected a replay counter mismatch: normalized
FTP listings now independently require two connection receipts, and denied or
forbidden-passive cases require zero listing requests. Tamper tests cover those
counters, channel swaps, stripped final replies despite rehashing, fabricated
metadata, missing runtime commitments and old-card relabeling. All 36 accepted
B1–B4 fixture specification encodings remain byte-identical; existing cards,
policies, runtime bounds and capability identities remain unchanged.

Validation passed **6,755 portable tests**, **50 real network workflow cases**,
**49 network enforcement cases**, and **140 affected legacy Linux tests**:
**239 distinct selected Linux checks** in total, with no selected skips, failures
or errors. The native selection includes 14 new B5 protocol cases and 10 new B5
enforcement cases. Legacy checks cover shared owner/admission/launcher and existing
HTTP/header, Nmap, curl and ffuf profiles. Python 3.11 syntax, dependency
consistency, local documentation links and whitespace checks passed. The private
JUnit receipts are `validation/portable.xml`, `workflow-linux.xml`,
`enforcement-linux.xml` and `legacy-linux.xml`; `validation-summary.json` records
their counts, durations and digests. Hosted checks must pass on the final PR
revision before a later authorized merge.

Clean-source execution at `e3f5056ce86ceb055a20c22fd908c2f9a52fc612` completed
**4/4 legitimate normal/empty tasks**, with **zero unnecessary refusals**, closed
labs, independent raw reparsing and matching read-only replay. FTP normal/empty
CLI times were 2.876/2.866 seconds; SMTP normal/empty times were 2.908/2.846 seconds.
All nine accepted B1–B4 bundles (including B4's two empty results) replayed exactly,
without changes to file bytes or modification times. Provider calls and actual
provider cost were zero. `verification.json` records exact source, runtime/action/
policy/artifact bindings, counters, digests and compatibility receipts.
The first receipt helper failed on the report's intentionally omitted rationale;
it was corrected to reconstruct the exact deterministic proposal and verify its
digest. That initial successful native capture is preserved in
`debug/clean-verifier-attempt-1`; application code did not change.

Private evidence is under `.secure-agent/ftp-smtp-tools-20261002` in the primary
checkout. Development captures remain under `debug`; they are not clean-source
acceptance receipts. No real credentials, external targets, provider calls, paid
calls or live-model evaluation were used. Automated test grants are synthetic
validation, not human acceptance. Local CLI wall times are descriptive correctness
measurements, not comparative security overhead. The topology and closed parser
vocabulary establish finite synthetic-lab support, not general FTP/SMTP service
compatibility or professional engagement readiness.

B6 Docker/WinRM metadata is next because it fills missing service families while
reusing existing curl/HTTP infrastructure and interactive suggestions. B6–B8
remain required; deeper workflows and comparative benchmarking wait for the full
coverage milestone. Model credentials and paid evaluation remain deferred until
much later; offline R5/local R6 and the separate proposal/PDF remain closed.

## Secure coverage B4: RPC registrations and NFS export metadata — 2 October 2026

The base is merged main `775352e` (PR #40). B0–B3 remain accepted. B4 adds
`rpcinfo_dump_v1` and `showmount_exports_v1` as independently invoked, bounded
native profiles through the existing policy, approval, audit, admission, launcher,
networkless parser and evidence path. See [rpc-nfs-tools.md](rpc-nfs-tools.md).
[PR #41](https://github.com/0xsl0th/recon-cockpit/pull/41) remains pending review
and an authorized merge; B5 FTP/SMTP is the next gap.
Main still has 11 accepted capabilities backed by 8 external programs; this
candidate would bring those counts to 13 and 10 after acceptance.

The real clients require fixed rpcbind discovery before their metadata query.
Both contact only the preauthorized TCP `127.0.0.1:111`; the synthetic service
multiplexes discovery and MOUNT export metadata at that endpoint. The fixture
caps connections at four, calls at eight, discovery calls at three and the
metadata query at one. Minimal transport and service-name tables are compiled,
hashed and sealed; host RPC configuration is absent. The fixture owner receives
`CAP_NET_BIND_SERVICE` solely to bind its private listeners and drops all
capabilities before service startup. The clients receive no extra capability.
All existing native memory/process/file/output bounds remain intact.

Native normal and empty RPC/NFS runs each use two accepted connections and one
validated DUMP or EXPORT. Empty RPC prints an explicit no-programs result; empty
NFS prints its complete export header with no rows. Malformed replies instead
exit unsuccessfully with decode diagnostics, so they cannot establish absence.
RPC advertisement of port 112 is retained as numeric metadata without a follow-up.
An injected NFS access-group string is retained only in raw evidence and the
result stays inconclusive. When discovery advertises port 112, the native client
times out: the forbidden witness receives no connection, and no export query is
counted. Stalls, output pressure and cancellation retain bounded cleanup.

Independent fixture, runtime, parser and evidence reviews found no blockers.
The complete portable suite passed **6,348 tests** with no selected skips, errors
or failures. All **36 network-tool workflow cases** and **39 enforcement cases**
passed, including the 11 new B4 protocol cases and 13 new B4 enforcement/staging cases.
The Linux-only memfd sealing check is explicitly classified as integration;
it must not skip inside the portable macOS matrix.
Another **140 affected legacy Linux checks** passed across the shared owner,
launcher, admission, HTTP/header, Nmap, curl and ffuf paths: **215 distinct Linux
checks** in total, with no selected skips, failures or errors. Python 3.11 syntax,
dependency consistency and local documentation links passed.

Clean-source execution at `a7b5d147ef37628912393ab76d6e81fa1a32cdc6` completed
**4/4 legitimate normal/empty tasks**, with **zero unnecessary refusals**, closed
labs and matching read-only replay. RPC normal/empty CLI times were 2.635/2.596
seconds; NFS normal/empty times were 2.620/2.558 seconds. Each used two connections
and one metadata request. All five accepted B1–B3 evidence bundles replayed
identically without changes to content or modification times. Private
`verification.json` records the implementation revision, report digests, tests
and compatibility receipts. Consult PR #41 for checks on its latest revision.

This establishes synthetic metadata coverage, not mounts, file access, general
NFS service coverage or professional engagement readiness. No credentials,
external targets, provider calls, paid calls or live-model evaluation were used.
Process success alone is not useful completion: malformed, hostile or unsupported
output cannot produce a normalized finding. Automated test grants are not human
acceptance. Local elapsed times are descriptive CLI timings, not comparative
security overhead measurements.

Private validation and clean-source receipts are under
`.secure-agent/rpc-nfs-tools-20261002` in the primary checkout. Development failures
are retained separately under `debug`; they are not acceptance evidence. The
coverage checklist stays open through B5–B8. Deeper workflows and comparative
benchmarking remain deferred, as do model credentials and paid evaluation.

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

## C1 Redis and SNMP secure metadata — 7 October 2026

C1 extends coverage after the accepted initial owned GUI in PR #54. It adds
`redis_server_info_v1` and `snmp_system_get_v1` through the existing seven-gate
CLI path, without changing older profiles or GUI workflows. The fixed Redis
RESP2 command is `INFO server`; SNMP performs one v2c TCP GET of three numeric
system OIDs with a public synthetic fixture community. No credential setup,
paid calls, external targets, UDP, writes, walks or deeper composition are added.

The implementation revision is `eb6775d`; final documentation records validation
separately. Private receipts are under `.secure-agent/redis-snmp-20261007/` in the
primary checkout. Raw transcripts, JUnit files and runtime hashes stay private.
The [runbook](redis-snmp-tools.md) describes invocation and limitations.

The complete portable suite passed **10,413 tests** in 312.118 seconds, with zero
failures, errors or skips (873 integration cases deselected). Hosted matrix checks
remain a separate PR gate. `validated-source-files.json` binds the tested source;
subsequent edits only document validation.

Actual Linux validation passed **63 tests** with zero selected failures, errors
or skips: **24 C1 cases** and **39 shared robustness regressions**. The C1 set
covers all 16 scenarios, real approval consumption and replay rejection,
missing-proof blocking, cancellation after the actual client starts, process
cleanup, and refusal before execution when a test broadens UDP socket creation.
The UDP negative test has an execution sentinel and sends no datagram traffic.

The 16 ordinary/adversarial scenario runs each used one accepted TCP connection
and one validated query, stayed within 8,192 output bytes and closed their lab.
All **32/32 forbidden IP/port witnesses** blocked, with zero unauthorized
successful destinations. All **16/16 evidence bundles replayed unchanged**.
The three ordinary reporting tasks (Redis metadata, SNMP metadata and explicit
SNMP noSuchObject) completed **3/3**, with **zero unnecessary refusals** and
elapsed times of **2,701 / 2,583 / 2,565 ms**, respectively. The two hostile
metadata cases also retained useful bounded results without follow-up authority;
they are separate from the ordinary usefulness denominator. Empty Redis output,
denial, malformed/oversized/stalled replies and Redis redirects stayed inconclusive.
Every trial used zero provider calls and zero actual provider cost. These are
local descriptive timings, not a comparative overhead measurement.

Golden regressions retain the accepted bytes for 84 older actions, capability
descriptors, workflow cards and lab specifications, 23 adapter descriptors, and
old invocations/environments/compiled inputs. The registry/catalog adds two
profiles from two programs: **25 accepted profiles / 13 external programs**
after PR #55. Completed B0–B8, offline R5,
accepted local R6 and the owner GUI walkthrough remain closed.

Development failures remain disclosed in the private `development-notes.json`:
initial mocks differed from native Redis newline/SNMP output framing; the first
report tests exposed a missing import and Redis field-order replay mismatch;
the first full portable run found four stale registry/subset expectations.
Those failures were corrected, not counted as successful evidence. SNMP strings
now use hex rendering and bounded printable decoding, so embedded newlines cannot
forge OID rows. Report rendering escapes service-supplied Markdown/HTML delimiters
and uses stable field ordering. Metadata and noSuchObject values remain explicit
untrusted service reports, not authenticated identity or vulnerability proof.

Three additional independent trials at clean revision `d914deb` completed 3/3
ordinary reports with zero unnecessary refusals, provider calls or cost, six of
six forbidden destination witnesses blocked and unchanged replay. Both CLI and
shared-service inspectors also replayed **30 previously accepted bundles unchanged**,
including accepted configurable/shared-service and personal graphical evidence.
Private receipt: `clean-source-d914deb4-s5dg5ugb/verification.json` under the C1
validation directory. Subsequent changes are documentation only.
[PR #55](https://github.com/0xsl0th/recon-cockpit/pull/55) was reviewed and merged
on 7 October. Reviewed head `8786308d8569979229b6e0019cdcd04a0811e252`
and merge `9786a6b4539ae2c1df9e63bff25f9ac0271ef759` have identical trees
(`a60ae6208e00ec7e875382ee62ac1346896d8d5b`). Independent authority/runtime
and parser/evidence reviews found no blockers. Fresh focused review sets passed
543, 540 and 597 cases respectively; these sets overlap and are not an additional
unique-test total. All five [final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37657264278)
and all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37658499228)
passed. No required-check rules were configured; the five portable matrix jobs
were used as the merge gate. Private merge receipt:
`.secure-agent/pr55-merge-review.json`. C1 is closed; do not repeat the merge.

## C2 PostgreSQL/MySQL pre-authentication TLS — 7 October 2026

This candidate extends the existing OpenSSL runtime with two fixed protocol
profiles. Each sends only the PostgreSQL SSLRequest or MySQL greeting/SSLRequest
preface, negotiates fixture-CA/name-verified TLS 1.3, and closes without application
data. It uses the accepted seven-gate authority path and one disconnected owned
endpoint, `127.0.0.1:8080`. No database credentials, login, SQL, real network,
plaintext downgrade, model provider or new GUI operation is added. The
[runbook](database-tls-tools.md) gives exact invocations and limitations.

Implementation revision: `dca814133cafdd08d916d2e93c12f9e66b11474e`, based on
accepted main `9786a6b`. Private records live under
`.secure-agent/database-tls-20261007/` in the primary checkout. All **476 tested
source/test/policy/workflow file hashes** matched the clean implementation after
validation; later documentation edits do not change those tested files.

| Validation | Actual result |
| --- | --- |
| Complete portable suite, `pytest -m 'not integration' --strict-markers` | **10,776 passed**, zero failures/errors/skips, 300.456 seconds |
| Selected actual Linux suite, `RECON_LINUX_INTEGRATION=1 pytest tests/test_secure_database_tls_workflow_linux.py tests/test_secure_network_tools_workflow_linux.py -k 'database_tls or openssl'` | **28 passed**, zero selected failures/errors/skips, 72.065 seconds |
| Twelve C2 ordinary/adversarial scenarios | All expected outcomes; **24/24** forbidden IP/port witnesses blocked, **120/120** boundary checks true |
| Ordinary PostgreSQL/MySQL TLS tasks | **2/2** useful completions; **zero unnecessary refusals** |
| Hostile MySQL greeting | **1/1** useful completion, kept separate from ordinary usefulness |
| Scenario evidence | **12/12** unchanged networkless CLI replays; one connection each, bounded output and closed owners |
| Independent clean-source verification | Three fresh trials; **6/6** destination witnesses blocked; **33 accepted bundles** replayed unchanged by both CLI and shared inspector |

The 28 actual Linux cases comprise **24 C2 cases and four accepted OpenSSL
regressions**. Beyond the twelve scenarios, C2 exercises grant consumption and
replay rejection, missing-proof blocking, cancellation after actual OpenSSL
execution, host-canary/descriptor isolation, refusal before execution when a
test broadens UDP socket permission, and real oversized-certificate diagnostics
hitting the output ceiling with unchanged evidence replay. The UDP negative
test sends no datagrams. Ordinary execution uses an explicitly unattended
synthetic policy; dedicated grant tests use synthetic approval inputs. Neither
claims new personal acceptance. The shipped policy still requires approval.

Only the two ordinary handshakes and hostile MySQL greeting record one completed
handshake. The other nine scenarios record zero, remain inconclusive and do not
fall back to plaintext or login. All twelve accept at most one TCP connection
and capture at most 8,192 bytes. Ordinary local secure-execution elapsed times
were **2,637 / 2,586 ms**; the hostile MySQL trial took **2,601 ms**. The two
stalled cases took 6,608 / 6,617 ms including setup, with the five-second native
deadline enforced. These are descriptive timings, not comparative overhead.

Independent trials at clean `dca81413` took **2,830 / 2,828 ms** for ordinary
PostgreSQL/MySQL, and **2,723 ms** for hostile MySQL. They checked exact action,
policy, runtime, raw-output, normalized-result, audit and owner-counter bindings.
The 33 accepted bundles were required by their previous receipt and report
hashes; none were omitted. Replay preserved bytes, modification times and modes.
Receipt: `clean-source-dca81413-6w256_ve/verification.json`. JUnit, source hashes,
scenario report hashes and the combined `verification.json` remain private.
Every trial used **zero provider calls and zero actual provider cost**.

Golden regressions preserve 100 older actions, capability descriptors, workflow
cards and lab specifications, all 25 old adapters, and all 16 older native
invocations/environments/compiled inputs. Independent source reviews found no
remaining blockers. The candidate has **27 profiles from the same 13 programs**;
accepted main is **27/13** after the reviewed merge below.

PR review exposed 15 macOS failures in hosted run `37662709531`: the new portable
MemoryBIO tests called the Linux owner's `memfd_create` certificate loader.
The correction loads the same public synthetic certificates through private
temporary files in the test helper, as the existing portable TLS tests do.
All 224 focused fixture/lab tests passed after correction. Certificate rejection,
TLS 1.3, clean shutdown and application-data rejection remain real in-memory TLS
checks on every runner; no tests are skipped. Production and native-test sources
are unchanged, so the 28 native results remain applicable. The original failure
log is retained privately. The corrected hosted checks passed before merge.

[PR #56](https://github.com/0xsl0th/recon-cockpit/pull/56) is accepted and C2 is
closed. Reviewed head `d072d04ad902cb3937548f6aa3a29ed680ccda59` merged as
`9603a54a105bfde6d7f2712445762b1b20236bcf` on 7 October at 18:07:54 UTC.
Both trees are `cbb982b4a07397c48d5c033dd8d49b5bda007e29`. Independent reviews
found no blockers, with 1,158 authority/runtime and 763 parser/evidence focused
tests passing; these overlapping sets are not an additional unique-test total.
All five [final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37663523544)
passed 10,776 tests each, and all five
[post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37664455704)
passed. No required-check rules were configured; all five portable jobs were
used as the merge gate. The private receipt is `.secure-agent/pr56-merge-review.json`.
Do not repeat the merge, broaden the accepted profiles or reopen completed milestones.

Results establish only `verified_tls_handshake_only` with
`authenticated_database_session: false`. The selected wire profile does not
prove database product/version, readiness, account access or a vulnerability.
OpenSSL may reject fragmented MySQL greetings; unsupported diagnostics remain
inconclusive. These synthetic fixtures contain no database engine or accounts.
Completed milestones stay closed. Next proposed coverage is bounded HTTP
application fingerprinting with a reviewed finite WhatWeb plugin allowlist;
deeper workflows, comparative benchmarks, credential setup and paid/live-model
evaluation remain deferred.

## C3 bounded WhatWeb HTTP fingerprinting — 7 October 2026

[PR #57](https://github.com/0xsl0th/recon-cockpit/pull/57) is accepted and C3 is closed.
Reviewed head `cf69f4ea1a9c26ec38811607d58ee021e79fd62f` merged as
`fdfe6e833799cdb15877c1314069af492d3d07d3` on 7 October at 18:53:30 UTC.
Reviewed and merged trees match `1ff0ce8b92cbd785e26cb2cd859311ee76ba6eba`.
Fresh independent authority/runtime and parser/evidence reviews found no blockers;
1,261 and 1,103 focused tests passed respectively, and all 494 validated source
hashes and receipt hashes matched. All five [final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37668578334)
passed 11,109 tests each; all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37670291745)
passed. No branch check rules were configured; all five jobs were the merge gate.
The private merge receipt is `.secure-agent/pr57-merge-review.json`.
Accepted main now has 28 profiles using 14 programs. Preserve the validation below;
do not repeat this merge or reopen completed milestones.

The candidate adds `whatweb_http_fingerprint_v1` through the existing single-action
CLI and all seven authority gates. Installed WhatWeb 0.6.3 runs with exactly five
passive plugin files, one GET of `/harbordesk/portal.html` at disconnected owned
`127.0.0.1:8080`, and a finite sealed Ruby 3.3 runtime. A compiled guard bounds
connections, wire requests, response input and regular-expression evaluation;
redirects, retries, linked resources, cookies and encoded-body expansion are
refused. The [runbook](whatweb-tools.md) records supported layout and limitations.

Implementation revision: `0bdd9b6324d3c10d1a426c51aaf491abdf51d92a`, based on
accepted main `9603a54`. All **494 source/test/policy/workflow file hashes** match
the validated implementation. Private records remain under
`.secure-agent/whatweb-20261007/` in the primary checkout; no raw assessment
evidence is committed.

| Validation | Actual result |
| --- | --- |
| Complete portable suite, `pytest -m 'not integration' --strict-markers` | **11,109 passed**, zero failures/errors/skips, 299.271 seconds; 914 integration cases deselected |
| Selected actual Linux suite | **39 passed**, zero selected failures/errors/skips, 156.861 seconds |
| Eleven C3 ordinary/adversarial scenarios | All expected outcomes; **22/22** forbidden IP/port witnesses blocked, **110/110** boundary checks true |
| Ordinary hints and no-hints tasks | **2/2** useful completions; **zero unnecessary refusals** |
| Hostile metadata and meta redirects | **2/2** useful completions, measured separately from ordinary usefulness |
| Scenario evidence | **11/11** unchanged CLI replays; exactly one connection/validated GET each, bounded output and closed owners |
| Independent clean-source verification | Four fresh useful trials, **8/8** destination witnesses blocked, **36 accepted bundles** replayed unchanged through CLI and shared inspection |

The native command selected `tests/test_secure_whatweb_workflow_linux.py` and
`tests/test_secure_network_tools_workflow_linux.py` with
`RECON_LINUX_INTEGRATION=1` and `-k 'whatweb or openssl or dig or kerberos or smb'`.
Its 39 cases comprise **17 C3 and 22 accepted regressions**. Beyond the eleven
scenarios, C3 tests consumed-grant replay denial, missing-proof refusal,
cancellation after actual Ruby execution, host-input/descriptor isolation, and
refusal before native execution when tests broaden UDP or task permissions.
The shipped policy requires fresh approval. Unattended synthetic policies and
synthetic grant tests do not claim new personal approval or acceptance.

Seven negative scenarios remain inconclusive: HTTP redirect, denial, malformed
framing, early EOF, stall, response-input pressure and native JSON output
expansion. Every one followed an actual validated GET; startup failure cannot
count as success. A native zero exit code alone does not count as useful work.
The output-pressure case reached `output_limit` while retaining only two bytes;
the ceiling is not a claim that 8,192 bytes were captured. No negative result
is upgraded into application hints or authority for another request.

Ordinary local secure-execution times were **4,169 / 4,139 ms**; hostile metadata
and meta redirects took **4,205 / 4,795 ms**. Independent clean-source trials took
**4,322 / 4,338 ms** for the ordinary pair and **4,313 / 4,537 ms** for robustness.
These are descriptive CLI wall times, including isolation setup, not comparative
authority overhead. Every trial used **zero provider calls and zero actual
provider cost**. The independent receipt is
`clean-source-0bdd9b63-949y69_c/verification.json`.

Independent trials checked exact action, policy, runtime, raw-output,
normalized-result, audit and owner-counter bindings. All 36 older bundles were
required by the accepted C2 receipt and report hashes; replay preserved their
bytes, modification times and modes. Golden tests retain all **112** older
actions/descriptors/workflow cards/lab specifications, **27** adapters and
**18** native invocations/environments/compiled inputs.

Preserved development failures include the first launcher's descriptor ceiling
while sealing the larger closure and two missing finite Ruby dependency files;
all occurred before requests and count as failures. The corrected profile uses
a separately checked outer-launcher tag with 256 descriptors; the executed Ruby
process remains limited to 64 descriptors, 256 MiB and 16 tasks. Accepted tools'
limits are unchanged. The first native run also exposed a test that conflated
exit status with useful completion; only its assertion changed before the final
39-case run. Shared test prefix mappings and legacy golden selectors required
updates: the first full portable run had 16 failures and 11,093 passes. Original
golden hashes/counts were preserved; 176 focused runtime and 184 fixture/lab
tests passed after the final test-only corrections. Failed logs remain private.

Independent source reviews found no remaining blockers. C3 brought accepted main
to **28 profiles using 14 programs** after the reviewed merge above.
Results mean `untrusted_application_hints`, not verified
products, installed versions or vulnerabilities. Empty hints are valid completed
observations, not proof of technology absence. Support is deliberately limited
to the reviewed Debian Ruby 3.3 x86-64 layout and five passive plugins.

Completed B0–B8, C1, C2, offline R5, accepted local R6 and initial GUI milestones
stay closed. Fixed TCP DNS SRV metadata with dig is the next coverage gap after
C3 acceptance. Model credentials, paid/live calls, real-network attachment,
deeper composition and comparative benchmarking remain deferred.

## C4 fixed DNS SRV service metadata — 7 October 2026

Review candidate: [PR #58](https://github.com/0xsl0th/recon-cockpit/pull/58).
Final hosted checks, PR review and an authorized merge remain acceptance gates.

This candidate adds `dig_dns_srv_v1` through the existing secure single-action
CLI and all seven authority gates. It reuses dig's exact 36-file runtime closure
and resolver/environment restrictions. One nonrecursive TCP question asks
`_ldap._tcp.harbordesk.test. IN SRV` at disconnected owned `127.0.0.1:8080`.
No returned target is resolved or contacted. The [runbook](dns-srv-tools.md)
defines the closed schema, fixed operation and limitations.

Implementation revision: `0c6dcf573b9792966deee492f667803e5dfaf960`, based on
accepted main `fdfe6e8`. All **502 source/test/policy/workflow files** are hashed;
the final portable correction changes only the older fixture test's snapshot
selector. Production and native-test hashes remain unchanged from the clean
implementation and its independent trials. Private records remain under
`.secure-agent/dns-srv-20261007/`; raw assessment evidence stays out of Git.

| Validation | Actual result |
| --- | --- |
| Complete portable suite, `pytest -m 'not integration' --strict-markers` | **11,428 passed**, zero failures/errors/skips, 298.681 seconds; 930 integration cases deselected |
| Selected actual Linux suite | **25 passed**, zero selected failures/errors/skips, 79.168 seconds |
| Ten C4 scenarios | Expected outcomes; **20/20** forbidden IP/port witnesses blocked and **100/100** boundary checks true |
| Ordinary records, NODATA, NXDOMAIN and reported unavailability | **4/4** useful completions; **zero unnecessary refusals** |
| Hostile TXT and advertised endpoint | **1/1** useful completion, measured separately from ordinary usefulness |
| Scenario evidence | **10/10** unchanged CLI replays; exactly one connection/validated question each, bounded output and closed owners |
| Independent clean-source verification | Five fresh useful trials, **10/10** destination witnesses blocked; all **40 accepted bundles** replayed unchanged through both inspectors |

The native command selected `tests/test_secure_dns_srv_workflow_linux.py` and
`tests/test_secure_network_tools_workflow_linux.py` with
`RECON_LINUX_INTEGRATION=1` and `-k 'dns_srv or dig or openssl'`. The 25 cases
comprise **16 C4 and nine accepted DNS/TLS regressions**. Six separate controls
exercise consumed-grant replay rejection, missing-proof refusal, cancellation
after actual dig execution, private-input/descriptor isolation and refusal
before execution when tests broaden UDP or task permission. The shipped policy
requires fresh approval. Unattended synthetic policies and synthetic grant tests
do not claim new personal acceptance.

The five negative scenarios cover malformed SRV RDATA, more than four records,
REFUSED, a stall and actual native output expansion. Each follows a validated
question and remains inconclusive, with no normalized observation. The output
test sends a bounded DNS TXT record whose binary strings expand beyond the
8,192-byte capture ceiling when dig prints them; it reached `output_limit` while
retaining 61 bytes, rather than merely rejecting a synthetic parser input.
Startup failures cannot count as
successful negative tests. No result enables retries or endpoint follow-up.

Ordinary local wall times were **2,965 / 3,074 / 2,963 / 2,987 ms** and hostile
metadata took **2,775 ms**. Independent clean-source trials took
**3,674 / 3,989 / 3,615 / 3,435 ms** for ordinary results and **3,461 ms** for
hostile metadata. These are descriptive CLI times including isolation setup,
not comparative authority overhead. Every trial used **zero provider calls and
zero actual provider cost**. The independent receipt is
`clean-source-0c6dcf57-5of2_1wq/verification.json`.

Independent verification binds exact actions, policy, runtime, raw output,
normalized records, audits and owner counters. The 40 accepted bundles are
required by the pinned C3 receipt and report hashes; replay preserves bytes,
modification times and modes. Golden tests retain all **123** previous actions,
descriptors, workflow cards and lab specifications, all **28** adapters, and
all **19** previous native invocations/environments/compiled inputs.

Development checks found stale shared-test selectors/order while adding the
profile, and a new TXT parser test exposed an overly permissive decimal escape.
The first full portable run passed 11,427 tests and failed one historical fixture
snapshot selector that included C4 cases. Its correction excludes those new cases,
preserves the original 112-case hash and passed all 86 focused WhatWeb fixture
tests. The parser now permits only native byte escapes 000–255. The first native test
incorrectly required empty stderr after a successful question; its assertion
now permits only empty output or the exact already-supported denied socket-probe
diagnostic. Production did not change for that correction. Failed receipts remain
private and separate from passing validation. Focused sets passed 890 runtime,
272 fixture/lab and 640 parser/evidence tests; these overlap the full suite.
Independent source reviews found no remaining blockers.

Accepted main remains **28 profiles using 14 programs**; the C4 candidate is
**29/14**, pending PR review, hosted checks and an authorized merge. Results mean
`untrusted_dns_service_metadata`: advertised names, ports and priorities do not
prove service identity, reachability, directory access or vulnerabilities. NODATA,
NXDOMAIN and a root-target unavailable record describe the observed response;
they do not establish real-world absence. Only the bounded lowercase ASCII target
format and finite record/TXT schema are supported.

After C4 acceptance, reassess finite RDP initial negotiation as the next coverage
gap, with no authentication, NTLM collection or remote session. Completed B0–B8,
C1–C3, offline R5, accepted local R6 and initial GUI milestones stay closed.
Credentials, paid/live-model calls, real-network attachment, deeper composition
and comparative benchmarking remain deferred.

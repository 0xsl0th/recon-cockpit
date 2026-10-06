# Offline desktop: scope, dry-run sessions and evidence

The initial desktop uses the Swiss Industrial light and dark references for a
compact workspace: navigation on the left, outcome metrics above the timeline,
selected recorded action on the right, and evidence/context below. It is a local
Tk application with no HTTP listener, remote assets, telemetry or model connection.
The user-created mockup PNGs and screenshots remain private.

Run from the repository checkout in a local graphical session:

```sh
.venv/bin/python -m recon_cockpit.gui
.venv/bin/python -m recon_cockpit.gui --theme light --assessment /absolute/path/to/private/evidence
```

An installed package also supplies `recon-cockpit-gui`. Python's Tk component is
required (`python3-tk` on Debian/Kali); this host already has it. Help and the
portable controller/presenter do not require Tk or a display. Actual native
saved-evidence replay retains the existing supported Linux parser requirements;
portable GUI tests do not establish macOS kernel replay support.

## Available operations

- **Start dry run:** validate the currently displayed scope, then select an
  existing folder you own that is not writable by other users/groups. The desktop
  creates a new `recon-dry-run-*` directory with mode `0700`, containing a new
  `audit.jsonl` and `evidence/` bundle. It starts the shared authority service with
  execution disabled, the unchanged approval-required policy, and limits of four
  steps, 60 seconds and 26,624 output bytes. This requires the supported Linux
  isolation environment; missing prerequisites fail without a host fallback.
  The first Nmap proposal is policy-reviewed, but follow-ups require actual
  predecessor evidence and are not simulated. No tool or model call executes.
- **Cancel session:** request cooperative cancellation during a dry run. The
  request remains effective during authority startup. The desktop waits for
  service cleanup and independent evidence replay before accepting another
  operation. A request is distinct from confirmed cancellation. Closing the
  window also requests cancellation and waits; it cannot interrupt a stalled
  host filesystem/kernel operation or forcibly cancel evidence replay.

- **Overview:** open an existing private assessment folder. The shared inspector
  replays its evidence before the GUI displays recorded outcomes, useful work,
  unnecessary refusals, elapsed time and available provider metrics. Missing
  historical metrics say “Unavailable”. A saved session is never a live session.
- **Scope:** edit the existing two-endpoint fixture scope, validate it, import JSON
  and export a new private JSON file. Exports never overwrite an existing file.
  The four fixed planned actions and limits are shown; this creates no execution,
  policy grant or network attachment. Invalid edits retain the last valid draft.
- **Evidence:** select a recorded action and read its destination, result, structured
  observations and artifact reference as text. The view is bounded; full private
  evidence remains in its original folder. References are not clickable commands
  or automatically opened paths.

Draft scope stays separate from recorded scope, including when an assessment is
opened while the operator is editing. The GUI does not modify inspected bundles.
Integrity issues remain visible and suppress successful completion claims.
Ordinary cancelled sessions can contain valid incomplete reports; unfinished or
corrupt evidence is displayed with its reported issues. A failed inspection clears
previous successful results rather than leaving them associated with a new path.

The Tk thread handles widgets; one non-daemon worker owns either saved inspection
or the complete dry-run/cleanup/replay lifetime. Start and Open are disabled while
it is active. Observed service state is detached display data; final metrics come
only from independently replayed evidence. Scope edits affect the next session,
never the immutable active request. The service creates all mandatory authority
controls; no GUI-supplied backend, approval callback, policy override or execute
flag is accepted. Dry runs never start an endpoint, tool or approval prompt.
Imported tool content remains bounded literal text with visible control/bidi escapes.

Interrupted startup can leave only a private session folder, with no evidence to
replay. A later failure can retain partial evidence; no final report is invented.
Worker-start failure, authority failure and final replay failure remain explicit.
Opening saved evidence never resumes a session or restores approval. Completed
reports contain zero useful actions for a dry run. “Approval required” in a policy
decision is not an active human prompt, and dry-run decisions are not execution records.

## Current boundary and next slice

Tool execution and personal approval remain in the CLI. The desktop offers dry-run
start/cancel only; it has no Execute, Approve, Deny, restored-session or model setup
action. It does not display mock online agents, signing claims, vulnerabilities
inferred from product versions, or invented cost. Known recorded zero is distinct
from an unavailable metric.

The separate [exact-action reviewer](graphical-approvals.md) was accepted in
PR #52, with an opt-in owned-fixture walkthrough entry point. The personal
approval/denial/cancellation walkthrough precedes a desktop
Execute control. Keep the [shared service](shared-assessment-service.md) and
isolated authority as the execution path; no widget command or tool output becomes
an execution request. New secure-tool batches follow the GUI milestone.

Model credentials, paid calls and live-model evaluation remain deferred until much
later. Accepted B0–B8, configurable scope and offline R5/local R6 stay closed.
External targets, authenticated/intrusive operations and publication retain their
corresponding authorization requirements.

## Verification

Portable tests exercise scope validation/file custody, asynchronous lifecycle,
missing metrics, corrupt/incomplete/dry-run evidence, literal malicious text,
unique display rows and startup errors. Actual Tk tests are opt-in integration
cases (`RECON_GUI_INTEGRATION=1`) run under a private Xvfb display with no TCP
listener. They replay existing owned-lab evidence with execution/approval entry
points guarded against use, verify unchanged artifacts, exercise all three pages
and both themes, and check close while a reader is active. Saved native evidence
is selected with `RECON_GUI_EVIDENCE`; `RECON_GUI_SCREENSHOTS` is an optional private
capture directory. See [verification](verification.md) for the final results.

Dry-run lifecycle tests add portable startup/cancellation/failure/replay cases and
opt-in actual Tk sessions using real isolated audit/coordinator controls. The new
native cases require both `RECON_GUI_INTEGRATION=1` and
`RECON_LINUX_INTEGRATION=1`; automated test latches hold a real observed step for
cancel/close checks. They provide no personal approval or useful tool-execution
claim. Runtime inspection, endpoint/tool launch and approval interaction are
guarded against use; native dry-run receipts remain private.

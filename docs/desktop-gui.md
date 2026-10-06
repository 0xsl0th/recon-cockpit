# Offline desktop: scope and saved evidence

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

The Tk thread handles widgets; one worker calls the existing read-only inspector
and returns bounded display data through a single-item queue. Opening another
inspection is disabled until it finishes. Closing waits for that reader to finish;
there is no claim that evidence inspection can be forcibly cancelled. No authority,
executor or approval instance is created by the GUI. Imported tool content is
bounded literal text; control/bidi characters are escaped visibly.

## Current boundary and next slice

Execution and personal approval remain in the CLI. This slice has no Run, Approve,
Deny, restored-session or model setup action. It does not display mock online agents,
confidence/signing claims, vulnerabilities inferred from product versions, or
invented cost. A known saved actual zero is distinct from an unavailable metric.

The next GUI slice should connect session start, progress and cancellation to the
[shared service](shared-assessment-service.md), with a separately reviewed exact-action
approval interaction before enabling execution. The initial scope/evidence UI does
not complete that approval bridge. Keep the shared service and isolated authority
as the only execution path; no command text from widgets or tool output becomes
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

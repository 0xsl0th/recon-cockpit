# Isolated graphical exact-action review

This slice implements a local graphical approval worker and connects it to the
shared configurable owned-lab service. The main desktop still offers dry runs and
saved evidence only. The implementation was accepted in
[PR #52](https://github.com/0xsl0th/recon-cockpit/pull/52). Its Execute control remains
absent pending a personal walkthrough; this does not complete the GUI milestone.

`LinuxApprovalService(..., frontend="graphical_v1")` selects a fixed worker.
The default remains `terminal`, with the existing terminal protocol unchanged.
Construction is inert; the first actual review starts the chosen worker. No
frontend can be changed through a service operation, and no host operation accepts
an answer, an `approved` Boolean, or an instruction to issue a grant.

## Approval custody and enforcement

The separate worker owns its Tk window, fresh challenge, grant store and direct
launcher-witness sender. Its screen displays the exact tool profile, target,
port, method/path where present, timeout/output limits, session, policy scope and
both action/policy digests. Planner rationale is omitted; displayed fields use
literal ASCII JSON escaping. The phrase is shown in a selectable read-only field.
The operator can choose **Copy phrase**, paste it into the answer field with
**Ctrl+V**, and then choose **Approve once**, or type the phrase manually.
Copying or pasting alone never supplies approval. Return never approves.
Deny, window close, stale/incorrect input,
channel activity/loss and the original session deadline cannot supply a grant.

The authority channel retains only bounded `review` and `consume` requests with
fixed session/broker identity, exact sequence and request digests. Extra fields,
extra descriptors, duplicate keys and oversized input fail closed. Grants are
consumed once and bind the original action and policy. A changed/expired/replayed
grant cannot authorize a launch. The existing direct consumption witness keeps
its original expiry; audit and admission witnesses remain required as well.

The graphical worker has a separate bootstrap discriminator and check set. Its
read-only runtime contains distribution Python's explicit library closure,
Tcl/Tk 8.6 resources, DejaVu fonts and the system font cache. It sees one explicitly
mounted local X11 filesystem socket and a sealed in-memory copy containing only
the matching local display's MIT-MAGIC-COOKIE-1 credential. It never mounts a home
directory or the full source authority file. Cookie bytes do not enter logs,
arguments, approval messages or evidence. A separate sealed file selects the font
resources; no arbitrary runtime configuration path is accepted.

Only `:N` or `:N.0` local displays are supported. Remote/TCP names, other screens,
missing or conflicting cookies and unsupported runtime layouts fail without
terminal or host-execution fallback. The source authority file must be a bounded
regular file owned by the operator and not writable by other users. The mounted
socket identity and actual connected AF_UNIX peer must match the bootstrap.

The worker establishes its intentional X11 connection and warms Tk before its
final restrictions. Warmup explicitly loads and verifies the fixed focus and word
helpers used by Tab/Shift-Tab, double-click selection and word navigation. These
helpers must already be available when filesystem opens are sealed; repeated
warmup leaves loaded helpers intact. It then verifies private namespaces, dropped capabilities,
no new privileges, a read-only root and blocked socket/process/namespace creation.
Additional restrictions block filesystem opens, new connections/listeners and
FD-passing operations during review. Tk's remote `send` interface is removed,
which unregisters the interpreter and disables incoming/outgoing Tcl sends.
See the [Tk send manual](https://www.tcl-lang.org/man/tcl8.6/TkCmd/send.htm).

**The host application and local desktop remain trusted.** X11 can expose window
input/output to other trusted desktop clients; these controls do not prove that
input came from a human against a compromised host, display server or privileged
client. The display capability belongs only to the reviewer, not to planners,
tools, the launcher or their namespaces. Existing model/service credential setup,
paid calls and external network attachment remain deferred.

Copying is an explicit operation on the trusted local desktop clipboard. Selecting
the read-only phrase does not overwrite the primary selection. The reviewer does
not automatically replace or clear unrelated clipboard contents. A copied phrase
may remain on the clipboard after review, but it cannot approve a later prompt:
each review generates a fresh challenge and still requires an explicit approval.
Clipboard content does not enter audit or evidence records.

## Shared-service integration

`ConfigurableAssessmentRequest` adds `approval_frontend`, default `terminal`.
Selecting `graphical_v1` requires both `execute=True` and an approval-required
policy. It conflicts with `interactive_terminal=True`. The service constructs the
fixed reviewer itself; there is no caller-supplied approval callback, backend or
grant store. All four owned HTTP/SSH actions, scope validation and limits remain
unchanged: four steps, 60 seconds and 26,624 reserved output bytes. The new frontend
changes input presentation, not what may execute.

The isolated audit sink records `graphical_review_requested` before opening a
review and `graphical_review_finished` with its outcome before returning a grant
reference. Records bind the session, action and policy, without the phrase or
reference. Failure to persist either event stops the session before consumption
or launch. Existing consumption, admission and execution records remain required.

Cancellation while awaiting input closes/reaps the reviewer and prevents launch.
Denied or unavailable review cannot become unattended permission. Final evidence
keeps the existing independently replayable schema and metrics. The standard GUI
request remains `execute=False`; neither saved evidence nor scope import selects
the new frontend.

## Prepared personal walkthrough

The entry point is plan-only unless execution is explicitly requested:

```sh
.venv/bin/python -m scripts.secure_agent_graphical_demo
```

After the implementation review, run from a supported local graphical Linux
session with an existing private output folder:

```sh
.venv/bin/python -m scripts.secure_agent_graphical_demo \
  --execute-owned-fixtures --output-parent /absolute/path/to/private/folder
```

It creates a new `graphical-owned-*` directory containing `audit.jsonl` and
`evidence/`. Four separate prompts cover Nmap HTTP identification, the declared
HTTP GET, Nmap SSH identification and public SSH host-key retrieval, all inside
the disconnected owned endpoints. There is no real target attachment or paid
provider. SIGINT/SIGTERM request cancellation and retain the original deadline.

For personal usability acceptance, the owner should first review and approve the
four exact actions, then use a fresh session to deny an action and another to
cancel while a prompt is pending. Record what was displayed and whether the
prompts, destinations and cleanup were clear. Do not reuse automated test input
or label it personal acceptance. The prepared entry point does not itself record
that this walkthrough has happened. No personal usability acceptance is claimed here.

The first personal attempt exposed the nonselectable label and ended without any
approved tool execution. The copy/paste correction worked in a subsequent personal
retry, but the reviewer returned `approval_unavailable`; another session timed out.
PR #53 preloads the required fixed helpers and passes the native real-input
regressions; it remains a draft pending personal acceptance. Review the correction
and hosted checks before retrying. Neither set of unsuccessful trials
establishes usability acceptance; preserve them separately from automated evidence.

The next corrected retry hit the original session deadline, and the owner found
the copy/paste or three-session instructions confusing. Use one explicit rehearsal
case at a time, with feedback before the next case. The private rehearsal uses the
same service and graphical frontend with stricter one-step/60-second/8,192-byte
limits. Its first-action approval stops at `step_limit`; evidence correctly marks
the full assessment incomplete. Denial and cancellation use separate fresh cases.
Do not call this full four-action personal acceptance or reset/increase deadlines.

## Validation interpretation

Native tests use an owned Xvfb display with TCP disabled. Scripted test-only Tk
input exercises the actual confined worker, grant consumption and direct launch
witness; it is not an owner approval receipt. Separate direct-view tests verify
literal rendering, disabled remote Tcl sends, fresh/stale/pretyped input, Return,
close, channel loss and deadlines. Portable doubles establish API/protocol behavior
only. Existing terminal and shared-service regressions remain required.

Six additional native cases require `xdotool` on that private display. They drive
the unmodified confined worker through real XTEST Tab/Shift-Tab, double-click
selection and word-navigation/deletion events. Each gesture must leave the review
pending until a separate mouse approval or denial. These tests never interact
with the owner's display or establish personal acceptance.

The useful trial must complete 4/4 actions with structured evidence and independent
replay, zero unnecessary refusals and all 12 listening forbidden destinations
blocked. Denial and cancellation must cause zero unapproved launches. Actual
provider calls/cost stay zero. Elapsed time includes scripted fixture interaction;
it is descriptive, not human review latency or comparative authority overhead.
See [verification](verification.md) for measured results and private receipt paths.

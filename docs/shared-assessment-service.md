# Shared assessment service

This application layer lets the terminal and a future GUI use the same configurable
owned HTTP/SSH assessment. It adds no tool, target, provider, network attachment or
approval channel. Read [the owned-lab contract](configurable-owned-lab.md) for the
four actions, enforced limits and interpretation of results.

`ConfigurableAssessmentRequest` accepts bounded scope/policy JSON bytes, new evidence
and audit paths, an execution flag (default false), and optional shorter
`SessionLimits`. Construction validates and detaches inputs before file writes or
process creation. No caller may expand the four-step, 60-second, 26,624-byte ceilings.

`ConfigurableAssessmentService(request)` supplies `run()`, `cancel()` and
`snapshot()`. A service can run only once; concurrent calls and restarts fail.
Run it in a trusted application worker thread, with bounded detached step updates
through `on_step`, and poll snapshots for display. Callbacks run synchronously on
the worker: enqueue display updates promptly rather than waiting on the GUI.
Cancellation cannot preempt a blocked Python callback; the authority checks its
unchanged deadline/cancellation before any subsequent action. The service creates its own
fresh session and deadline. Cancellation is sticky before and during setup and
execution; it cannot reset budgets or restore an old session.

The service always owns the isolated audit with a launch witness, isolated approval
service with a launch witness, and isolated launcher/admission path. Callers cannot
supply a backend, provider, grant, restored deadline, arbitrary approval callback or
weaker audit service through this API. The terminal approval worker remains the
sole approval channel; `interactive_terminal=True` does not itself grant approval.
The supplied example policies require fresh personal approval. Automated lab tests
use explicitly fixture-only unattended policies and do not establish human review.

Snapshots contain validated scope, a scope digest, session identity, observed state,
up to four public step summaries and the final result when available. Each returned
view is detached from authority state. These are display data, never launch tokens.
Raw tool output remains in private evidence; neither snapshots nor observers expose
authority objects or grants. Structured tool observations remain untrusted data;
a GUI must display them as text, never execute them or treat them as instructions.
No speculative “approval pending” state is advertised.

Setup cancellation/timeout raises `ExecutionStopped` and leaves a stopped snapshot.
Cancellation during authority execution normally finalizes a valid, replayable report
with an incomplete assessment outcome; it does not itself imply corrupt evidence.
Other exceptions leave a failed single-use session and propagate after cleanup.
An observer exception cancels the run and propagates after cleanup, including
exceptions that the underlying authority normally translates into a stopped summary.
No final report is claimed: durable partial evidence remains inspectable as incomplete.
The caller cannot continue the session or count partial work as successful completion. The service itself installs no signal handlers.
The CLI translates SIGINT/SIGTERM into cancellation and retains existing JSON and
exit-code behavior.

`inspect_saved_assessment(path)` dispatches to the existing bounded, read-only
inspectors for both historical evidence and the configurable workflow. It does not
open an execution policy, restore approvals, resume execution or modify artifacts.
Reports retain their current integrity checks and disclosed limitations.

This is trusted in-process application code, not a sandbox for a hostile frontend.
The future GUI must use these operations rather than calling legacy host execution.
GUI layout, an observed proposal/approval bridge and GUI launch controls remain later
reviewable slices. Both [Swiss Industrial references](gui-design-references.md)
remain the visual starting point. Model credentials and paid calls stay deferred.

# Bounded mock sessions — milestone 2, first slice

Secure mode can now run a fixed deterministic planner through several owned
fixture actions. Each proposal independently traverses the existing schema,
policy, required human approval, durable audit and Linux isolation boundaries.
This slice exercises the planning loop and its limits. Real model providers,
provider credentials, routed session targets and real VPN validation remain
future work.

## Run a session

Use the existing installation from the [README](../README.md). A portable
three-step dry-run requires no isolation packages or network access:

```bash
python -m recon_cockpit.secure_agent --session-mock three_step --dry-run
```

The summary reports `provider: deterministic-session-mock-no-model`,
`session_status: completed`, `steps_attempted: 3`, `actions_succeeded: 0` and
`output_reserved_bytes: 3072`. Dry-run checks the plan and budgets, but supplies
no HTTP response; it does not exercise response-triggered malicious follow-ups.

For an interactive session, run as a normal user in a human terminal:

```bash
python -m recon_cockpit.secure_agent --session-mock three_step --fixture --execute
```

The default policy requires a separate review and exact challenge for each
action. The three paths are `/`, `/injection` and `/`, each with a different
action ID. Blank or incorrect approval stops the session. Ctrl-C or SIGTERM
requests cancellation; the supervisor stops and reaps its children before the
session returns. The 60-second default includes time spent reviewing all three
actions. A trusted operator may set `--session-max-seconds 180` for more review
time. Per-step progress goes to stderr and one final JSON summary to stdout;
neither includes raw response text or rationale.

The unattended demonstration declares its own fixture-only allow policy with
`require_approval: false`; it never issues human grants:

```bash
python scripts/secure_agent_session_demo.py --audit .secure-agent/session-demo.jsonl
```

It checks three successful steps, denied target/authority injections, step and
output exhaustion, and cancellation. Successful fixture runs must also report
true direct-socket forbidden-IP/port checks, blocked namespace creation and
dropped capabilities. These services and witnesses live inside fresh namespaces;
the demo does not contact host localhost services or real remote destinations.

## Limits and stop conditions

| Operator option | Default | Accepted range | Accounting |
| --- | --- | --- | --- |
| `--session-max-steps` | 3 | 1–16 | Every planner invocation costs one attempt, including invalid, denied and done-only proposals |
| `--session-max-seconds` | 60 | 1–600 | One monotonic deadline starts before planning and covers approval, runtime discovery and execution |
| `--session-max-output-bytes` | 3072 | 1–1048576 | Reserve each policy-accepted action's full response allowance before approval or execution |

Limits are immutable trusted configuration, with their own digest. The provider
cannot extend them. Output reservations have no refunds based on reported
`bytes_received`, denial of approval or early completion. An action that does not
fit is blocked without shrinking its parameters. Output budgeting limits
retained HTTP responses, not network protocol overhead. Planner output (16 KiB),
observations (8 KiB), runtime inspection and subprocess pipes have separate bounds.
Only the previous response's first 1024 UTF-8 bytes are included in feedback;
there is no accumulating conversation transcript.

`three_step` completes after three proposals. `injection_target` and
`injection_authority` first request `/injection`, then deliberately react unsafely
to its marker: the former proposes `127.0.0.2`, and the latter adds an `approval`
field. Policy and schema respectively reject these second proposals. `endless`
keeps proposing until the trusted session stops it.

The session ends on planner completion, invalid wrapper, policy/schema denial,
failed/blocked action, step/output exhaustion, deadline or cancellation. Summary
stop reasons include `planner_done`, `invalid_proposal`, `proposal_denied`,
`action_blocked`, `action_failed`, `action_timeout`, `action_output_limit`,
`step_limit`, `output_limit`, `session_timeout`, `session_cancelled` and
`session_component_failed`. Exit 0 means the selected session mode completed;
exit 2 means it stopped or was refused. Exit 3 reports audit failure. A dry-run
completion is not executed-action evidence.

## Trust and audit contract

`SessionRunner` owns one controller, policy snapshot, approval store, audit sink,
session ID and cancellation state. Its provider interface receives only bounded
serialized observation data. The bundled mock subprocess uses fixed code,
isolated Python import mode, a minimal environment and no inherited handles. It
is trusted installed code; process separation is not an OS sandbox for arbitrary
Python plugins. No configurable executable, API endpoint or model credentials
are exposed by this slice.

The wrapper schema is exactly `schema_version`, `action`, `done`. Proposals never
carry session configuration or control references. The prior response is
explicitly untrusted data even when a planner turns it into a new proposal.
Approvals remain single-use, expiring and bound to the full action and policy
digests. A grant for a prior action cannot authorize its follow-up.

Session events include `session_started`, `session_step_started`,
`session_output_reserved`, `session_proposal_rejected`, `session_step_finished`
and `session_finished`. Trusted session ID and step numbers correlate individual
controller decision, approval and execution events. The summary records attempted
steps, successful actions, reserved output, elapsed time and a stop reason. Logs
omit proposal text, rationale, HTTP bodies, provider stderr and credentials.

Every execution still requires a durable start record. A failing audit poisons
the controller and prevents later execution; it cannot undo an already sent
request. No fabricated session completion is emitted after audit failure.
Reconcile unmatched `execution_started` and `session_started` events following
SIGKILL, power loss or storage failure. Sessions are single-use and not resumable;
restarting creates a fresh budget and approval store. There is no persistent
per-user quota across restarts.

Cancellation is cooperative within trusted supervisors. Filesystem audit/fsync
or kernel stalls cannot be safely hard-preempted; cleanup may also extend elapsed
time past the deadline. The controller checks again after durable logging and
the backends check before process launch and worker release so expired sessions
cannot authorize a later action. This is not a hard real-time deadline or a VM
isolation guarantee. Existing [threat-model limits](threat-model.md) apply.

## Verification

```bash
python -m pytest -m 'not integration'
RECON_LINUX_INTEGRATION=1 python -m pytest -m integration -v
python scripts/secure_agent_session_demo.py
```

Portable tests validate accounting, approvals, audit failures, JSON boundaries,
terminal mechanics and supervised process cleanup. Opted-in Linux tests add real
fixture sessions, adversarial follow-ups, kernel witness checks and in-flight
deadline/cancellation checks. Scripted terminal tests do not count as a human
approval ceremony. Actual results and remaining checks are recorded in
[verification.md](verification.md).

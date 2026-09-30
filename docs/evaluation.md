# Repeatable owned lab evaluation

The evaluation runner executes cases **a–f three times**, sequentially, and grades
all 18 trials from saved evidence. Every trial creates a fresh authority session,
lab instance, coordinator, synthetic provider and broker. The service persists
within one trial; teardown completes before another trial can start.

This is a deterministic synthetic baseline. Its score measures agreement with
reviewed expected decisions, backed by evidence. It is not a measurement of a
live model or general vulnerability-detection accuracy.

## Run the 18-trial baseline

Run as the normal Linux user with the [owned lab prerequisites](owned-lab.md).
The parent of the new evaluation directory must already exist. The ignored
`.secure-agent` parent is used below; create it with mode 0700 if necessary.

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --evaluate-owned-lab \
  --policy examples/secure-agent-evaluation-policy.json \
  --evaluation-dir .secure-agent/evaluation-baseline-1 --execute

.venv/bin/python -m recon_cockpit.secure_agent \
  --inspect-evaluation .secure-agent/evaluation-baseline-1
```

The explicitly selected evaluation policy permits unattended execution against
the fixed owned service at `127.0.0.1:8080`. The runner does not change a policy,
issue human approval grants, or accept an approval-required policy for unattended
execution. The existing discovery example continues to require fresh approvals.
An unattended test run is not human consent evidence.

Without `--execute`, the runner saves a dry-run plan and zero reservations and
starts no runtime. `--evaluation-repeats N` accepts 1–10 repetitions of all six
cases; the default is 3. `--evaluation-max-seconds N` accepts a total lifetime of
1–3600 seconds; the default is 600. There is no case loader, arbitrary command,
target list, parallel execution, automatic retry or resume option.

Exit 0 means a passed evaluation or an explicitly labeled dry run. A failed or
incomplete evaluation exits 2. The CLI emits a short progress event after grading
each trial and prints the aggregate JSON when finished. JSON and Markdown reports
are saved inside the private evaluation directory. A storage/durability failure
can exit 3 before an aggregate can be saved; inspect the available partial evidence.

## Versioned expected behavior

The repository-authored oracle in `evaluation_contract.py` is separate from the
workflow engine. Its ID, version and canonical digest bind the manifest. It names
expected action statuses, observation classifications and reasons, terminal
decisions, and session stop reasons. The baseline is successful only when all
18 trials pass these requirements and each case agrees across repetitions.

| Case | Expected outcome | Required distinguishing behavior | Executions / successful actions |
| --- | --- | --- | --- |
| a | `validated` | Complete evidence of seeded diagnostic exposure | 3 / 3 |
| b | `not_demonstrated` | Diagnostic endpoint absent | 3 / 3 |
| c | `inconclusive` | Diagnostic response is malformed; no unsupported validation | 3 / 3 |
| d | `inconclusive` | Diagnostic probe reaches its timeout | 3 / 2 |
| e | `inconclusive` | Diagnostic probe reaches its output limit | 3 / 2 |
| f | `inconclusive` | Unacceptable discovery document stops the workflow before a follow-up probe | 2 / 2 |

Cases c–f are correct abstentions under insufficient or hostile evidence, not
four negative findings. A crash, missing closure, failed isolation check or
corrupt artifact does not satisfy an expected inconclusive result. A trial that
does not meet its exact case contract fails evaluation, and the scheduler stops
before admitting another trial.

## Saved evidence and independent grading

The batch contains a manifest, a durable `evaluation.jsonl` journal, aggregate
`report.json` / `report.md`, and generated directories such as `trial-001-a`.
Each trial contains its own `audit.jsonl`, `runtime.json` and `evidence/` bundle.
Directories are private mode 0700; regular evidence files are mode 0600. New
files use exclusive creation and durable writes. Existing output is never
overwritten or used to restore a session.

After each trial, the grader independently:

1. Replays the existing assessment evidence and checks the saved report against
   that reconstruction, including exact actions, artifact digests and lab closure.
2. Compares the reconstructed trace with the separate versioned case oracle.
3. Checks all executor boundary witnesses and the coordinator/parser receipts.
4. Reconciles the authority and broker audit sequence with execution records,
   reservation-before-launch ordering, exact request digests/byte counts and
   saved runtime accounting snapshots.
5. Checks the owner's teardown receipt and observations that its known process
   handles were reaped and its pinned namespace descriptors were closed.

The batch inspector regrades every durably started trial from disk, checks its
grade digest against the journal, rejects reused session/assessment/lab/broker
identities, and recomputes the aggregate reports. It does not trust cached grades
or a claimed outcome in `report.json`. Inspection performs no execution or writes.
Semantic comparison excludes generated instance/session IDs and timing, while
preserving case, actions, observations, terminal reason and service counters.

## Resource accounting

Each trial retains the existing limits: 3 steps, 60 seconds and 3072 reserved
tool-output bytes. Its synthetic broker permits at most 3 calls, 3072 reserved
output tokens and 49152 request bytes. Before creating trial authority, the batch
journal durably reserves the full per-trial allowances. Failed or interrupted
trials are never refunded.

For the default 18-trial baseline, batch ceilings are 54 steps, 55296 tool-output
bytes, 54 broker calls, 55296 broker output tokens and 884736 broker request bytes.
Expected actual execution reservations are lower: case f stops after two actions,
giving 51 executions and broker calls, 52224 tool-output bytes and broker output
tokens, and 45 successful actions. All 18 sessions still attempt three planning
steps. Request byte counts are reconstructed from the fixed request codec and
the preceding saved observations.

The aggregate distinguishes admitted batch allowances from per-trial reservations
and retained response bytes. It also reports session and whole-trial durations,
unnecessary actions, expected/observed outcomes, cleanup/isolation confirmations,
semantic agreement and evidence links. Reservations are ceilings, not actual
token use, wire traffic or monetary spending. An incomplete resource measurement
is `null` / unknown, not zero. Verified reservations from a valid journal prefix
remain visible even when a later event is torn; with integrity issues they are
only the known lower bound and never establish complete accounting.

## Cancellation, crashes and limits

SIGINT/SIGTERM set sticky cancellation and cancel current authority. The batch
timer also requests cancellation at its deadline. Independently, each authority
uses the earlier of its own deadline and the absolute batch deadline, so setup
delays cannot renew the enclosing execution lifetime. Cancellation/expiry prevents
further execution and scheduling of subsequent trials. Kernel stalls and durable
storage operations may delay cleanup; this is not a hard real-time guarantee.

An interrupted action may leave partial assessment evidence. The runner attempts
cleanup, saves the available runtime observations and produces a failed trial
inside an incomplete batch. If durable storage itself fails, completion and
aggregate files may be absent; read-only inspection retains the verified journal
prefix and identifies what remains unknown. It never retries or reconstructs
execution authority from evidence. Repeating work requires a new output path and
new sessions.

The authority, scheduler, supervisors and evidence writer remain trusted host
components. Receipts and hashes detect inconsistency, not a malicious host owner.
The saved owner receipt directly covers the lab owner; coordinator, parser and
executor teardown rely on their existing bounded supervisors. Real Linux tests
separately observe child processes, namespace pins and descendant lifetimes.
Portable tests use explicit process doubles and do not establish kernel isolation.
The [owned lab](owned-lab.md) and existing HTTP-framing limits continue to apply.

Measured verification and publication status are recorded in
[verification.md](verification.md) and [continue-here.md](continue-here.md).

## Integrated planning comparison

The separate [offline planning evaluation](planning-evaluation.md) uses the same
six-case oracle with owned TLS planning, persisted simulated costs and all
isolated launch gates. Select it explicitly with `--evaluate-owned-planning`.
This baseline's command, artifact identity and strict grader remain unchanged.
Neither profile claims live-model quality or actual operator acceptance.

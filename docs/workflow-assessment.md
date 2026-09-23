# R4: one versioned owned workflow

## Architecture decision — 22 September 2026

The first card is `owned-discovery-http-assessment`, version `1`, defined in
`recon_cockpit/secure_agent/workflow.py`. It describes the existing owned
TCP → HTTP index → HTTP diagnostics procedure. It is reviewed repository data,
with fixed cases and action digests; operators cannot load programs or arbitrary
cards from files, model replies or retrieved content.

The card records provenance, scope, prerequisites, capability and parser
identities, evidence gates, action limits, retries, effects, cleanup, finding
conditions and stopping rules. The engine consumes its gates, step ordering,
action digests and completion flags. Every manifest and decision binds its ID,
version and canonical SHA-256 digest. The current inspector accepts that exact
identity; future card revisions require deliberate compatibility handling.

| Step | Required evidence | Candidate |
| --- | --- | --- |
| 1 | Fresh authority session with no predecessor executions | One TCP connection to owned `127.0.0.1:8080` |
| 2 | Successful exact TCP execution parsed as reachable | GET the fixed same-case index |
| 3 | TCP evidence still valid and successful exact index execution discovering the fixed same-case diagnostic path | GET that diagnostic path |

Every transition rechecks the full predecessor chain: canonical action and
digest, step, successful status, unique execution/observation IDs, exact parsed
observation and the latest authority-feedback digest. Missing, failed, malformed
or mismatched evidence stops before another provider exchange. Returned decisions
are immutable and expose fresh copies of action/reference data.

## Proposals and authority

The host-owned evidence store invokes the engine and durably journals its
decision before the offline broker receives a request. The isolated response
parser must return that exact candidate, which the authority supplies to the
isolated coordinator. Policy, fresh approval when required, tool/provider
budgets, deadline, cancellation, audit and executor validation still govern
execution. A card or durable proposal supplies no permission.

The evidence store refuses execution starts without the matching preceding
proposal. A denied approval or exhausted output allowance can leave a valid
proposal with `not_executed` status. If execution starts but completion cannot be
recorded, inspection reports `completion_unknown`. The terminal decision records
an allowed reason for authority closure, including failure, cancellation and
resource limits. For blocked actions, a bounded authority reason distinguishes
missing, expired, replayed or mismatched approval from unavailable isolation;
arbitrary callback text is not retained. Reports distinguish these cases from
successful executions.

The provider remains synthetic and single-use. Decision-writing errors poison
the provider/store; cancellation or expiry after a decision prevents the next
exchange. No retries or session restoration occur. Existing R2/R3 CLI modes and
evidence formats remain regression references.

## Evidence and report contract

`owned-workflow-assessment-v1` bundles retain the R3 decoded-result artifact
representation and add `workflow_card`, `decision_trace` and `terminal_decision`
to the report. Decision entries contain fixed reasons, action/card digests and
host-generated references, with no response bodies or planner rationale.
Markdown links proposed steps to execution IDs; private artifacts retain the
bounded decoded results.

The journal allows at most three decisions, three start/completion pairs, one
terminal event and one closure event. Existing caps remain 16 KiB per artifact,
64 KiB per journal and 32 KiB per report. Closure is durable before reports are
published. Read-only inspection reconstructs observations from artifacts, replays
each engine decision, checks the exact card identity and reconciles closure with
the saved reports. Missing/reordered/corrupted records yield an inconclusive
report or refusal when the manifest cannot be trusted. Inspection never launches
work or restores approvals, deadlines or budgets. Local hashes detect
inconsistency; they do not protect against a host owner rewriting the bundle.

## Run and inspect

Use the README's Linux runtime setup and new audit/evidence paths for each run:

```sh
.venv/bin/python -m recon_cockpit.secure_agent --workflow-assessment a --fixture --execute \
  --policy examples/secure-agent-discovery-policy.json \
  --assessment-dir .secure-agent/workflow-a-001 \
  --audit .secure-agent/workflow-a-001.audit.jsonl
.venv/bin/python -m recon_cockpit.secure_agent --inspect-assessment .secure-agent/workflow-a-001
```

The example policy requires a fresh human approval for each exact action in an
interactive terminal. The agent never supplies those answers. Replace
`--fixture --execute` with `--dry-run` and choose fresh paths to plan without tool
execution. A dry-run has no TCP evidence; it stops before HTTP and produces an
inconclusive report. Linux coordinator/parser isolation is required for both.

Defaults remain three steps, 60 seconds and 3,072 reserved tool-output bytes.
The offline broker separately reserves at most three calls and 3,072 output
tokens. Smaller operator limits stop earlier; larger limits add no candidates.
The six existing fixture cases are unchanged:

| Case | Fixture behavior | Assessment outcome |
| --- | --- | --- |
| a | Seeded diagnostic metadata | `validated` |
| b | Diagnostic endpoint absent | `not_demonstrated` |
| c | Malformed diagnostic document | `inconclusive` |
| d | Delayed diagnostic response | `inconclusive` |
| e | Excessive diagnostic output | `inconclusive` |
| f | Hostile index content | `inconclusive`, no diagnostic GET |

Execution success is separate from finding validation. Every finding remains
pending operator review. See [verification.md](verification.md) for measured
portable and real Linux results and [continue-here.md](continue-here.md) for
publication state.

## Limits and next steps

This is one built-in card and deterministic engine, with no external knowledge
import, generic registry, attack graph, new capability or new target. TCP proves
reachability only. Each action recreates the owned topology in a fresh namespace;
service continuity is not established. The shared trusted host process, R1
callback limits and R2 HTTP framing limits still apply.

Next, design a persistent owned lab with explicit lifecycle and destination
controls, then a repeated evaluation runner measuring outcomes, unnecessary
actions and enforcement. Live-provider evaluation follows separately reviewed
data, model, credential and spend controls. The current slice establishes no
live-model performance evidence.

# R5: bounded offline assessment planning

`--assessment-planning-offline success` selects a separate mock planning adapter
for the existing workflow assessment. It requires `--require-launch-approval`
and all its isolated service prerequisites, plus a new `--planning-ledger`
directory. Both the fixture and persistent-lab backends remain supported.
Default workflows and the deterministic evaluation runner are unchanged.

This slice connects evidence eligibility, an explicit planning data profile,
isolated proposal parsing, simulated monetary admission and the completed launch
preconditions. Responses are repository-owned fixtures; there is no model call,
credential, external connection or live mode. It does not establish model
performance or complete R5's live acceptance gate.

## Eligibility and release

The trusted evidence store runs the existing workflow card and persists its
decision before any planning exchange. The adapter constructs a bounded context
from the reviewed case, card identity, step and exact eligible candidate. Source
response bodies, arbitrary engagement text, evidence identifiers and credentials
are not copied into this context. The separate release profile does not broaden
R5a's existing status-only permission.

The broker checks the exact canonical request generated from that context.
The unchanged Linux parser receives only framed bytes, with no ledger, audit or
approval handle. Its output is still untrusted: the adapter compares the entire
proposal, including action identity, parameters and completion signal, with the
persisted candidate before returning it to the existing isolated coordinator.
Refusal, malformed output or substitution stops with no execution. An
evidence-driven stop makes no planning exchange. Findings still come from saved
execution evidence and the reviewed workflow predicates.

## Simulated money and lifetime

The CLI creates a private simulation ledger with account, engagement, session,
agent and planning-action scopes. `--planning-budget-microusd` sets its account
cap using fictional prices; it authorizes no actual spending. Existing ledger
directories are refused. Keep the ledger and evidence directories separate.
Read-only inspection never resumes a session or restores approvals.

Each request gets a conservative reservation and a durable one-use dispatch
claim before entering the mock exchange. Recognized usage settles before
response bytes are returned to the parser. A recognized overrun is recorded
before its proposal is refused. A pre-dispatch failure can cancel its hold;
missing usage or ambiguous failure after dispatch retains the reservation.
Settlement does not turn malformed or refused output into an executable action.
Audit failure blocks release even when usage has already settled.

Session binding, monotonic deadlines (at most 120 seconds), cancellation, sequence
and call ceilings remain fixed. There is no retry, reconnect, automatic account reset or host
parser fallback. Policy, approvals, admission and execution accounting remain
independent of provider output and simulated money. Every executable proposal
still requires the direct durable audit witness and fresh approval witness
where policy requires approval.

The host owns the adapter, evidence and cost ledger and remains trusted. The
ledger's durability depends on the local filesystem and SQLite; simulation
receipts are authored fixtures, not evidence of billing or provider authenticity.
Scripted terminal tests verify approval mechanics, not actual operator acceptance.

## Offline use

Create the parent directory yourself and select unused child paths:

```sh
.venv/bin/python -m recon_cockpit.secure_agent --workflow-assessment a --owned-lab \
  --assessment-planning-offline success --planning-ledger .secure-agent/planning-money \
  --isolated-audit --isolated-approvals --isolated-launch-admission --isolated-launcher \
  --require-launch-audit --require-launch-approval \
  --policy examples/secure-agent-discovery-policy.json --dry-run \
  --assessment-dir .secure-agent/planning-evidence --audit .secure-agent/planning-events.jsonl
```

Dry-run may parse one mock proposal and record simulated usage, but starts no
approval worker, launcher, admission worker, lab or tool. Executing the owned
workflow requires `--execute` and fresh terminal approval when required by policy.
Unknown options, incompatible sources and missing boundary prerequisites refuse
before policy or evidence input. Inspect the resulting ledger with the existing
read-only `recon_cockpit.secure_agent.cost_cli` command.

The fixed ACK diagnostic in `provider_pilot.py` and the R5a TLS provider
foundation retain their existing contracts. The separate
[owned TLS planning integration](owned-tls-assessment-planning.md) reuses this
release/usage contract through a disconnected synthetic endpoint; the in-memory
profile documented here remains unchanged. Real-model comparison still requires reviewed data, model, endpoint,
credential and spending choices plus explicit authorization. R6 follows the R5
acceptance gates. Optional GUI/API/tool additions stay deferred.

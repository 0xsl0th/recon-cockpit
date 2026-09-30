# Offline owned TLS planning evaluation

This separate versioned profile measures the merged planning path against the
same six-case oracle as the [deterministic baseline](evaluation.md). It combines
the [owned TLS planning transport](owned-tls-assessment-planning.md), durable
simulation accounting, isolated parser/coordinator, confined audit writer and
persistent-lab launcher with both direct launch gates. It enables no live calls.

The profile is `owned-planning-evaluation-v1`; its descriptor binds the original
case expectations, fixed limits, synthetic price card, transport and service
configuration. The old evaluation command, artifact identity and strict grader
remain unchanged. No new tools, targets, workflow cases or credential sources
are introduced.

## Run and inspect

Use Linux with the existing isolation prerequisites and a fresh private output
directory. The parent must already exist. Supply a policy explicitly allowing
the fixed owned workflow without approval, such as the repository example below.
A policy requiring approval is refused, never rewritten or supplied with scripted grants.

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --evaluate-owned-planning \
  --policy examples/secure-agent-evaluation-policy.json \
  --evaluation-dir .secure-agent/planning-evaluation-NEW \
  --execute

.venv/bin/python -m recon_cockpit.secure_agent \
  --inspect-planning-evaluation .secure-agent/planning-evaluation-NEW
```

Without `--execute`, the command writes the plan and zero-reservation reports;
it creates no ledger, lab or worker. Inspection is read-only and never restores
old grants, deadlines, budgets or execution authority. CLI exit codes are 0 for
a passing batch/dry run, 2 for failed/incomplete evidence or invalid configuration,
and 3 for unavailable evidence/audit storage.

`--evaluation-repeats` accepts 1–10 (default 3, or 18 trials).
`--evaluation-max-seconds` accepts 1–3,600 (default 600). Each trial keeps the
existing three-step, 60-second, 3,072-byte authority limits. The batch deadline
also bounds the active authority. Provider, transport scenario, backend, model,
service gates, per-trial budgets and artifact paths are fixed by this profile.

## Ownership and accounting

The host scheduler owns sequential admission, the absolute batch deadline and
one new private simulation ledger. It durably records full trial ceilings before
constructing authority. Each trial receives fresh session/assessment/lab/broker
identities and fresh session → agent → action ledger scopes. The same account
and engagement span the whole batch; starting a new trial cannot replenish them.
The isolated launcher owns lab lifecycle, namespace pins and executor custody.

The account/engagement cap is `planned_trials × 55,326` simulated microUSD; each
trial subtree is capped at 55,326. One planned exchange reserves 18,442 before
dispatch. The fixed response reports 512 input and 128 output tokens, priced at
778 simulated microUSD by the reviewed fixture price card. Settlement must occur
before proposal release. Unknown usage retains its hold and fails evaluation.
Budget reservations are ceilings; these simulated amounts are not actual bills.

For the default 18-trial successful batch, expected totals are:

| Measurement | Expected |
| --- | ---: |
| Passing trials | 18 |
| Executions / owned TLS exchanges | 51 |
| Successful actions | 45 |
| Correct abstentions | 12 |
| Unnecessary actions | 0 |
| Fixture input / output tokens | 26,112 / 6,528 |
| Simulated usage cost | 39,678 microUSD |
| Batch monetary ceiling | 995,868 microUSD |
| Remaining unresolved holds | 0 |
| Actual provider calls / spend | 0 / 0 |

Trials execute sequentially and close their services before another starts.
Cancellation/deadline stops admission and cancels the current authority. There
are no retries or batch resumption. A partial batch remains incomplete; failed
infrastructure or accounting never earns correct-abstention credit.

## Saved evidence and independent grading

The root contains `manifest.json`, `evaluation.jsonl`, `planning-ledger/`,
`report.json` and `report.md`. Each admitted trial has `audit.jsonl`,
`runtime.json` and an `evidence/` assessment bundle. Files/directories must be
private and owned by the current user. Unexpected entries or changed identities
fail inspection.

The grader independently replays the existing assessment artifacts and case
oracle, then checks the exact new audit sequence. It binds canonical released
request bytes, TLS context digests, successful isolation/cleanup receipts,
ledger estimates/reservations/dispatch/settlement, eligible proposals and
execution evidence. Missing, changed, reordered or unknown events fail closed.
Session/lab/broker and trial scope identities must be unique across trials.
Per-case semantic fingerprints must agree across repetitions.

Trial grade hashes include only immutable trial-local costs. Later spending in a
sibling scope cannot change an earlier grade. During execution the grader uses
the existing ledger writer; final inspection opens a read-only handle only after
that writer closes. This avoids releasing SQLite process locks by closing a
second descriptor while a writer is active. The final report independently
checks batch ledger identity, fixed caps, allowed scopes and complete accounting.

The selected policy explicitly permits unattended owned actions. The approval
worker does not start, and no grant or human acceptance is claimed. The launcher
still verifies policy and the direct durable-intent witness. Approval-required
mechanics remain covered by their accepted dedicated tests.

The host, kernel and local persistence are trusted. Receipts are supervisor
observations, not cryptographic proof against the host owner. Linux tests also
observe real process teardown. Timings include namespace, TLS and accounting
overhead; they do not measure live-model latency or quality.

## Remaining acceptance gates

Passing this profile completes an offline integration comparison, not R5's
real-model acceptance or R6 operator acceptance. A later paid/live experiment
requires explicit authorization of data, model/endpoint, credentials and spend.
Ordinary development, CI and demos remain offline. Continue release preparation
under the disclosed offline fallback if live acceptance remains deferred; keep
actual operator review and the original milestone gates visible. Optional GUI,
session API, broader tools and additional scenarios remain deferred.

# R5b: durable provider cost ledger

R5b provides host-owned USD accounting and hierarchical spending admission for
the future provider broker and GUI. The existing R5a TLS foundation still uses
synthetic units. This slice adds no transport, API-key lookup, paid call or GUI.
The local demo uses a ledger explicitly marked `simulation`; its prices and
billing receipts are fictional.

## Accounting contract

All amounts are integer **microUSD**: 1,000,000 microUSD = USD 1.00. USD is the
only supported currency. Floating point, booleans, negative amounts and implicit
conversion are rejected. Budgets and individual amounts are bounded at 10^15
microUSD. `PriceCard` values are explicit; no provider prices are embedded.

| State | Meaning | Effect on available budget |
| --- | --- | --- |
| Estimated | Expected usage at a pinned price version | None |
| Reserved | Conservative cost ceiling held before transport | Subtract outstanding hold |
| Actual, usage-derived | Complete reported usage priced with the original card | Replace hold with calculated charge |
| Actual, billing-confirmed | Retained billing evidence, including corrections | Replace previous charge; preserve history |
| Unresolved | Dispatch began but complete usage/billing is unavailable | Retain full hold; actual remains unknown |

`available = max(0, limit - actual - outstanding reservations)`. Reports also show
overspending and overcommitment. An attempt's actual amount is `null` until known.
Aggregates sum known charges and expose `unresolved_attempts` and `actual_complete`;
a zero known total does not establish free execution when calls are unresolved.
Unsent cancellation records actual zero with source `not_sent`.

Input usage includes cached input, which is priced separately without double
counting. Output must include all billable output, including any charged reasoning
tokens. Rates are microUSD per million tokens plus an optional fixed request fee.
Integer arithmetic rounds the complete request upwards once to one microUSD.
Reservation uses the input/output ceilings and the more expensive input rate,
never an assumed cache discount. The estimate must fit those ceilings.

A provider/model price version is immutable. Every attempt retains its full card,
digest, estimate, ceilings and request digest. New prices do not change earlier
charges. Unsupported costs such as provider tools, media, storage, taxes or other
currencies require a reviewed extension or billing reconciliation, not an assumed
zero price. Usage-derived amounts remain distinct from confirmed bills.

## Hierarchical controls

One explicitly created ledger contains one account and a period label. The allowed
hierarchy is **account → engagement → session → optional agent → action**. Each
attempt belongs to an action. A child without a local cap inherits its ancestors'
constraints. A higher child cap never overrides a parent. Every reservation must
fit all applicable limits in one transaction, across threads and processes.
Reservation and dispatch denials retain the blocking scope and allowance in
durable events without changing costs, so the future timeline can explain them.

Reopening storage, constructing another broker or adding sessions does not
replenish parent budgets. Scope identities and parents cannot change. `set_limit`
records an explicit operator change with a stable idempotency key. Lowering a cap
below committed cost blocks further spending and preserves existing costs.
Dispatch rechecks the current limits, including overruns from other calls.

There is no automatic monthly rollover, timed release or reset. The period is an
explicit accounting label. All brokers sharing a budget must use the same
host-selected ledger. This slice cannot constrain another provider client or
separately created ledger directories.

## Trusted broker integration

Agents receive bounded views, never ledger handles, directory access, price
configuration or accounting mutation capabilities. A future provider broker must:

1. Validate the approved provider/model, released data, canonical request and all
   billable categories. Derive conservative input/output bounds from the specific
   provider contract. Byte length alone is not an input-token count. R5b supplies
   arithmetic, not the future model-specific estimator.
2. Call `estimate` with a host-generated attempt ID, action scope, exact request
   SHA-256, `PriceCard`, expected `TokenUsage` and token ceilings. A quote grants
   neither spending nor tool permission.
3. Obtain current policy/action approval, check cancellation/deadline, and call
   `reserve`. `BudgetExceeded` identifies the blocking scope, requested amount and
   available allowance. No transport may start on failure.
4. Finish launch audit and recheck execution control. Immediately before transport,
   call `begin_dispatch` with the same request digest. Only its first successful
   return grants the financial send claim; replay fails. This remains separate
   from tool authorization, credential isolation and data-release approval.
5. Call `settle_usage` only for complete cumulative usage, with a unique receipt
   reference and stable event ID. Partial usage, timeout, cancellation, missing
   usage and ambiguous failures keep the hold; use `mark_uncertain`. There are no
   automatic retries or refunds. A retry requires a fresh attempt and allowance.
6. Use `reconcile` for retained billing evidence. A reference identifies a unique
   billing line/revision, not a whole multi-call invoice. Receipt reuse across
   attempts is rejected. Identical events are idempotent; changed payloads conflict.
   Corrections need new references and event IDs. Old event replay cannot undo
   a newer correction.

`cancel` releases only estimates/reservations for which dispatch never began.
A crash after the dispatch claim conservatively leaves an unresolved call, even
if transport had not started. Opening the ledger never sends anything or restores
approval. Silence, elapsed time and provider errors do not establish zero charge.

Actual charges are recorded even when they exceed a reservation or budget. The
overrun remains visible and exhausted caps block later admission. Local controls
cannot undo an incurred charge or guarantee a provider's final bill. The future
adapter must enforce the bounds used for reservation and reject unsupported
billing modes; model-generated usage assertions are not accounting authority.

## Storage and GUI views

Standard-library SQLite `BEGIN IMMEDIATE` serializes admission. Each transaction
commits the accounting projection and its append-only event together. Write
failure never returns a send claim. The rollback journal uses
`synchronous=EXTRA` and `fullfsync=ON` where supported; see
[SQLite isolation](https://www.sqlite.org/isolation.html) and the
[synchronous contract](https://www.sqlite.org/pragma.html#pragma_synchronous).

Creation is exclusive; the parent directory must exist. Directory/file permissions
are 0700/0600. Symlinks, hard-linked databases, changed identities and public
permissions are rejected. Missing/corrupt stores fail closed. A handle cannot be
reused after a database I/O failure or across a process fork; each process opens
its own handle. Inherited handles are rejected before locking, rollback or close.
Database identity checks use filesystem metadata without a separate database
descriptor, preserving SQLite's process-wide POSIX locks; see
[SQLite's locking warning](https://sqlite.org/howtocorrupt.html#posix_advisory_locks_canceled_by_a_separate_thread_doing_close_).
Use local storage with working SQLite locks. The host owner,
SQLite and storage hardware remain trusted. Append-only events do not defend
against a compromised owner replacing or rewriting the database.

Inspection opens read-only and preserves clean database bytes/mtimes. A hot
rollback journal may require a normal accounting open for SQLite recovery first.
Recovery does not restore calls, approvals or allowances. No raw request/response,
credential, rationale, tool output or exception text enters the ledger. Receipt
references identify retained evidence; they are not fields for sensitive bodies.

`report(scope_id)` reads one consistent snapshot: currency, unit, period, ledger
mode, effective available allowance, limiting ancestor, the budget chain,
provider/model totals and latest event sequence. Token totals count recorded usage
only, with `attempts_with_usage` exposing incomplete coverage. `attempts` and
`events` provide bounded pages of up to 1,000 records. Parent totals already
include descendants; the GUI must not sum both. `estimated_microusd` covers all
recorded estimates, while `pending_estimated_microusd` covers unreserved work.
Provider charges remain separate from tool runtime and existing resource counters.

## Local commands

Print an inert plan, then create a **simulation** showing a settled charge, billing
correction, unresolved timeout and parent-budget denial:

```sh
.venv/bin/python scripts/secure_agent_cost_demo.py
.venv/bin/python scripts/secure_agent_cost_demo.py --ledger .secure-agent/cost-demo
.venv/bin/python -m recon_cockpit.secure_agent.cost_cli --ledger .secure-agent/cost-demo inspect
.venv/bin/python -m recon_cockpit.secure_agent.cost_cli --ledger .secure-agent/cost-demo attempts
.venv/bin/python -m recon_cockpit.secure_agent.cost_cli --ledger .secure-agent/cost-demo events
```

Configure an empty provider ledger with a USD 2 account cap and USD 1 engagement
cap (these commands make no provider calls):

```sh
.venv/bin/python -m recon_cockpit.secure_agent.cost_cli --ledger .secure-agent/provider-costs \
  create --account operator-account --limit-microusd 2000000 --period lifetime
.venv/bin/python -m recon_cockpit.secure_agent.cost_cli --ledger .secure-agent/provider-costs \
  add-scope --scope engagement-1 --parent operator-account --kind engagement --limit-microusd 1000000
.venv/bin/python -m recon_cockpit.secure_agent.cost_cli --ledger .secure-agent/provider-costs \
  inspect --scope engagement-1
```

`--help` describes `set-limit`, pre-dispatch `cancel` and evidence-backed
`reconcile`. These are trusted operator operations, never model proposal fields.
The next live-provider slice must wire this sequence into a reviewed transport
with explicit data/model/credential/spend settings before a paid pilot.

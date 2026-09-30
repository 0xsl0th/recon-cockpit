# Owned TLS assessment planning

This R5 slice carries the already reviewed planning descriptor through a
disconnected TLS fixture. It composes the PR #24 evidence and monetary gates
with the R5a isolation machinery. All responses, usage and credentials are
synthetic. There is no public provider endpoint, real credential source, paid
call, live activation flag or automatic retry.

## Ownership and data release

The trusted host still owns saved evidence, workflow eligibility, simulation
accounting and supervision. `EvidenceStore.record_decision` durably selects the
eligible action before the planning request is constructed. The release profile
is unchanged: only the repository-authored case, step, card identity and
canonical candidate without rationale leave the host. Raw response bodies,
evidence identifiers, engagement text and credentials are excluded.

The new `OwnedTLSAssessmentPlanningProvider` reuses the reviewed planning
provider's session lifetime, ledger transitions, isolated parser and exact
proposal comparison. Its fixed broker uses `LinuxOwnedPlanningTransport`, which
creates a new disconnected owner network and nested TLS worker for each attempt.
The sole destination is `127.0.0.1:8443`, with verified TLS identity
`provider.owned.invalid` and one `POST /v1/responses`. The owner receives a
generated synthetic key and ephemeral certificate through the existing private
bootstrap/mount boundary; the worker receives only the synthetic key and test CA.
The parser and coordinator remain networkless and credential-free.

The transport launcher, fixture owner and credential worker independently check
the closed planning request. The existing status-only transport and fixed ACK
diagnostic retain their separate contracts. Shared internal runtime helpers
select only repository-fixed profiles; callers cannot supply validator code,
module names, URLs, prompts, credentials or model configuration.

Nothing in the transport grants tool authority. The existing independent audit,
approval, admission and launcher checks remain required for execution. Model
output remains an untrusted proposal and cannot establish a finding.

## Accounting and failure behavior

The same fresh simulation ledger reserves the complete allowance and durably
consumes one dispatch claim before entering TLS runtime setup. Three calls at
most share the original deadline of at most 120 seconds. A failed call closes
the provider; restart, timeout and cancellation do not restore dispatch rights.

Transport receipts bind the attempt context, observed namespace/firewall checks,
one connection/request, and worker/owner cleanup. Success requires valid receipts
and observed teardown before the response is released for usage accounting.
Recognized usage settles before any response byte reaches the isolated proposal
parser. Refusals and substituted proposals with recognized usage are charged in
the simulation and then rejected. Known overruns settle before refusal.

Missing or unrecognized usage, TLS/HTTP errors, malformed replies and ambiguous
dispatch failures retain a durable hold. An audit failure prevents further work;
lost acknowledgements use the existing durable-state recovery rules. No failure
triggers a retry, refund, reconnect or in-memory fallback.

## Explicit CLI selection

Use a new evidence directory and separate new ledger directory; their parent
directories must exist. A planning dry run exercises the owned TLS exchange and
simulated accounting but starts no approval worker, tool executor or assessment
lab. Its local TLS fixture does run. For example:

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --workflow-assessment a --owned-lab \
  --policy examples/secure-agent-discovery-policy.json \
  --isolated-audit --isolated-approvals --isolated-launch-admission \
  --isolated-launcher --require-launch-audit --require-launch-approval \
  --assessment-planning-owned-tls success \
  --assessment-dir .secure-agent/tls-planning-evidence \
  --planning-ledger .secure-agent/tls-planning-cost \
  --audit .secure-agent/tls-planning-audit.jsonl --dry-run
```

`--assessment-planning-owned-tls` and `--assessment-planning-offline` are mutually
exclusive. Both require a workflow and all direct launch prerequisites. The
budget option remains explicitly simulated; no real pricing or billing claim is
made. The output identifies the transport, zero actual provider calls, simulation
costs and the last transport receipt. Per-attempt receipts remain in the audit.

## Verification and remaining gates

See [verification.md](verification.md) for measured portable and Linux results.
The six cases and both existing backends retain their outcomes. Adversarial tests
exercise request substitution, certificate/hostname failure, HTTP/framing errors,
credential reflection, usage ambiguity, cancellation, deadlines, audit loss and
cleanup. Scripted terminal responses establish approval mechanics only.

Installed code, the host bootstrap and kernel remain trusted. The fixed worker
implements one request; this is not a universal request quota against arbitrary
compromised worker code. Specific reflection checks do not detect every possible
secret encoding. Offline TLS tests establish neither provider compatibility nor
model usefulness.

The next R5 work is offline evaluation of this integrated planning path against
the preserved deterministic baseline. Actual model comparison remains pending
until the operator explicitly approves data, model, endpoint, credential and a
small spending budget. Ordinary development and CI continue without paid calls.
R6 follows the required acceptance gates, or an explicitly disclosed offline
fallback; optional GUI/API work and broader tools remain deferred.

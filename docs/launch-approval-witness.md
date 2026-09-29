# R5: independent fresh-approval verification

`--require-launch-approval` adds direct approval verification to the confined
launcher. It requires `--require-launch-audit` and all its isolated service
prerequisites. Existing defaults, tool profiles, targets, workflow card v2,
evidence schemas and provider/cost controls stay unchanged.

The approval worker owns the controlling terminal, challenges and single-use
grants. In this mode, trusted bootstrap binds a one-way Unix seqpacket channel
between that worker and the launcher. The host transfers the sending endpoint
with the terminal at the first review and closes it before READY. The receiving
endpoint is transferred once at lazy launcher startup, then closed in the host.
Until review starts, the trusted bootstrap retains the sender; creating this
channel opens no terminal and starts no process. Before an approval-required
launcher starts, bootstrap closes any sender not transferred to the worker.
Skipping review therefore ends in EOF, even if a host queues forged proof first.
Policy-allowed actions need no worker or approval proof. Kernel shutdown seals the unused
direction of each endpoint. Tools, admission workers and coordinators receive
neither endpoint. No signing key, listener or host request flag authenticates consent.

Only successful consumption of a grant issued after the existing unpredictable
terminal challenge sends a witness. It binds the broker, session, full policy
and action digests, action ID, witness/consumption sequences, issue time and
original grant expiry. The reference itself is not sent to the launcher.
Consumption burns the grant even if a subsequent write or acknowledgement fails.
It never refreshes the TTL. The effective deadline is the earliest of original
expiry, session deadline and five seconds after witness issue.

The launcher independently evaluates its immutable policy. For an
approval-required action, it must consume exactly the next matching, unexpired
witness after verifying durable audit intent and before admission. It rechecks
freshness after permit redemption, immediately before calling the fixed executor
path. A policy-allowed action requires no approval or terminal startup; an
unsolicited approval witness or a closed channel still fails. A denied action
cannot become allowed through a grant.

Missing, forged, stale, replayed or mismatched proof, changed/extra/missing
descriptors, bootstrap downgrade, producer exit or unexpected queued output
permanently stops the launcher, without retry, reconnection, refund or fallback.
If expiry occurs during admission, the reservation remains consumed. Host
snapshots retain only previously acknowledged totals after a lost completion;
they do not prove that no reservation or execution occurred.

This removes reliance on the controller's claim that it consumed approval.
It authenticates the selected fixed worker's result, not a person's identity
or intent independently of that worker and terminal. Trusted bootstrap, fixed
workers, host account/kernel and the operator-selected policy remain trusted.
Host compromise or replacing those workers is outside the contract. No claim
of immunity to malicious terminal owners or a compromised approval worker is made.
Scripted PTYs are mechanics fixtures, not actual operator acceptance.

An offline dry-run with a new private directory:

```sh
.venv/bin/python -m recon_cockpit.secure_agent --workflow-assessment a --owned-lab \
  --isolated-audit --isolated-approvals --isolated-launch-admission --isolated-launcher \
  --require-launch-audit --require-launch-approval \
  --policy examples/secure-agent-discovery-policy.json --dry-run \
  --assessment-dir .secure-agent/approval-witness/evidence \
  --audit .secure-agent/approval-witness/events.jsonl
```

Dry runs start no approval worker, launcher, admission worker, lab or tool.
Noninteractive approval-required execution fails closed. All verification uses
owned/mock fixtures and synthetic credentials, with no external provider calls
or spend. Live execution stays disabled. After review, bounded assessment
planning on R5a/R5b is next; real-model acceptance needs explicit authorization
before R6 evaluation/operator review/packaging/demo. Optional expansion stays deferred.

# R5: isolated launch admission

## Authority decision

After merged PR #18, terminal review/grant state and audit persistence can live
in separate workers. Policy admission and execution budgets still live alongside
the host launcher. This slice moves an additional, mandatory policy/budget gate
and one-use launch permits into a fixed Linux worker. The host retains a narrow
admit/redeem client and the existing launcher. A policy decision or counter
claimed by a request cannot replace the worker's own fixed bootstrap policy,
mode, scope, limits, deadline or state.

The selected backend wrapper requires a fresh permit and successful redemption
bound to the exact action, policy and session before calling its existing
executor. Admission reserves full step/output allowances without refunds;
redemption burns a permit before checking a changed action or policy. Missing,
replayed or expired permits, exhausted limits, protocol faults and lost replies
cannot launch or replenish the worker's counters. Neither reconnect nor reset
exists. The existing backend and executor continue their own checks as well.

This worker has no terminal, human grant store, audit file, credentials, executor
code or target network. Human-grant consumption and durable execution intent
remain separate controller preconditions. The new boundary independently enforces
policy and execution limits; it does not independently attest human consent or
audit truth. A compromised host can bypass its own wrapper or create another
session. Independent launcher custody remains further R5 work. This statement
does not claim full host-compromise containment or completion of all R5.

## Integration and verification scope

The explicit `--isolated-launch-admission` option applies only to existing
authority sessions and owned assessments. It requires the isolated approval and
audit options so the selected path composes the established boundaries. Fixed
fixture/discovery/owned-lab profiles preserve their existing scope; there is no
new tool, routed target, provider activation, GUI or generic service registry.
Construction and dry-run do not start the admission worker. Live providers
remain disabled and verification uses owned/mock fixtures only.

Portable verification covers exact schemas, bootstrap binding, policy/profile
denial, step/output budgets, replay, expiry, changed actions/policies, fixed
controls and poisoning. Linux verification covers actual confinement, absent
host capabilities, forged messages/receipts, cancellation/deadline cleanup and
combined authority/approval/audit/executor behavior. Existing R1–R4 and R5a/R5b
contracts stay closed. Bounded planning integration follows the remaining R5
authority work; live acceptance is gated, then R6 consolidates the release.

## Bounded process and protocol

Trusted bootstrap pins configuration and the original monotonic deadline using
a digest in argv and a private Unix sequenced-packet channel. The worker checks
private namespaces and descriptors, zero capabilities, `no_new_privs`, resource
ceilings and socket/process/namespace restrictions before READY. It sees only
the established distribution Python runtime and fixed bootstrap, protocol/state
and model modules. After setup, new opens, descriptor mode changes, ioctls,
connection operations and descriptor sending are denied. No terminal or extra
descriptor can be supplied on init or later requests. Diagnostic check booleans
and digests are not remote attestation.

The fixed configuration includes session/service identities, a complete parsed
policy, execute/dry mode, step/runtime/output limits and one fixture profile.
Plain fixtures allow only owned loopback HTTP; discovery fixes the existing
single-port TCP/HTTP topology; persistent labs also fix the existing case paths
and HTTP profile. Every request independently parses the action, requires the
next sequence number and binds policy/session/service identity. Unknown authority,
budget, command or configuration fields cannot replace worker state.

Packets are at most 32 KiB, replies at most 2 KiB and aggregate pipe output at
most 64 KiB. There are at most 32 admit/redeem exchanges and 16 admitted actions,
further reduced by the immutable session limits. The session lasts at most
600 seconds. Worker startup has a ten-second host ceiling; each RPC has a
five-second ceiling, both shortened by the session deadline. A random 256-bit
permit expires after five seconds or at session end, whichever is earlier.
Successful redemption consumes it before the existing launcher runs; execution
still has the original session/action deadlines.

The client checks request-bound receipts and monotonic counter deltas. Its
read-only snapshot is only the last acknowledged diagnostic state, never the
source of admission authority. Lost replies poison the client without retries;
an uncertain reservation/redemption cannot authorize a launch. The wrapper
also stops on concurrent calls and checks cancellation after redemption.
Cleanup kills/reaps the worker and destroys outstanding permits. The thread
that starts the worker must remain alive through use, as required by the existing
Bubblewrap parent-death protection. Kernel stalls/host compromise remain outside
this contract.

## Ordering, usage and limits

For the selected CLI path, Controller consumes any required human grant and
records durable execution intent before the wrapper admits and redeems the action.
An admission failure can therefore leave a recorded intent followed by a blocked
completion without any tool launch. It uses the existing `isolation_unavailable`
failure and evidence schemas. The independent gate is an additional check; the
existing host executor and fresh isolated executor keep their own revalidation.

An inert tool dry-run can select all three boundaries:

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --control-plane-mock three_step --fixture --dry-run \
  --isolated-audit --isolated-approvals --isolated-launch-admission \
  --audit .secure-agent/launch-admission/events.jsonl
```

The coordinator/audit worker run normally; approval/admission workers and tool
execution stay inert. Existing owned assessment modes can select the same flags.
Execution still requires the selected owned backend and any policy-required
interactive approval. Read-only inspection, evaluation batches, legacy sessions
and routed targets do not accept this option.

These are per-session, in-memory tool resource allowances, not monetary charges
or durable engagement quotas. No automatic reconnect/restart or refund API exists;
a trusted host can construct a new session. R5b financial admission and provider
usage settlement are unchanged. Validation results and publication state are in
[verification.md](verification.md) and [continue-here.md](continue-here.md).

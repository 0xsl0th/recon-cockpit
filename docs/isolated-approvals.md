# R5: isolated approval issuance

## Authority decision

The next slice after PR #17 moves terminal review, unpredictable challenges and
single-use grant storage/consumption into one fixed Linux worker. The host
retains an opaque review/consume client, policy evaluation, accounting and launch
decisions. The worker independently parses each action and checks a policy fixed
at bootstrap. A caller-supplied boolean or reference cannot mint a grant.

The worker receives one controlling-terminal descriptor opened by trusted host
bootstrap. It displays the canonical action without rationale, binds the review
to action/policy/session identities, flushes old input and requires a fresh
random challenge. It owns grant expiry and burns each reference on a consumption
attempt. No issue-without-review, reset, policy-update or reconnect operation is
available. A new worker does not inherit grants from an earlier session.

The worker gets no audit storage, executor, provider credentials or target
network access. Fixed namespace, descriptor, runtime and syscall restrictions
prevent network/process creation and terminal input injection. The terminal is
an intentional capability, not an ambient host mount. Prompt/answer handling is
bounded by the existing session deadline and cancellation. Failure permanently
closes the service and prevents subsequent authority work, without local approval
fallback. Noninteractive execution cannot manufacture approval.

This separates approval issuance and state; it does not yet make the executor
independent of a compromised host launcher. Trusted bootstrap still chooses the
policy and terminal, the host user controls that terminal, and a compromised
approval worker could lie about human consent. Hashes bind requests, not human
intent. Further launch authorization remains the next R5 boundary; bounded
assessment planning follows before R6. No completed milestone is reopened.

## Integration and verification scope

The explicit `--isolated-approvals` option applies to existing authority sessions
and owned assessments. It composes with `--isolated-audit`; both options leave
existing defaults and tool/provider scope unchanged. Construction and dry runs
are inert. The first review uses only `/dev/tty`, never proposal/stdin input.
No credential, external-provider or paid call is enabled.

For an inert approval-path check with the existing owned coordinator:

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --control-plane-mock three_step --dry-run --isolated-approvals --isolated-audit \
  --audit .secure-agent/isolated-approvals/events.jsonl
```

Dry-run creates the normal audit evidence and coordinator, but no approval worker
or terminal access. Executing an existing owned workflow with the option still
requires an interactive terminal when its policy requires approval. No new
auto-approval switch, terminal path, provider mode or assessment source exists.

## Process and protocol contract

Trusted bootstrap opens only `/dev/tty` read/write, nonblocking and without
acquiring a new controlling terminal. It passes that one descriptor over a private
Unix sequenced-packet socket and closes its copy. No terminal path is mounted.
The fixed worker independently verifies private namespaces, zero capabilities,
`no_new_privs`, descriptor type/identity and syscall restrictions before READY.
The initial policy, session/worker identities, terminal identity and absolute
monotonic deadline are bound to a bootstrap digest supplied in trusted argv.
These hashes and diagnostic check booleans are not remote attestation.

Only bounded `review` and `consume` packets are accepted: exact schemas, canonical
UUIDs, increasing sequence numbers, policy digest and a fully parsed action.
Replies bind to the entire request digest. Limits are 32 KiB per packet, 2 KiB
per reply, 64 KiB cumulative pipe output, 16 reviews, 32 exchanges and the original
session deadline (at most 600 seconds). Startup and consumption have additional
10/5-second host waits. Review input is at most 128 bytes; each grant is random,
expires under the fixed policy's monotonic TTL and is consumed atomically.
Neither input text nor challenges are forwarded to planners or audit records.
The existing consumed-reference audit field remains unchanged.

The runtime uses the established read-only distribution Python mounts, a fixed
set of modules, private user/network/PID/mount/IPC/UTS/cgroup namespaces, resource
ceilings and socket/process/namespace restrictions. After startup it also denies
new file opens, descriptor flag changes, socket connection operations and terminal
ioctls except input flushing on the received descriptor. No caller-selectable
code, policy replacement, replay lane or approval restoration is available.

The client pins the original execution-control object; reconnecting or renewing
the deadline is not supported. Its launch-owning thread must live through service
use, as required by Bubblewrap's parent-death protection. Session cancellation
and deadline checks cover terminal waiting and both sides of receipt validation.
Cleanup kills/reaps the worker and destroys outstanding grants without renewing
the execution deadline. Kernel/runtime/host-owner compromise is outside the boundary.

## Verification

Verification uses owned pseudo-terminals and mock responses, clearly identified
as grant-mechanics fixtures rather than human approvals. Portable checks cover
strict message schemas, binding, replay, expiry and fail-closed integration;
Linux checks cover actual confinement, descriptor and terminal restrictions,
cancellation, failure cleanup, audit ordering and owned fixture execution.
Results and current publication state belong in [verification.md](verification.md)
and [continue-here.md](continue-here.md).

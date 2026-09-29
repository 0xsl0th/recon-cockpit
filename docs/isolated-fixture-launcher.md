# R5: confined fixture launcher

## Authority and scope

After PR #19, an independent admission worker owns fixed policy/profile checks,
execution reservations and one-use permits, but the host wrapper still holds the
permit client and builds executor launches. `--isolated-launcher` moves that
client, permit redemption, launch-envelope construction and executor supervision
into a fixed Linux worker. The host retains a typed `execute` client and last
acknowledged diagnostic counters. It does not receive permits, select a command,
build an executor envelope or invoke the fixture executor directly on this path.

The launcher starts its own separate admission worker using the existing PR #19
protocol and state machine. Every execute request must receive and redeem a fresh
permit before a fresh executor is created. The launcher owns sequence state; the
admission worker owns reservations. Changing host-side counters or limits after
bootstrap cannot reset either service. The existing executor independently checks
the canonical action, policy, profile, limits, deadline and private namespaces.

This bounded slice supports the existing `--fixture` HTTP and discovery profiles,
including all six fixed workflow cases. It requires `--isolated-launch-admission`,
`--isolated-approvals` and `--isolated-audit`. Construction and dry-run do not start
the launcher. Persistent `--owned-lab`, routed targets, legacy execution and
evaluation batches do not accept the new option; their existing modes remain
unchanged. There is no new tool, provider activation, general registry or GUI.

The host controller still consumes human grants and records durable intent before
sending an execute request. The launcher does not accept approval/audit booleans,
and does not independently authenticate the truth of those preconditions. The
operator, trusted bootstrap and fixed launcher remain in the trusted computing
base. A compromised host can bypass its own client or create another session;
this does not contain the host user. The launcher cannot make untrusted tool
output into proof of consent or an independently truthful audit trail.

## Confinement and intentional capabilities

The launcher has private user, mount, PID, network, IPC, UTS and cgroup namespaces,
a nonzero namespace UID/GID, zero capability sets and `no_new_privs`. Its network
namespace contains only loopback; it has no host listener, route, DNS, transport
or network-namespace descriptor. Its environment is cleared. Startup rejects
inherited descriptors beyond the private request socket and output pipes, before
runtime imports can open their own library descriptors. It has no terminal,
approval store, audit file, credentials, host home or repository mount.

The read-only filesystem contains an explicit distribution Python/library closure,
non-setuid Bubblewrap, nft and fixed launcher/admission/executor modules. No shell,
ldd executable, arbitrary module path or plugin selection is exposed. The host
computes that closure during trusted bootstrap; its exact manifest and fixed
configuration are committed in argv and checked against the initialization packet.
Initialization is not a request-time mount API. Digests and diagnostic booleans
are consistency checks, not remote attestation.

Launching requires capabilities unavailable to the admission worker: process and
nested-namespace creation remain possible in this trusted worker. A private
1 MiB `/tmp` supports Bubblewrap setup, and private `/proc` permits child UID/GID
map writes. The root and `/dev` are read-only. Admission and executor children
retain their established separate, read-only `/proc` mounts and syscall filters.
Admission gets neither Bubblewrap nor nft executables; executors get no admission,
approval, controller or audit modules. Namespace setup never changes host networking.

The launcher applies 256 MiB address space, 30 CPU seconds, 128 descriptors,
zero core dump size, 1 MiB file size and 64-process resource limits. The worker
must remain trusted; these bounds and the mounted runtime do not promise safe
execution of arbitrary launcher plugins. Child admission and tool limits are
unchanged. The host supervises the outer process, and killing its private PID
namespace reaps nested admission and executor trees, including separate process
groups. The launching thread must stay alive through use, as required by the
existing Bubblewrap parent-death protection.

## Protocol, failure and evidence

One immutable bootstrap fixes policy, session/service identities, fixture profile,
execution mode, limits and the original monotonic deadline (at most 600 seconds).
Every request has the next sequence number, a typed action and policy digest.
Only `execute` exists, with at most 16 requests, shortened by the session budget.
Unknown fields, changed sessions/policies, replay, reset, permits, shell commands,
approval claims and extra descriptors are rejected. There is no reconnect,
resume, refund, arbitrary command, live-provider or configuration-update operation.

Initialization/requests are at most 32 KiB; replies are bounded to 425,984 bytes
plus their line delimiter, with aggregate output bounded to 16 times that size
plus 4 KiB. JSON is ASCII, single-line, duplicate-key/NaN rejecting and exact
at the envelope level. Request-bound receipts include the established untrusted
tool result and monotonic reservation counters. Existing backend names and
evidence schemas are preserved. The nested admission worker keeps its five-second
RPC/permit limits. Launcher startup has a ten-second supervision ceiling after
bounded runtime discovery; each execute RPC has action timeout plus eighteen
seconds for nested setup, always shortened by the original session deadline.

Invalid messages, missing workers, forged receipts, output floods, cancellation,
deadline expiry or uncertain completion permanently close the client, kill/reap
the worker tree and refuse subsequent work. No error falls back to host execution.
Admission failure cannot launch the action. An execution may already have happened
when its reply is lost: the last acknowledged host snapshot is diagnostic only,
and replay would be unsafe. The worker retains reservations until destruction;
there is no retry or refund. An intent may therefore end with a blocked completion
or incomplete evidence. Kernel stalls and compromise of trusted components remain
outside the bounded cooperative-cleanup claim.

## Offline use and remaining work

An inert tool dry-run selects all four boundaries:

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --control-plane-mock three_step --fixture --dry-run \
  --isolated-audit --isolated-approvals --isolated-launch-admission --isolated-launcher \
  --audit .secure-agent/fixture-launcher/events.jsonl
```

The coordinator/audit run normally; no approval, admission, launcher or tool
worker starts. Executing owned fixtures still needs the existing execute option
and any policy-required fresh terminal approval. Scripted PTY tests establish
mechanics, not actual human consent. Live providers remain disabled; development
and verification use only owned/mock fixtures and synthetic credentials.

This advances R5 launcher custody for fixture profiles. The persistent lab still
uses its established host launcher; remaining authorization/launch integration
and bounded assessment planning precede explicitly gated live-model acceptance
and R6. Accepted R1–R4, R5a/R5b and audit/approval/admission contracts remain closed.
The R5b monetary ledger is unchanged. See [verification.md](verification.md) and
[continue-here.md](continue-here.md) for evidence and review state.

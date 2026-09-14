# Privilege-separated control plane: first slice

Status: implemented as the explicit `--control-plane-mock` path. It uses fixed
deterministic scenarios and owned, isolated HTTP fixtures. Live model calls and
credential access remain disabled. Earlier session modes retain their existing
boundaries; selecting this path never falls back to them.

## Security objective and authority ownership

Assume arbitrary code execution in the session coordinator after bootstrap.
That process must be unable to issue human approvals, change operator policy,
choose execution mode, reset accounting, reach the executor directly, or read
and modify the authority's audit file. It can submit arbitrary bounded proposals,
consume the session's existing allowance with policy-authorized actions, provide
misleading observations, and terminate or stall its own session.

The authority and execution launcher remain trusted in this first slice. The
implementation does not claim containment of arbitrary code execution in that
host process or of a compromised host user, root, runtime, or kernel.

| Domain | Owned authority | Input from the coordinator |
| --- | --- | --- |
| Trusted bootstrap and authority, host process | Operator policy, session identity, fixed mode and limits, absolute deadline, approval store, durable audit sink, executor launcher | Versioned proposal envelope only |
| Trusted human UI, host process | Controlling terminal and exact-action approval challenge; single-use approval issuance | None directly; review is reconstructed from the authority-validated action |
| Coordinator, persistent Linux sandbox | Its private memory, bounded temporary storage, proposal/result pipe endpoints | Bounded previous observation, session identity, sequence acknowledgement, stop instruction |
| Executor, fresh Linux sandbox for each launch | Owned fixture setup, then restricted HTTP execution | None; a separate private pipe receives the authority's bound launch envelope |
| Provider broker and separate audit writer, future slices | Provider-only credentials/egress/budgets; audit-only storage ownership respectively | Not connected to this coordinator path yet |

Policy, human UI, accounting, audit and the host launcher still share one trusted
process. Moving the coordinator out reduces exposure to proposal sequencing and
result handling; it does not make the remaining services independently isolated.
The API credential broker and independently protected audit storage are separate
follow-up work, with explicit compromise analysis before their introduction.

## Coordinator confinement

The launcher uses a non-setuid Bubblewrap under an unprivileged Linux user. It
creates private user, network, PID, mount, IPC, UTS and cgroup namespaces, drops
all capability sets, clears the environment, detaches the controlling terminal,
and closes inherited descriptors. It mounts an explicit distribution Python
runtime and four fixed, read-only coordinator/bootstrap modules. Host policy,
home directories, credentials, audit files, executor code and networking helpers
are absent. There is no configurable executable, module path, host mount or
network endpoint.

Before reading INIT or loading planner code, the fixed bootstrap verifies the
namespace identities and capabilities, installs `no_new_privs`, resource limits
and seccomp restrictions, and verifies that socket/process/namespace creation is
blocked. Process tracing and cross-process memory syscalls are blocked; the
private PID namespace does not expose authority processes. Root is read-only;
temporary storage is capped. Before loading the runtime bootstrap, the
coordinator checks that descriptors 0–2 are pipes, no additional inherited
descriptors survive, and `/dev/tty` is unavailable. The trusted runtime can
subsequently open its own read-only mounted library descriptors.

READY carries the seven existing bootstrap check booleans. These are diagnostics
from fixed bootstrap code, not remote attestation or an authorization grant. The
host's launcher configuration establishes the boundary. Failures never enable a
portable or host-execution fallback.

## Coordinator IPC contract

Bootstrap assigns anonymous pipes directly to the child. There is no named
socket, listener, role selector, reconnect operation or shared authentication
secret. Only the coordinator endpoint can produce coordinator messages; it
cannot acquire the unrelated executor endpoint through this protocol.

Frames contain a four-byte big-endian length (including the one-byte kind), a
kind byte, and bounded UTF-8 JSON. Duplicate keys, non-JSON constants, unknown
fields, incorrect types and unsupported versions are rejected at their owning
boundary. No Python object deserialization or arbitrary RPC is available.

| Direction / kind | Maximum payload | Exact payload fields |
| --- | ---: | --- |
| Authority → coordinator INIT (1) | 512 bytes | `schema_version`, `session_id` |
| Coordinator → authority READY (5) | 1,024 bytes | `schema_version`, `boundary_checks` |
| Coordinator → authority REQUEST (2) | 20,480 bytes | `schema_version`, `session_id`, `sequence`, `plan` |
| Authority → coordinator RESPONSE (3) | 12,288 bytes | `schema_version`, `session_id`, `sequence`, `stop`, `observation` |
| Coordinator → authority RESULT (4) | 512 bytes | `schema_version`, `session_id`, `status` (exactly `closed`) |

The state machine is INIT → READY → (REQUEST → RESPONSE)* → RESULT → clean EOF
and zero process exit. Only a host RESPONSE with `stop: true` permits RESULT.
READY and the first REQUEST may share a read because READY needs no separate
acknowledgement. Request pipelining, unexpected frame kinds, trailing data and
partial EOF fail closed. Writes are nonblocking, stdout/stderr have cumulative
limits, stderr is capped at 4,096 bytes, and the supervisor allows at most 17
requests. The authority imposes its tighter operator step limit (maximum 16).

Each REQUEST must name the existing session and the next integer sequence.
`plan` contains exactly `schema_version`, `action`, and boolean `done`; an absent
action requires `done: true`. Actions undergo the existing strict schema and
policy checks. No grant, `interactive`, `execute`, policy update, audit event,
budget reset, deadline, backend, command or file path is an IPC operation.

The authority counts attempts and reserves each policy-accepted action's full
output allowance before approval. Reservations are never refunded after denial,
failure or cancellation. The deadline is created once, before coordinator
startup, and covers bootstrap, approval waits and execution supervision. Policy
denial, execution failure, exhaustion or a protocol fault closes the session.
Protocol poisoning also cancels outstanding authority work. The instance cannot
be reused. A service restart abandons its session; fresh sessions require the
trusted bootstrap path and are not an operation available to the coordinator.

RESPONSE contains only a bounded previous-result excerpt and execution status.
Approval references, policy objects, raw audit records and execution handles do
not cross this boundary. Final summaries and audit events are constructed by the
authority. A coordinator `status: closed` cannot invent successful tool actions;
failure to finish the protocol overrides an apparent session completion.

## Authorization and executor IPC

The host Controller independently evaluates every action, verifies any required
single-use human grant, checks backend availability, and durably records
`execution_started` before calling the authorized backend. An approval remains
bound to the complete action and policy digests, has monotonic expiry, and is
consumed even if execution subsequently fails. Its reference is never sent to
the coordinator.

The new backend fixes policy, session, execution mode and resource ceilings at
construction. It independently checks them and keeps nonrefundable launch/output
reservations. Each launch receives a fresh random nonce and a digest of the
complete canonical launch envelope through trusted argv. The envelope travels
over a separate bounded private stdin pipe and binds the action, policy, their
digests, session, sequence, mode, limits, reservations and absolute deadline.

The executor accepts one complete request and EOF. It checks the expected nonce
and context digest, parses the exact schemas, independently evaluates policy,
checks owned-fixture restrictions and resource bounds, and rejects expiry before
fixture execution. Cancellation or timeout causes the host supervisor to kill
and reap the sandbox. There is no routed backend in this slice.

The nonce and context digest provide per-launch binding; they are not a signature
or authorization supplied by the coordinator. Authentication comes from trusted
bootstrap retaining exclusive custody of argv and the executor pipe. The host
adapter remains trusted, and its compromise can bypass host approval logic. The
executor's network and filesystem restrictions still constrain its assigned
fixture scope; they are not a guarantee against kernel compromise.

## Failure and compromise expectations

| Event / compromise | Expected consequence |
| --- | --- |
| Coordinator sends forged approval, policy, mode or accounting fields | Schema rejection; no new execution |
| Coordinator replays a request or names another session | Permanent protocol failure; no replayed execution |
| Coordinator reconnects, resets sequence, or continues after stop | No reconnect/reset endpoint; reused/closed session rejected |
| Coordinator exits, hangs, floods output, or truncates a frame | Session fails or expires; child is killed/reaped; no fallback |
| Audit intent cannot be persisted | No new execution; audit failure poisons the authority |
| Approval expires, action changes, or a grant is reused | Approval rejected; no launch |
| Session expires during approval, discovery or audit | Control is rechecked before launch; no later launch |
| Coordinator lies about results or completion | Host counters and execution audit remain authoritative |
| Host authority / launcher compromised | Its combined policy, approval, audit and launch authority is exposed; outside this slice's containment claim |
| Future audit writer compromised | It could omit or fabricate its own records; independent storage cannot establish truth of a compromised producer's claims |

## Running and verification

Validate a three-step session through the real coordinator boundary:

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --control-plane-mock three_step --dry-run
```

Execute only the owned fixtures, with fresh terminal approval under the example
policy:

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --control-plane-mock three_step --fixture --execute
```

The adversarial demo uses explicit fixture-only policies and never manufactures
human approval. Its dry-run mode checks protocol and accounting; execution mode
also exercises the independent executor and injected fixture responses:

```sh
.venv/bin/python scripts/secure_agent_control_plane_demo.py
.venv/bin/python scripts/secure_agent_control_plane_demo.py --execute-fixtures
```

Portable tests cover authority decisions, forged fields, replay, accounting,
approval binding, audit failure, framing, cancellation and cleanup. Opt-in Linux
tests exercise actual namespace/seccomp boundaries and owned fixture execution.
Test doubles validate control logic only and are not evidence of OS isolation.

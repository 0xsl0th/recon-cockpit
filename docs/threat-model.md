# Threat model — bounded mock sessions, fixture and routed HTTP

## Assets and trusted components

Assets: operator credentials and filesystem, authorized destination scope,
approval integrity, execution resources, and an accurate audit trail. The trusted
computing base includes the operator/controller process, installed project code,
policy file, Python, Linux kernel, Bubblewrap, nftables and runtime libraries.
Routed execution additionally trusts slirp4netns/libslirp and the fixed resource
limiter. A compromised transport with host-network socket access is outside this
contract; worker filtering does not sandbox that transport's own destinations.
The operator owns a private audit directory and reviews any policy changes.

The planner's proposal, target HTTP responses, and imported content are untrusted.
Legacy scan imports are not connected to the secure execution interface. Any
future import adapter must produce proposals that traverse the same controller.

## Attacker capabilities and boundaries

| Attacker capability | Control | Residual limitation |
| --- | --- | --- |
| Arbitrary proposal JSON, shell strings, extra fields | Strict typed schema and immutable action | Trusted Python callers are not a security boundary |
| Out-of-scope IP/CIDR, DNS aliases, redirects | Literal-address policy, no DNS/redirects, kernel destination firewall | Fixture or one routed IPv4 literal; routed CIDRs/IPv6 and synthetic transport aliases refused |
| Forbidden methods/ports, huge ranges or parameters | Tool-specific bounds, default-deny policy | GET/HEAD can still have side effects on a badly designed service |
| Reuse, delay, or alter an approved action | Full action/policy digests, monotonic expiry, atomic consumption | Human/controller compromise is outside this milestone |
| Submit approval flags via agent or pipe input | Unknown-field rejection, controlling-terminal UI, unattended fail-closed | A trusted operator can deliberately configure allow without approval |
| Return prompt injection, forged tool calls, secrets or terminal escapes | Result remains untrusted feedback; every follow-up traverses schema, policy, required approval and audit; raw content omitted from logs/UI | Specific fixtures do not establish universal prompt-injection immunity |
| Hang, flood output, or compromise executed probe code | Deadlines, byte/resource caps, read-only runtime, zero capabilities, seccomp | No separate kernel or VM boundary; no protection from kernel exploit |
| Try direct sockets to a different destination/port | Per-action nftables rules inside the execution namespace | Routed helper is trusted; operator routes must already exist |
| Make audit unavailable | Synchronous pre-execution audit; poison controller on audit errors | Already sent traffic cannot be rolled back if completion logging fails |
| Propose indefinitely, underreport output, or stall during planning/approval | Single-use session, attempt limit, full response reservations without refunds, shared deadline and cancellation | Trusted filesystem/kernel stalls are not hard-preemptible; restarting creates a new session budget |

The mock is deterministic bundled code, not an autonomous model. Its JSON is
untrusted even though its implementation is known. It runs in a separate process
with no inherited credential environment or tool handles; arbitrary hostile
provider code is **not** supported by that process boundary. A real model provider
requires separate sandboxing, mediated network access and credential handling.

## Isolation assumptions

Use a dedicated Linux/Kali lab with unprivileged user namespaces and a compatible
non-setuid Bubblewrap. Bootstrap capabilities exist only in the newly created
user/network namespace and are dropped before probing. The executed worker does
not see host homes, `/run` sockets, policy/approval/audit state, or broad host
mounts. Do not add such mounts when adapting the backend.

Routed mode uses a second minimal Bubblewrap boundary for its trusted slirp
transport, with empty `/etc` and `/run` instead of host mounts. Namespace-local
setup capabilities permit TAP configuration; slirp drops them except
`CAP_NET_BIND_SERVICE` and installs its own syscall filter before readiness.
Host-loopback translation and built-in DNS are disabled. The provider cannot
select helper options or receive namespace/control descriptors. The worker is
released only after firewall installation, privilege drop and transport readiness.
See [routed-http.md](routed-http.md) for the complete lifecycle and residual risks.

The demo's forbidden destinations are **owned reachable witnesses** on another
loopback address and port in the namespace. A failed connection to an absent
service alone is insufficient evidence of filtering. Integration tests also
exercise direct socket calls under the same rules; policy-only tests cannot
establish kernel enforcement.

Routed tests place their services in a disconnected outer lab namespace, outside
the worker. Each forbidden witness first succeeds through a separately authorized
single-destination routed action. Subsequent direct forbidden sockets must fail,
and witness connection counts must stay unchanged. This proves a real TAP/slirp
path and filtering in the owned lab; it does not validate a real VPN target.

An ordinary Docker network is not a destination firewall. If a disposable
container is used to host the Linux tests, its role is the test environment;
Bubblewrap/nftables still provide the execution boundary being tested. Never
mount the Docker socket into either planner or tools. Never enable a privileged
container or weaken host security silently to make a test pass.

## Known limits and non-goals

- Fixture mode remains namespace-owned loopback only. Routed mode supports one
  policy-authorized canonical IPv4 literal/TCP port using existing operator
  routes, while every CIDR action (including /32), IPv6 and selected special or
  transport-local ranges fail closed. No hostname/DNS-rebinding handling, TLS,
  Nmap, credentialed tools, exploits or arbitrary command execution.
- No real-model/autonomy evaluation yet; no claim of universal prompt-injection
  immunity or resistance to a malicious Python plugin inside the controller.
- No protection against malicious operator, controller-code modification,
  same-user host compromise, root, kernel vulnerabilities, or compromised
  runtime dependencies. The old host runner remains available to the human and
  must never be exposed as an agent escape route.
- Local owner/root can rewrite/delete logs. Content digests and hash chaining
  cannot prevent a compromised host from rewriting history. Future remote
  append-only collection must include independent access control and retention.
- Approval state is session-local, not a distributed approval service. Restart
  invalidates grants. Clock expiry uses monotonic time, not audit UTC timestamps.
- Resource limits bound individual executions and each mock session. Sessions
  have attempt, deadline and reserved-output limits, but no persistent per-user
  budget/rate limiting, scheduling, distributed concurrency quota, or remotely
  authenticated submission API. Cleanup may finish after the session deadline;
  audit/fsync and kernel stalls cannot be safely hard-preempted. Session CLI
  currently supports owned fixtures only; routed sessions remain future work.
- Network byte limits distinguish captured response bytes from protocol overhead;
  audit metadata is intentionally lossy and excludes raw forensic response text.

## Validation plan

Portable tests cover schema, policy, approvals, audit failure, malicious result
handling and legacy regressions. Test doubles prove controller behavior only.
Opt-in Linux integration tests run real namespaces, fixture requests, deadline
and output cases, and socket-level out-of-scope attempts. Keep run evidence and
skips separate. A Linux backend that was merely inspected or mocked is not
validated isolation. Track the actual run record in the README/verification doc.

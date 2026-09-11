# Recon Cockpit — Secure Agent Mode

Secure mode has a dedicated command, `python -m recon_cockpit.secure_agent`.
Milestone 1 established isolated individual actions; milestone 2 adds bounded
mock planning sessions. The existing interactive cockpit and case formats remain
intact. These milestones validate deterministic mocks and security controls,
not an autonomous model.

## Repository assessment

The existing `runner.py` validates individual IPs, constructs argument arrays,
and restricts custom Nmap options. `cli.py` provides default-no confirmations,
known-secret redaction, and command records. `case.py` provides private case
storage. Existing regression tests verify those behaviors.

Those mechanisms are useful precedents but do not provide agent isolation:
the runner executes on the host; its transcript can grow without a total output
cap; command records follow execution; and noninteractive legacy startup can run
a Quick scan. Secure mode never invokes that runner, imports legacy scan content,
or exposes interactive commands as agent tools. The new modules use the same
standard-library approach and argument-array construction, without widening the
old builders' responsibilities.

## Control flow and ownership

| Boundary | Input | Enforcement / output |
| --- | --- | --- |
| Fixed mock subprocess → controller | Untrusted JSON | Bounded read, strict versioned schema, duplicate-key rejection |
| Schema → policy | Immutable canonical action | Scope, tool, method, port, timeout, output, target-count checks |
| Controller → human terminal | Exact action + action/policy digests | Default-no exact challenge; no rationale in trusted review |
| Human UI → approval store | Controller-only grant | Monotonic expiry, full content binding, atomic single use |
| Controller → audit | Structured decision/start event | Private JSONL, synchronous write + fsync required before launch |
| Controller → Linux backend | Revalidated action and policy | Fresh namespaces, exact destination firewall, restricted runtime |
| Tool → controller | Bounded untrusted result | Allowlisted metadata in audit and CLI; session feedback remains untrusted |
| Session → fixed mock → controller | Previous response excerpt, then a fresh proposal | Step/deadline/output budgets; full validation and authorization for every follow-up |

`ProposalProvider.propose() -> str` is the small future provider interface.
`MockProvider` invokes only the bundled fixed mock script with an empty credential
environment and isolated Python import mode. This is trusted fixture code; its
process separation is not a sandbox for arbitrary Python/model plugins. There is
no configurable provider executable or API credential support. A real provider
must be separately sandboxed before integration; importing arbitrary provider
code into the controller is outside this interface's security contract.

The controller owns policy, approval store, audit, and backend. No provider gets
those objects. The only agent-controlled input is the proposal. The Python APIs
are internal trusted components, not independently authenticated services.

`SessionRunner` adds a single-use loop around that same controller. Its fixed
`SessionMockProvider.propose(observation, control=...)` adapter supervises a
bundled subprocess; the process receives JSON observation bytes only. Shared
trusted `ExecutionControl` state bounds planning, terminal approval waiting,
runtime discovery and worker supervision. Every planner call costs one step;
every accepted action reserves its full response allowance before approval,
without refunds. Session configuration never arrives through proposal fields.
See [bounded-sessions.md](bounded-sessions.md) for exact limits, events and stops.

## Schema and policy

Schema version `"1"` requires all action fields: UUID `action_id`, `tool_id`,
literal `target`, typed `parameters`, and bounded `rationale`. The only tool is
`http_probe`. Its parameters are `port`, `method`, `path`, `timeout_seconds`, and
`max_output_bytes`. No command, output file, headers, proxy, URL, environment,
approval flag, policy override, or arbitrary extra field is accepted.

Methods are GET and HEAD; paths are bounded simple absolute paths without query
strings, fragments, percent escapes or traversal. HTTP redirects are never
followed. There is no TLS or Nmap tool in this milestone.

Policy is operator-supplied strict JSON, with explicit allowlists and bounds.
Missing/malformed policy blocks operation. Empty allowlists deny everything.
Targets are literal IPv4/IPv6 addresses or strict CIDRs; scope must contain the
entire proposed network. Expansion counts all CIDR addresses, including endpoints,
and is capped at 16. Hostnames, zones, mapped IPv6 and selected ambiguous/special
ranges are rejected. There is no DNS resolution.

Policy decisions are `allow`, `deny`, or `approval_required`, with stable reason
codes. Successful human approval does not change the original policy decision:
`approval_consumed` and execution status show how that condition was satisfied.
The full canonical policy digest is checked as well as its human version label,
so editing policy without changing the label still invalidates a grant.

## Approval lifecycle

The trusted UI displays the action without rationale and both SHA-256 digests.
Approval requires a controlling terminal and typing `approve <digest-prefix>`.
The grant binds the **full** action digest, including rationale and action ID,
and full policy digest. No approve-all CLI flag or agent approval field exists.
Noninteractive execution of an approval-required action always blocks, even if
a caller supplies a reference. Policies may explicitly allow unattended actions.

Grants live only in controller memory, expire after the policy TTL (maximum 300
seconds), and are consumed under a lock. A changed action/policy or expired grant
burns the grant. A new controller session has no old grants. A failed launch
requires a fresh approval. The store is not an external authorization service.

## Linux execution boundary

`LinuxFixtureBackend` is an explicitly selected, fixture-only backend. It runs an
owned HTTP service in a fresh network namespace and accepts only `127.0.0.1` or
the equivalent singleton CIDR. This address refers to the sandbox fixture, not
the operator's localhost. The policy engine supports wider literal scopes, but
this backend refuses to execute against them. There is no fixture-to-host fallback.

The separate `LinuxRoutedBackend`, selected by `--routed`, now supports one
policy-authorized canonical IPv4 literal and TCP port through a supervised slirp
transport. It preserves the worker boundary below, using distinct routed
firewall rules and an explicit firewall-ready/transport-ready release handshake.
Only the separately sandboxed trusted transport retains the controller's network
namespace. It uses existing routes; no host network configuration changes occur.
The transport adds slirp4netns/libslirp to the trusted computing base. See
[routed-http.md](routed-http.md) for lifecycle, filesystem isolation, limits,
operator examples and the owned-service test topology.

Bubblewrap creates user, network, mount, PID, IPC and UTS isolation. A minimal
read-only runtime contains the fixed worker, system Python/standard library, nft
and their required libraries. It excludes the repository, policy, approvals,
audit, home directories, credentials and Docker socket. A small private writable
temporary filesystem and process resource limits bound tool resources.

The namespace bootstrap installs nftables default-deny output rules for the
exact action IP and TCP destination port. Established **reply-direction** traffic
supports the fixture; it is not a general outbound established-connection bypass.
For routed execution, output admits only the original destination tuple on
`tap0`, while input admits only established replies matching that tuple. There
is no incoming-listener allowance in the routed worker.
The bootstrap then drops capabilities and sets no-new-privileges. A seccomp filter
restricts new processes, execution, namespace changes and dangerous syscalls.
Worker checks prevent applying namespace firewall setup to the host namespace.

These layers matter separately: network namespaces isolate network stacks but
do not express a routed destination allowlist; Bubblewrap is a sandbox builder,
so the caller must supply the restrictions. See the
[Linux namespace documentation](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
and [Bubblewrap manual](https://manpages.debian.org/bookworm/bubblewrap/bwrap.1.en.html).

The fixed worker bounds response bytes and request duration; the parent also
bounds total execution time and subprocess output and kills the process group on
violation. Output content remains data. The malicious fixture never changes
policy. In session mode a fixed adversarial mock can turn it into another
proposal, which must independently pass validation, policy and approval.

## Event contract

JSONL events are independently consumable; PivotTrail is not a dependency.
Each has `event_schema_version`, UUID `event_id`, UTC `timestamp`, and `source`.
Controller events include:

```json
{
  "event_schema_version": "1",
  "event_type": "execution_started",
  "source": "recon-cockpit.secure-agent",
  "action_id": "11111111-1111-4111-8111-111111111111",
  "action_digest": "<sha256 of full canonical action>",
  "policy_version": "local-lab-v1",
  "policy_digest": "<sha256 of full canonical policy>",
  "decision": "approval_required",
  "reasons": ["human_approval_required"],
  "approval_reference": "<single-session reference>",
  "execution_status": "started"
}
```

Actual events also contain timestamp/event ID. Schema-invalid proposals have
null action identity because their claimed fields are untrusted; event ID still
identifies the rejection. Rationale is explicitly labeled untrusted and fully
redacted. Headers, bodies, raw proposals, exceptions and environment are omitted.
Completion metadata contains only bounded numeric/boolean allowlisted fields.
The controller API returns body data separately under `untrusted_result`; the
CLI does not display it.

Audit errors before launch prevent execution. Failure recording completion
cannot undo a request already sent: the CLI returns an audit error and the
controller refuses later execution. Reconcile unmatched `execution_started`
events after interruption or failure. Local logs are not tamper-proof. Hashes
bind content for approval; no hash chain or host-compromise protection is claimed.

# S3.4b: bounded stock OpenSSH compatibility

This is the native implementation candidate following accepted S3.4a
[PR #92](https://github.com/0xsl0th/recon-cockpit/pull/92), merged at `bfe6680`.
S3.4b remains open until the complete validation below, independent review and
required PR checks pass. It adds no accepted catalog entry: the inventory remains
**52 secure profiles / 17 external programs**. Stock OpenSSH is a fixture server,
not another integrated pentest program.

The purpose is useful, bounded service identification and public host-key
observation against an actual installed OpenSSH server. This does not establish
authentication, a trusted host identity, a completed encrypted user session,
general SSH interoperability or professional engagement readiness.

## Exact action and authority

The separate `stock_ssh_compatibility_v1` commitment binds one existing typed
Nmap or keyscan action to configuration A or B, the case, policy, exact tool
runtime, generated server configuration, public test key and three installed
server executables. The accepted configurable four-action assessment and HTTP
profiles keep their existing behavior.

| Configuration | Only client destination | Server identity and negotiated signature |
| --- | --- | --- |
| A | `10.77.0.20:2222` | `OpenSSH_10.2p1`, RSA-SHA2-256 |
| B | `172.23.0.20:12222` | `OpenSSH_10.2p1 Owned-lab-B`, RSA-SHA2-512 |

These addresses exist only in newly created disconnected namespaces. Neither
configuration contacts the same address on the host, an attached lab, VPN or
engagement network. No default external route, host firewall change, resolver
fallback, host credential or daemon service-manager operation is involved.

The controller evaluates policy, obtains a required single-use approval when the
policy requires it, and records intent. The isolated launcher independently
verifies durable audit and approval witnesses, then admits and consumes the exact
action before either owner starts. Audit records prove what was recorded; they
do not authorize an action. Constructing the host backend or lab is metadata
only. A changed selection, action, policy, session, runtime or budget cannot reuse
the launch.

Default CLI execution requires approval and stops without a personal review.
The explicitly named unattended owned-lab test mode uses a separate policy for
this finite disconnected corpus. Scripted PTY approval tests exercise the real
approval service but do not count as personal owner acceptance.

## Server custody and transport

The installed `sshd`, `sshd-session` and `sshd-auth` bytes are copied into sealed,
read-only snapshots with the exact 25-file native dependency closure and eleven
generated files from [S3.4a](stock-ssh-feasibility.md). The public test private key
is mode `0400`; it is deliberately public fixture material, never an operator
credential. No host configuration, key store, plugin directory or trust store
is mounted. Runtime hashes identify the installed bytes; they are not a claim
of a reproducible build or locally trusted upstream signature.

A separate custodian runs as namespace UID/GID 65534, with zero capabilities,
no-new-privileges and read-only filesystem restrictions. The launcher verifies
its UID/GID mapping from its own namespace before supplying the manifest.
Inherited supplementary groups are recorded and immutable, rather than claimed
to be empty.

For each admitted connection, a ptrace/seccomp gate permits only the reviewed
finite process graph: initial `sshd`, its temporary configuration writer, the
`sshd-session` image and preauthentication `sshd-auth` child. There are at most
three server identities, two internal forks and three executable loads per
instance. Executable path, argv and environment are checked while the process
is stopped, and the resulting executable inode must match its sealed snapshot.
Failed attempts consume their allowance; threads, extra executable transitions,
shared-memory mutation paths, new network sockets and namespace changes are
denied. This is a separate SSH boundary; HTTP's no-child restriction is unchanged.

The recorder and custodian have separate user, network, mount and PID namespaces.
The recorder prepares a finite set of connected loopback TCP pairs, closes the
private listener and transfers only one exact server descriptor after connection
admission. Conntrack is initialized with exact temporary tuple rules before the
private handshakes. The final firewall permits only the selected client endpoint
and the already established private tuples. A fixed bidirectional exchange
verifies every private pair through those final rules and is fully consumed
before server handoff. Clients never receive a private socket or owner control
descriptor. The server inherits only that mediated stream on stdin/stdout and a
bounded stderr pipe.

The custodian is an additional trusted process with its own explicit budget;
it is not counted as one of the three stock-server identities. Previous instance
processes must be reaped before another starts. The owner keeps the per-action
ledger across instances; losing it stops the operation.

| Bound | Nmap banner observation | RSA key observation |
| --- | --- | --- |
| Session / actions | 60 seconds / one action | 60 seconds / one action |
| Tool deadline / native timeout | 5 seconds / 3-second host timeout | 5 seconds / `ssh-keyscan -T 2` |
| Connections | At most three, one active | At most one |
| Admission rate | Burst one; at least 250 ms between admissions | Same rule |
| Forwarded client bytes | Zero; NULL/banner recognition only | At most 8,192 |
| Captured server bytes | At most 255 aggregate | At most 8,192 |
| Client protocol | No application request or HTTP probe | Identification, KEXINIT and DH init only |
| Completion boundary | Observed service/version | First public host-key reply; no client NEWKEYS or user authentication |
| Tool stdout/stderr retained | At most 8,192 combined | At most 8,192 combined |
| Per server process | 256 MiB address space, 64 descriptors, one thread | Same bounds |
| Custodian | One process; 256 MiB, 64 descriptors, 1 MiB retained bound | Same bounds |
| Recorder | One process with no children; 256 MiB, 64 descriptors, 1 MiB scratch/evidence aggregate | Same bounds |

The recorder validates packet lengths, stages, algorithm subset and the public
fixture key before forwarding. Server NEWKEYS bytes that arrive in the same
read remain bounded original evidence and are not delivered. One extra byte may
be retained solely as an overflow witness; no over-limit message is forwarded.

## Required usefulness and failure corpus

All ten cases run for both configurations; none substitutes a synthetic SSH
server for the stock executable. Artificial faults belong to the recorder and
are labeled separately from the original server bytes.

| Cases | Required evidence |
| --- | --- |
| O1 | Nmap identifies SSH and the full observed `10.2p1` suffix. |
| O2 | Keyscan returns the exact public RSA-2048/e65537 fixture key and fingerprint, with trust explicitly unverified. |
| R1 | The hostile version addendum remains untrusted data while useful key collection completes. This alone does not demonstrate a planner injection or authorize its requested target. |
| R2 | Deliberate fragmentation inside identification, packet length and host-key blob preserves useful completion and original bytes. |
| N1 | Malformed delivered identification remains inconclusive. |
| N2 | A truncated delivered host-key reply remains inconclusive. |
| N3 | A withheld response produces a measured timeout. A native failed exit remains recorded; timeout classification requires corroborating withholding and latency evidence. |
| N4 | The recorder rejects a response proposal crossing its wire capture cap; classification is output limit, with the original stock bytes preserved. |
| N5 | An explicitly substituted RSA-1024 blob is unsupported and inconclusive. |
| N6 | An explicitly substituted unsupported host-key algorithm is inconclusive. |

Successful work is measured alongside blocking: all eight ordinary/robustness
rows must complete usefully with zero unnecessary refusals, and all twelve
negative rows must have their declared non-useful outcome. Boundary tests must
show unauthorized actions and prohibited destinations denied, finite packet
and process budgets enforced, and cancellation/owner death leaving no descendants.
Action and total elapsed time are recorded. Provider calls and actual spending
remain zero; this is not a comparative overhead benchmark.

## Evidence and validation status

Private artifacts remain under `.secure-agent/stock-ssh-native-20261015/` and
must not be committed. Saved reports revalidate action/policy/runtime identity,
process and transport custody, original versus transformed wire bytes, resource
counts and cleanup. Native output is reparsed in a networkless worker. Inspection
does not start a daemon, restore a session or issue an approval. Hashes establish
consistency of saved artifacts, not protection against a compromised host owner.

Final source pins, complete corpus/enforcement counts, unchanged replay and
accepted-profile regression results will be recorded here after validation.
The initial transport failure and artifact-size failure remain retained rather
than replaced by successful repetitions.

After S3.4b acceptance, continue **S3.5 disconnected multi-host routing** from
the [roadmap](stage3-compatibility-routing.md). Credentials, paid/live models,
deeper workflows, comparative benchmarking, attached targets and proposal
submission remain deferred. Any network attachment needs a concrete ownership,
scope, effect, exclusion and routing authorization first.

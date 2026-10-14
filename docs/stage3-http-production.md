# S3.3: finite HTTP compatibility contract

PR #89 accepted the stock-nginx diagnostic at `c068a9d`. Its 26 native corpus
rows, authority tests and immutable evidence close S3.2; they do not establish
production HTTP integration. This document defines the next finite contract.
S3.3a preparation is accepted in PR #90 at `d30a2f1`; S3.3b implementation
and native acceptance remain open.

S3.3a prepared the exact Apache runtime/configuration and this contract.
S3.3b must implement and validate the secure production path on **both nginx and
Apache**. Apache's listener, dynamically loaded modules and nonzero user mapping
need a separate review from nginx's private Unix socket and namespace UID zero.
This finding adds one reviewable increment: Stage 3 now forecasts **nine PRs**,
four accepted and five remaining, rather than the original 6–8. No required
corpus row, bound or later routing/name/TLS gate is removed to fit an estimate.

## Selection and authority

The proposed production launch profile is `stock_http_compatibility_v1`. It is
not registered by S3.3a. Accepted `configurable_owned_lab` and
`stock_nginx_diagnostic_v1` contracts remain unchanged, including the former's
ordered four-action workflow. A new request must bind:

| Input | Finite permitted value and meaning |
| --- | --- |
| Contract identity | Schema version 1 and the separate production launch profile. |
| Implementation | Exactly `nginx` or `apache`; each has an independent, revalidated runtime manifest. |
| Configuration | A or B, with the exact numeric HTTP target, port and path below. |
| Operation | One existing configurable header-reader action or one existing configurable Nmap service action. No action sequence or automatic follow-up. |
| Owner configuration | One generated, content-pinned server configuration/public body from the declared corpus. Test transport faults are explicit owner-fixture inputs, never hidden in an ordinary production result. |
| Runtime and policy | Full daemon/module/client runtime and generated-file digests, selection-specific policy digest, exact action digest, limits, fresh session and owner identity. |

| Configuration | Sole client TCP destination | Header GET path |
| --- | --- | --- |
| A | `10.77.0.10:8080` | `/harbordesk/portal.html` |
| B | `172.23.0.10:18080` | `/portal/index.html` |

The header request is exactly `GET <path> HTTP/1.1` with the numeric
`Host: <address>:<port>` and `Connection: close`. Nmap retains its separate
18-byte `GET / HTTP/1.0\r\n\r\n`, pinned NULL/HTTP probe data, one numeric
port, no DNS, zero retries and existing version-intensity-one invocation.
Neither action grants arbitrary URL, path, Host, argv, environment, method,
body, credential, cookie, upgrade, redirect or response-directed access.
An exclusion takes precedence over an allow entry.

The authority must persist intent and independently verify its audit witness,
verify and consume fresh exact-action approval when required, then admit/redeem
the one-use action before starting any owner or client. Audit records attest to
execution intent; they grant no authority. Both isolated witness services remain
mandatory, including when an explicit owned-test policy does not require a human
approval. Implementation/case/runtime changes invalidate the binding even when
the nominal client request is identical. Missing, stale, mismatched, replayed,
cancelled or exhausted inputs must fail closed before execution.

The default policy requires approval. Scripted approval mechanism tests must
remain distinguishable from personal owner acceptance. The new mode requires
coordinated admission, launcher, worker, backend, parser, result and inspection
validation; a host-side wrapper around the diagnostic is not integration.

## Preparation findings and native design requirements

Reuse the existing exact requests, client runtime, networkless parsing,
request-accounting state machine, supervisor, audit/approval services and
private evidence conventions. Preserve the accepted nginx diagnostic unchanged.
Shared helpers are appropriate only with regression evidence for that boundary.
Do not duplicate or weaken authority checks to accommodate a second server.

Apache preparation specified a fixed prefork `-X` configuration, a nonzero
namespace-local user/group, four pinned modules and a private loopback listener.
S3.3a did **not verify native startup**. S3.3b must freeze the concrete
descriptor/namespace handoff and verify:

- The Apache socket exists only inside a fresh disconnected daemon namespace.
  The recorder has a bounded, independently accounted route to it; the client
  has neither that namespace nor any private-listener descriptor or route.
- A single mapped nonzero UID/GID supports startup without host privileges,
  additional mapped group authority, host account files or privilege-changing fallback.
- The selected `-X`/prefork/module set works with enforced process/thread,
  socket-family, filesystem, deadline and resource bounds. If it cannot, retain
  the failure and review the design; do not enable general fork/thread access.
- The server consumes only sealed exact runtime/modules and generated public
  data. No host Apache configuration, wildcard includes, module directory,
  external resolver, TLS/provider configuration or package-manager side effect
  enters the runtime.

The Apache `127.0.0.1:19080` endpoint belongs only to the private daemon namespace,
**never an authorization to contact that address on the host**. Apache needs a
different private transport from nginx; no transparent proxy may bypass the
recorder's exact-request admission, counters or deadline. The final topology
must be reviewed and tested before the new production backend is enabled.

## S3.3b implementation under validation

The candidate registers `stock_http_compatibility_v1` separately from the accepted
nginx diagnostic. The controller, both isolated witness services, one-use
admission, launcher, backend, confined client, parser and evidence validators all
bind the implementation and its preparation/runtime digests. The default policy
requires approval. Explicit unattended owned-lab test policy is mechanism evidence,
not personal owner acceptance.

Apache's bootstrap runs as the single mapped namespace UID/GID 65534. The
launcher independently verifies that identity maps only to its own unprivileged
UID/GID before releasing the daemon bootstrap. It creates one unconnected IPv4
stream socket in its fresh
disconnected network namespace. A private control channel transfers that socket
through the launcher to the recorder; each receiver checks domain, type, TCP
protocol, inode, namespace cookie, nonblocking state and unconnected zero address.
Malformed transfers close their received descriptors. The daemon and launcher
close their copies before client readiness. The client receives neither the
private socket nor the daemon namespace descriptors.

Only after the recorder validates the exact allowed request does it connect the
one-use socket to the fixed private endpoint. The recorder cannot create TCP
sockets, and Apache cannot call connect or create children/threads. Pinned process
and namespace descriptors let the launcher inspect the bounded private TCP table
for the sole expected listener without sending a readiness request. All forwarding
uses the existing request ledger, shared action deadline and byte/connection/rate
limits. Native proof remains required; this description is not a passing result.

The production client checks that the private loopback listener is unreachable
from its own namespace. Immutable evidence retains the server identity, real
response bytes, separate injected-fault bytes, transfer custody, namespace identity,
startup/action/cleanup latency, useful completion and denial results. The accepted
diagnostic retains its original selection schema and default Unix-socket connector.

### Recorded identity-boundary revision before native completion

The first frozen smoke (`3c7f51b`) failed closed on both servers; neither result
counts as useful work. Native receipts under
`.secure-agent/stock-http-production-20261014/smoke-01/` and private diagnostic
captures show that ordinary-user Bubblewrap retains supplementary group IDs.
nginx observed its primary group and overflow IDs; Apache's nonzero remapping
reported overflow/primary IDs and an intermediate parent-namespace UID zero.
That intermediate zero is not proof of host-root privilege or an acceptable
substitute for checking the complete mapping from the launcher.

The original promise of an empty supplementary-group list was therefore
incorrect for this launch mechanism. Linux requires unprivileged group-map
setup to disable `setgroups`, and that disablement is inherited; see
[user namespace rules](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
and [Bubblewrap's group-map setup](https://github.com/containers/bubblewrap/blob/v0.11.2/bubblewrap.c).
The candidate explicitly revises its new production selection commitment:
record at most 64 inherited group IDs, permit only the namespace primary GID and
the kernel overflow ID 65534, require `setgroups=deny`, and witness refusal of a
group-change attempt. It does not claim inherited groups were removed.

Before sending the daemon's startup packet, the launcher pins its process/user/net
namespace descriptors and reads UID/GID maps from the launcher's namespace. Each
must contain exactly one mapping from the expected namespace ID to the launcher's
own positive UID/GID. The daemon separately checks its inner mapping and actual
identity. Runtime files remain sealed and read-only; Landlock, capabilities,
network, process/thread, storage and deadline bounds are unchanged. No privileged
helper, extra capability, broad host mount or host account database is added.
This revision requires fresh native tests and independent review; its earlier
failed attempts remain separate evidence.

### Apache version recognition correction

The first complete native run at `a481b87` retained **103 passes and three
failures**, with all 899 source hashes unchanged. Apache O5 in configurations
A and B delivered valid responses, but Nmap reported generic HTTP rather than
the advertised product/version. Its original fixed matcher expected `Server`
immediately after the status line and a bare version; stock Apache sends a
`Date` header first and a parenthesized distribution suffix. Those two results
remain inconclusive, not useful completions. A separate Apache O1 adversarial
budget probe also failed and remains recorded in `native-final-01/`.
An instrumented replay completed the first request and recorded the second
request's denial; it did not reproduce the failure, whose cause remains
unconfirmed. The production test now handles a reset during the denied
connection's connect step as well as send/receive. Twenty deterministic tests
check that handling; unexpected errors and any returned byte still fail. No
production exception handling, recorder rule or execution limit is relaxed.

The correction gives production Nmap its own pinned runtime and recognition
payload. Only the Apache recognition expression changes: it permits one bounded
Date header and an optional bounded parenthesized suffix. It does not accept a
body banner as a header or invent a suppressed version. The exact NULL/GET
probes, arguments, timers, requests and budgets stay fixed. The existing
diagnostic and configurable modes retain their original runtime and probe bytes.
Production selection, policy and runtime commitments bind the new payload;
the old runtime is refused in the new mode and vice versa. Required useful-work
criteria and raw-response grading are unchanged. Fresh native validation must
establish the corrected result; the original failed run is not relabeled.

## Bounds retained from the diagnostic

| Limit | Headers | Nmap |
| --- | --- | --- |
| Session and action count | 60 seconds, one action | 60 seconds, one action |
| Action deadline | 1 second | 5 seconds; native host timeout remains 3 seconds |
| Client output | 2,048 bytes | 8,192 stdout/stderr bytes combined |
| Connections / application requests | One connection, one exact GET | At most three connections, at most one exact root GET |
| Admission concurrency/rate | One active connection; four per second, burst one | Same; at least 250 ms between admissions |
| Forwarded request bound | Exact compiled request, at most 256 bytes | Exactly 18 bytes or zero for an empty exchange |
| Recorder response bound | 2,049 bytes including overflow witness | 4,096 bytes across the action |

Owner startup remains inside the session deadline and is measured separately.
Client readiness starts one shared absolute action deadline for client and
recorder. A bounded reporting allowance grants no further network forwarding.
Preserve the declared daemon ceiling of two processes (including any reaper),
256 MiB per process, 64 descriptors per process and 1 MiB total scratch/logs;
the recorder remains one process with no children, 256 MiB, 64 descriptors and
1 MiB aggregate scratch/log/trace storage. Enforce aggregate storage with the
kernel rather than per-file limits alone. Any needed change requires a recorded
contract revision and fresh boundary evidence, not a silent compatibility fix.

## Required S3.3b acceptance corpus

Execute both configurations and **all thirteen cases on each implementation**:
52 native corpus rows total. Keep server-specific raw bytes and observations;
equivalent outcomes do not require identical Date, Server or redirect body bytes.

| Cases per server | Required result |
| --- | --- |
| O1/O2 × A/B | Complete 200 response with present/absent optional security headers respectively. Absence is useful observation, not an execution failure. |
| O3/O4 × A/B | Complete 404 and 302 responses; report their status and headers. Record Location without following it. |
| O5/O6 × A/B | Useful Nmap HTTP service identification with server version advertised and suppressed. No invented version when suppressed. |
| R1/R2 × A/B | Hostile body remains untrusted data; four timed writes preserve all daemon bytes and complete usefully. This does not evaluate a live model. |
| N1–N5 × A/B | Retain a valid original daemon response, then separately record truncation, reset, withholding, capture overflow or conflicting Content-Length. Inconclusive, timeout and output-limit outcomes must match the declared fault. |

Across both servers require **24 ordinary and eight robustness useful
completions, zero unnecessary refusals, 20 correct negatives, and 32 distinct
blocked destination combinations** (two servers × two configurations × two
action families × four forbidden endpoints). Report request/connection attempts,
admissions, deliveries and extra/budget-denied activity separately. Blocking all
actions fails this gate. Repeated witnesses do not inflate distinct-denial counts.

In addition, both implementations require authority/audit/required-approval
negatives and positive controls, private-listener bypass denial, second-request
and connection-budget exhaustion, prelaunch/inflight cancellation, failed-startup
cleanup, runtime/owner/selection tampering and unchanged Python/CLI inspection.
Retain response bytes, parsed facts, runtime identity, intent/witnesses,
transport ledger, namespace/resource/cleanup receipts and source pins. Reopening
saved evidence must not restore approvals, deadlines or budgets.

Record owner/client startup, action, cleanup and total latency, along with
legitimate completion, unnecessary refusals and zero provider usage/cost.
Comparative benchmarking remains deferred; mediated timing is not a baseline
overhead result. Native nginx success from S3.2 cannot replace this new
production-mode corpus. Run the accepted configurable workflow and diagnostic
regressions before closure, plus portable checks and independent review.

## Completion and subsequent work

S3.3a closes preparation only after strict portable validation, all 26 actual
installed-runtime inspections, immutable receipts, independent review and checks.
It starts no server or tool and adds no secure catalog entry. The
[Apache preparation record](stock-apache-feasibility.md) distinguishes source
findings, metadata inspection and unresolved native behavior.

S3.3 closes only after S3.3b meets every native row and boundary above through the
new production path. Then S3.4 adds stock OpenSSH compatibility; S3.5 handles
disconnected multi-host routing and aggregate budgets; S3.6 handles explicit
DNS/TLS name/trust binding; S3.7 performs combined acceptance. Completed offline
R5/local R6, B/C/T coverage and initial GUI milestones remain closed.

Network attachment, real credentials, paid/live models, deeper workflows,
comparative benchmarks, proposal submission and release publication retain
their separate later authorization gates. This contract grants none of them.

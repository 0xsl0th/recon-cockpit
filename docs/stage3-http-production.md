# S3.3: finite HTTP compatibility contract

PR #89 accepted the stock-nginx diagnostic at `c068a9d`. Its 26 native corpus
rows, authority tests and immutable evidence close S3.2; they do not establish
production HTTP integration. This document defines the separate finite production contract.
S3.3a preparation is accepted in PR #90 at `d30a2f1`.
[S3.3b PR #91](https://github.com/0xsl0th/recon-cockpit/pull/91) implements the
production path and has completed native and portable validation. It awaits
final review and required checks on the latest revision, then merge; S3.3b
acceptance is not yet claimed.

S3.3a prepared the exact Apache runtime/configuration and this contract.
The S3.3b candidate implements and validates the secure production path on
**both nginx and Apache**. Apache's listener, dynamically loaded modules and
nonzero user mapping required separate review from nginx's private Unix socket
and namespace UID zero.
This finding adds one reviewable increment: Stage 3 now forecasts **nine PRs**,
four accepted and five remaining, rather than the original 6–8. No required
corpus row, bound or later routing/name/TLS gate is removed to fit an estimate.

## Selection and authority

The candidate production launch profile is `stock_http_compatibility_v1`.
S3.3a did not register it; PR #91 adds the separate production path. Accepted `configurable_owned_lab` and
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
S3.3a did **not verify native startup**. The separately reviewed S3.3b
handoff and native validation below retain these requirements:

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
recorder's exact-request admission, counters or deadline. The reviewed topology
and its finite native validation are recorded below; they grant no host or
attached-network access.

## S3.3b implementation awaiting review

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
limits. The native corpus and boundary results below validate this finite
configuration; final PR review and acceptance remain separate gates.

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
The fresh native results below cover this reviewed revision; its earlier
failed attempts remain separate evidence, and final PR acceptance is pending.

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
criteria and raw-response grading are unchanged. The corrected native result
is recorded below; the original failed run is not relabeled.

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

## Recorded S3.3b validation

Frozen production source `1cfa59a` passed **106 native checks**: all 52 corpus
rows and 54 authority, cancellation, cleanup and budget cases. All **904 tracked
source hashes stayed unchanged**. This includes 24 ordinary and eight robustness
useful completions, zero unnecessary refusals, 20 correct negative outcomes and
32 distinct forbidden-destination combinations. No provider call or spend occurred.

Independent inspection regraded all 52 bundles through Python and the CLI
without modifying them: **104 unchanged inspections**, with all source,
generated-file and 29 installed-native-file pins verified. The receipt is
`.secure-agent/stock-http-production-20261014/independent-native-final-02.json`,
SHA-256 `14dd726b6704bddcf64b1046526a2bc396c88c2fc2bf7c3cfb01d77144da74e7`.
These hashes establish consistency of saved evidence, not tamper resistance
against a compromised host owner.

The accepted nginx diagnostic, its owner/enforcement/budget cases and the
configurable command-line/background-service workflows passed **68 distinct native
regression checks** in `regressions-final-01/` and
`remaining-regressions-final-01/`. Three separately launched repetitions of the
Apache extra-request test also passed in `budget-final-02/`; an earlier
pytest-deduplicated invocation ran one passing case in `budget-final-01/`.
All use the same frozen source. These successful runs do not establish the
cause of the original, unreproduced budget-test failure.

| Observed median across 26 cases per implementation | nginx | Apache |
| --- | ---: | ---: |
| Owner startup | 779.5 ms | 808 ms |
| Client startup | 1,217 ms | 1,224 ms |
| Action | 106.5 ms | 116 ms |
| Owner cleanup | 3 ms | 3 ms |
| Whole trial | 4,256 ms | 4,395.5 ms |

These are validation timings including the declared negative cases, not a
comparative benchmark or measured mediation overhead. Raw timings remain in
each report.

The first hosted run passed all 25,312 portable tests on its four Linux jobs;
macOS passed 25,307 and failed five new fixtures that assumed Linux-only
`memfd_create`/`listxattr` APIs. The test-only correction stages real bytes in
temporary descriptors, records the exact requested sealing flags, and explicitly
supplies the capability-query mock. No production behavior, native test or
required assertion is removed. Retain `ci-macos-1cfa59a.log` and its summary.
The corrected full local portable run at `d19eef3` passed **25,312 tests**,
with all **904 tracked source hashes unchanged** during that run. There were
1,565 integration tests deselected and zero failures, errors or skips; retain
`portable-final-01/verification.json`, its source maps, log and test XML under
`.secure-agent/stock-http-production-20261014/`. All five
[corrected hosted jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/38649179063)
also passed at `d19eef3`. Production and native-test bytes are identical to
`1cfa59a`; only portable fixtures and validation documentation changed between
those two validation sources. The fixture correction separately passed 29
focused tests normally and 29 with all ten relevant Linux-only APIs absent,
without skips. Final review and required checks on PR #91's latest revision
still precede merge.

## Completion and subsequent work

S3.3a closed preparation in PR #90 after strict portable validation, all 26
actual installed-runtime inspections, immutable receipts, independent review
and checks. Its inspector starts no server or tool and adds no secure catalog
entry. The [Apache preparation record](stock-apache-feasibility.md) remains
preparation evidence; the native results above belong to the separate S3.3b path.

S3.3b remains a validated candidate until final review, required checks and
merge of PR #91. Stage 3 retains four accepted and five remaining increments out
of nine until that merge, and the catalog remains 52 accepted profiles across
17 external programs. After acceptance, S3.4 first pins the finite OpenSSH
server configurations, public synthetic keys, requests and confinement contract,
then validates service identification and host-key collection. S3.5 handles
disconnected multi-host routing and aggregate budgets; S3.6 handles explicit
DNS/TLS name/trust binding; S3.7 performs combined acceptance. Completed offline
R5/local R6, B/C/T coverage and initial GUI milestones remain closed.

Network attachment, real credentials, paid/live models, deeper workflows,
comparative benchmarks, proposal submission and release publication retain
their separate later authorization gates. This contract grants none of them.

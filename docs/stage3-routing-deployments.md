# S3.5: fixed routing deployment extension

This contract precedes implementation of the next routing batch. The first
fixed-A slice is accepted in [PR #94](https://github.com/0xsl0th/recon-cockpit/pull/94),
merged as `46f9b73`. Its native results and retained failures remain in the
[routing runbook](stage3-disconnected-routing.md). S3.5 remains open. This plan
grants no launch authority and changes no accepted catalog profile.

## Closed deployment selection

Add only four explicit deployment selections: `nginx-A`, `nginx-B`, `apache-A`
and `apache-B`. Select one when creating an assessment; it cannot change during
that owner lifetime. Preserve the existing four independently selected actions
and their ordinary underlying cases:

| Action | Underlying accepted operation |
| --- | --- |
| `http_nmap` | HTTP O5: fixed Nmap NULL/root-GET service identification |
| `http_headers` | HTTP O1: exact declared header GET |
| `ssh_nmap` | SSH O1: fixed NULL/banner identification |
| `ssh_keys` | SSH O2: one bounded public RSA host-key observation |

| Configuration | HTTP endpoint and header path | SSH endpoint |
| --- | --- | --- |
| A | `10.77.0.10:8080`, `/harbordesk/portal.html` | `10.77.0.20:2222` |
| B | `172.23.0.10:18080`, `/portal/index.html` | `172.23.0.20:12222` |

The HTTP implementation changes only the selected accepted daemon contract.
SSH retains its accepted A/B runtime, public fixture key and process boundary.
No target, port, path, command, payload or runtime can be supplied arbitrarily.
There is no response-directed action selection or automatic cross-tool workflow.

Use a separately versioned extended selection commitment. Bind deployment,
configuration, implementation, runtime, topology, action identifiers, policy and
the new Apache handoff into that commitment. Preserve the original fixed-A v1
selection/hash and saved-evidence inspection; do not reinterpret old hashes as
new deployments. Existing default invocation remains the original fixed-A form;
an explicit deployment selects the extended form. Saved evidence restores no
session, deadline, budget, admission or approval.

## Topology, custody and unchanged limits

Retain five owned network namespaces, four veth pairs, the fixed `10.78.0.x`
transit links, six sequential setup helpers and eighteen topology-owner exports.
Derive only the selected service addresses/ports, static routes, listener checks
and firewall matches from A/B. The router-owned excluded listener remains
`10.77.0.99:8080`. Wrong-port witnesses are HTTP 8081 / SSH 2223 for A and HTTP
18081 / SSH 12223 for B. Live other-service, excluded and wrong-port baselines
must precede final deny filters; record eight denied role/destination checks
per topology. No extra cross-configuration listener is implied by this contract.

There is no host network namespace, physical interface, attached target, VPN,
external default route, slirp transport or host firewall change. Client namespaces
have their exact selected-service filters. No native client receives a private
daemon descriptor, namespace custody descriptor or ledger channel.

Apache reuses the accepted nonzero-UID daemon mapping and generated configuration.
Its daemon owner creates exactly one unconnected private TCP descriptor for the
action. Verify its type/state, namespace cookie, inode, exact daemon listener and
owner-copy closure before transferring it to the HTTP frontend. The frontend
consumes it through the accepted one-use `DescriptorService` only after the
global request reservation succeeds. Denial, cancellation, descriptor mismatch
or reuse closes the descriptor and action; it must not create a replacement.
Close each sender copy after transfer and reap the daemon before another action.

This single per-action Apache descriptor is separate from the topology owner's
eighteen exports. It is an explicitly bounded transient addition within existing
launcher/frontend descriptor ceilings; final custody/closure must be recorded.
Native clients still receive none of it. Apache needs no nginx `/peer` Unix-socket
mount or its filesystem permission. Retain that mount only for nginx, with the
existing per-action scratch directories. Keep daemon/frontend process, memory,
descriptor, output and scratch limits unchanged.

The whole-assessment caps remain **60 seconds, four unique selected actions,
eight connections, two HTTP requests, one SSH key exchange, one active target
connection, at least 250 ms between admissions, 8,466 request bytes, 14,591
response bytes and 26,624 reserved output bytes**. Existing per-action limits
remain unchanged. No SSH authentication, client NEWKEYS or encrypted user
session is added. The same three lowered-budget presets remain negative tests.

Reserve connections, requests and bytes before delivery, across every host and
action. No refund or allowance replacement follows a failed action, daemon
restart or selected deployment. Lost ledger continuity stops execution. Preserve
exact policy checks, independent durable audit, required consumed one-use
approval, consumed admission and freshness before confined execution. Explicit
unattended owned-lab testing remains visibly a test policy, never personal approval.

## Required evidence for this batch

Before review, freeze the source and verify:

- For each of four deployments, all four individual actions and both existing
  complete action orders: 24 ordinary trials, 48 useful selected actions, zero
  unnecessary refusals. A successful exit without the expected structured
  observation does not count as completion.
- All three lowered-budget presets on each deployment: twelve trials, each
  preserving the first useful observation and refusing the later excess work.
  Do not count these as complete legitimate assessments.
- Default required-approval refusal for each deployment, plus real audit/approval
  witness denials and cancellation/launcher-death cleanup on the new Apache path.
- Actual native custody for Apache's private descriptor and refusal of wrong,
  connected, duplicated, stale, reused or leaked custody. Verify cleanup rather
  than inventing an unacknowledged final owner snapshot.
- Listening baselines, selected-target usefulness, exact A/B destinations and
  denied other-service/excluded/wrong-port traffic under the unchanged caps.
- Structured observations, raw evidence, runtime/action/selection/namespace
  identity, reservation arithmetic and byte delivery agree. Both Python and CLI
  inspection leave every saved bundle's bytes, mode and timestamp unchanged.
- Original PR #94 fixed-A bundles still inspect unchanged. Run relevant accepted
  HTTP/SSH regressions, the full portable suite, independent reviews and latest
  required CI. Keep private artifacts out of Git.

Record legitimate completion, unnecessary refusals, expected denials, timing,
reservations, delivered bytes and cleanup. Provider calls and actual cost remain
zero. No comparative baseline or professional-engagement compatibility is claimed.

Preserve the original Apache B/O1 `isolation_unavailable` refusal from PR #94's
first 75/76 regression run. Its cause remains unlocalized despite later passing
diagnostics and a complete passing follow-up. Instrumented diagnostics are
separate evidence and cannot substitute for uninstrumented acceptance cases.
Do not relax deadlines or bounds to make the next run pass.

## Remaining required work

This batch extends only the current ordinary operation mapping. The complete
ordinary-variation, hostile-response, negative and enforcement matrix remains
a separate required S3.5 batch. Pin its finite case selectors before code.
In particular, standalone HTTP N4 delivers a 2,049th overflow witness, while
routing caps header delivery at 2,048 bytes. Define truthful routed overflow
semantics under the existing cap; do not silently increase it or relabel a
budget refusal as the standalone N4 outcome.

S3.5 closes only after the full required matrix and review gates pass. S3.6
name/TLS binding and S3.7 combined acceptance follow in order. Stage 3 remains
ten logical increments, seven accepted and three open; the current estimate is
11–13 PRs because routing needs multiple batches. The catalog remains 52 accepted
profiles / 17 external programs. Completed milestones stay closed. Credentials,
paid/live models, deeper workflows, comparative benchmarking, attached networks
and proposal submission remain deferred.

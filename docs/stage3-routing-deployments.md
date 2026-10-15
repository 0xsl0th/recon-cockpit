# S3.5: fixed routing deployment extension

This contract was pinned before implementation of the current deployment
candidate. Its corrected native validation is recorded below; review and merge
remain separate. The first fixed-A slice is accepted in
[PR #94](https://github.com/0xsl0th/recon-cockpit/pull/94),
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

## Entry point

The CLI accepts only the four named deployments. Omitting `--deployment` keeps
the original v1 selection. For example, select four independent actions with:

```sh
python scripts/disconnected_routing.py run --deployment apache-B \
  --action http_nmap --action http_headers --action ssh_nmap --action ssh_keys \
  --directory .secure-agent/routing-apache-b
```

This invocation does not execute tools. Native owned-lab validation adds both
`--execute` and the explicit `--unattended-owned-lab-test` test policy. Without
that test policy, required personal approval remains unavailable through this
entry point and execution is refused. The test policy records no personal
approval. No target, command or budget override is accepted.

Inspect saved evidence with
`python scripts/disconnected_routing.py inspect DIRECTORY`. Inspection restores
no authority and must leave bundle bytes, permissions and timestamps unchanged.

## Initial validation and retained failures

Initial production source was frozen at `e955549`; `6a08a0e` changed only the two new
native test harnesses. The 986 candidate source pins were unchanged during each recorded
candidate gate (accepted-main diagnostics have 981 pins). The native evidence covers **80 distinct cases** across two runs, not one
all-passing invocation:

- `native-final-01`: 71 passes and nine retained test-harness failures. All 50
  trial bundles and 90 result snapshots were complete and independently verified.
- `custody-final-01`: all nine corrected custody/handoff cases pass. Production
  and the sources of the other 71 passing cases are byte-identical to the first
  run. No production bound, authority condition or required case changed.

The seven custody failures occurred during isolated helper imports: the helper
mounted the frontend closure while also importing launcher-side services. It now
mounts the existing routing launcher's source closure. Both live-handoff tests
reached the real descriptor checkpoint but misclassified a bwrap source-mount
argument as an executing client. The corrected predicate checks the executable
as well as the script. Preserve the original failures; they are not successful
custody or cleanup evidence.

| Measurement | Verified deployment result |
| --- | --- |
| Useful ordinary work | 24 trials: four individual actions and two complete orders on each deployment. All 48 selected actions complete; zero unnecessary refusals. |
| Aggregate negatives | Twelve trials preserve the first useful observation and refuse excess connections, HTTP requests or SSH key exchanges. These are not complete legitimate assessments. |
| Required approval | Each of four deployment defaults refuses unattended launch with no result or reservations. Independent missing/nondurable audit and missing/replayed approval checks also refuse before admission on the Apache path. |
| Apache custody | Twenty saved HTTP custody receipts: eighteen descriptors consumed after reservation and two closed unconsumed after budget denial. Seven isolated kernel-descriptor cases verify successful transfer and wrong/connected/duplicated/stale/reused/leaked refusal. |
| Lifecycle | Four post-useful cancellation/death cases retain the one completed action and reap ten tracked processes each. Two additional instrumented Apache-B tests observe the sole unconsumed socket at the frontend, stop before any routed client, and reap all twelve tracked processes and descriptor owners. |
| Evidence | All 50 new-run bundles pass Python/CLI inspection without changing bytes, modes or timestamps. Ten original PR #94 bundles also pass both production inspection paths unchanged. Saved evidence restores no authority. |
| Topology and caps | Five distinct namespaces, four veth pairs, eighteen topology exports and eight denied role/destination witnesses per created topology; all existing limits remain unchanged. |
| Provider use and cost | Zero provider calls and zero actual cost. No comparative baseline or benchmark claim. |

Complete-order measurements include setup and trial overhead. Every order
reserves four actions, six connections, two HTTP requests, one SSH exchange and
26,624 output bytes. Reserved capacity and delivered bytes remain separate.

| Deployment | Forward / reverse order time (ms) | Actual request / response bytes in each order |
| --- | ---: | ---: |
| nginx-A | 23,247 / 23,195 | 1,501 / 1,679 |
| nginx-B | 22,844 / 22,657 | 1,498 / 1,703 |
| apache-A | 23,639 / 23,610 | 1,501 / 1,887 |
| apache-B | 23,569 / 23,483 | 1,498 / 1,911 |

Private receipts, source manifests, raw evidence, JUnit and reviews remain in
`.secure-agent/stage3-routing-deployments-20261015/`; none is committed to Git.
The initial v1 replay attempt was refused by sandbox parser isolation before
processing any bundle. The authorized follow-up replay passed all ten original
bundles, with original bytes/modes/timestamps and production source unchanged.

The full local portable gate at `6a08a0e` passed **26,873 tests**, with no
failures, errors or skips, and all 986 candidate source hashes unchanged.

Accepted-profile regression runs remain separately recorded:
`regressions-final-01` passed 74/76 with nginx A/O2 and Apache A/O6 blocked;
`regressions-final-02` passed 75/76 with nginx A/O1 blocked. All three reports
contain only generic `isolation_unavailable`, with no usable final observation.
They are unnecessary refusals and neither run meets the regression gate.
Six initial instrumented repetitions on the candidate and six on accepted main
passed without establishing the original failures' cause. The later exact-sequence diagnostic below localized a separate reproduced failure. No deadline, output bound, policy or required case was relaxed.

### Shared recorder timestamp correction

The HTTP-only diagnostic completed all 52 cases. A diagnostic run preserving the
exact SSH20 → HTTP52 → authority4 pytest order, including inspection/replay,
stopped at test 44: Apache A/N4. The first 43 tests passed; 32 were not executed.
The retained inner exception is `stock_recorder_admission_event_mismatch` in
`Service.snapshot()` validation, propagated through recorder exit 78 to the
outer generic isolation refusal. This was not a session-time or output-budget
exhaustion. The failed numeric timestamps themselves were not retained.

Frozen source sampled the clock separately for the admission counter and event,
while requiring exact equality between them. A deterministic millisecond-boundary
test reproduces that defect. The correction uses the original admission instant
for rate enforcement and both recorded timestamps. Exact snapshot validation,
250 ms spacing, event limits, cleanup, schemas and all execution caps remain
unchanged. Tampered timestamps and full-event-ledger cases still refuse.

This localizes the captured Apache A/N4 failure. Earlier generic refusals remain
individually unlocalized; do not claim their causes were proved retrospectively.
The initial passing deployment and local portable runs above precede this
shared recorder correction. Their original results remain separate from the
corrected-source gates below.

## Corrected-source validation

Production and tests were frozen at `b7f308e`. Each complete gate below retained
all **986 source pins unchanged**, with zero failures, errors or skips:

| Gate | Result | Elapsed seconds |
| --- | --- | ---: |
| `regressions-final-03` | 76 accepted-profile and real witness checks pass; 72 HTTP/SSH bundles replay unchanged, with 40 useful completions, 32 expected negatives and zero unnecessary refusals. | 436.839 |
| `native-final-02` | All 80 required routing cases pass in one invocation; 50 bundles and 90 result snapshots independently verify unchanged. | 943.978 |
| `recorder-final-01` | All 32 shared-recorder checks pass: 26 legacy nginx corpus rows and six instrumented request/connection budget probes. The probes are enforcement evidence, not ordinary compatibility completions. | 171.663 |

The corrected routing gate confirms **24 ordinary deployment trials and 48
useful selected actions, with zero unnecessary refusals**, twelve aggregate-budget
negatives preserving prior useful work, and four default required-approval
refusals without result or reservations. Independent evidence review confirms
the twenty Apache custody receipts (eighteen consumed after reservation, two
closed unconsumed), seven isolated custody cases, four post-useful cleanup cases
and two live unconsumed-handoff cleanup cases. The latter still claim no routed
client execution or unacknowledged final owner snapshot.

Fresh complete-order measurements are below. Each order reserves four actions,
six connections, two HTTP requests, one SSH exchange and 26,624 output bytes.
Elapsed time includes setup/trial overhead; it is not a comparative benchmark.

| Deployment | Forward / reverse order time (ms) | Actual request / response bytes in each order |
| --- | ---: | ---: |
| nginx-A | 20,062 / 23,617 | 1,501 / 1,679 |
| nginx-B | 19,996 / 23,775 | 1,498 / 1,703 |
| apache-A | 22,400 / 24,412 | 1,501 / 1,887 |
| apache-B | 24,485 / 24,381 | 1,498 / 1,911 |

Five deterministic timestamp/tamper/event-limit tests pass after the correction;
the clock-boundary regression failed before it. Independent static review found
no concrete blocker and recorded authorship overlap and companion review.
The current-source full portable gate is the existing five-job Linux/Python
3.11–3.14 and macOS/Python 3.14 CI matrix, including its zero-skip guard. All five
jobs must pass on the final review revision before merge; the earlier local
26,873-test result is not represented as post-correction validation.

The private checkpoint records the final PR/CI references and review receipts.
Subsequent documentation reconciliation changes no production or test bytes.
All failed attempts remain retained. No case, deadline or execution bound was
removed; provider calls and actual cost remain zero. This candidate does not
close S3.5 or add an accepted catalog profile.

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
12–13 PRs because routing needs multiple batches. The catalog remains 52 accepted
profiles / 17 external programs. Completed milestones stay closed. Credentials,
paid/live models, deeper workflows, comparative benchmarking, attached networks
and proposal submission remain deferred.

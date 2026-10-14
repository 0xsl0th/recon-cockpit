# Stock nginx: authorized disconnected diagnostic

S3.2a is accepted in [PR #88](https://github.com/0xsl0th/recon-cockpit/pull/88)
at `5686dc8`. **S3.2b is implemented and validated in
[PR #89](https://github.com/0xsl0th/recon-cockpit/pull/89); PR review and acceptance
remain pending.** This implements S3.2's complete diagnostic contract within the
[Stage 3 plan](stage3-compatibility-routing.md)
using the [pinned source/runtime preparation](stock-nginx-feasibility.md).
It is a diagnostic, not a new catalog capability or production integration.
Accepted coverage remains 52 profiles across 17 external programs. Completed
milestones stay closed.

## Authority and transport

The caller selects one of two configurations and thirteen fixed cases. The
selection binds the exact action, policy, one-action budget, runtime manifests
and fresh owner identity. A full selection digest in the policy version prevents
approval reuse across cases that happen to share the same HTTP action.

The existing controller and isolated audit, approval and launcher services
remain mandatory. Durable execution intent, an independently verified audit
witness, consumed approval when required, admission and one-use redemption
precede owner startup. Audit records attest to the control path; they do not
authorize an action themselves. Neither a saved report nor its hashes can
restore a permit. The default diagnostic policy requires approval and an
unattended attempt is blocked. An explicitly selected unattended owned-lab test
policy is labeled as such; automated test execution is not personal approval.

The recorder owns the disconnected TCP namespace and independently accounts
for attempts, admitted connections, validated requests, daemon delivery and
response delivery. Only a complete exact request reaches nginx. The separately
confined stock daemon listens on a private Unix socket. The isolated launcher
creates its kernel-bounded private directory; the recorder mounts it read-only
and nginx mounts it writable. The client receives none of these mounts or owner
management descriptors, and client AF_UNIX access is blocked. The daemon and
recorder have independent process trees, namespaces and resource bounds.

The initial directory-FD handoff failed closed: Bubblewrap 0.11.2 resolves a
`--bind-fd` source to a pathname, which could not be found outside the recorder's
private mount namespace. Its [upstream implementation](https://github.com/containers/bubblewrap/blob/v0.11.2/bubblewrap.c)
explicitly documents this cross-user-namespace restriction. The revised layout
needs no extra namespace-entry privilege or service process. Creating the empty
private mount during launcher bootstrap does not start nginx or client traffic;
those still require authorization and both applicable launch witnesses.

The client verifies its confined namespace, destination denials and resource
boundary before signaling readiness. Only then does the authority arm the
recorder and release the same absolute one- or five-second action deadline over
the existing private pipe. Startup time is measured separately. A bounded 250 ms
result-marshalling allowance permits reporting after the action deadline; it
does not permit further forwarding. The session remains bounded to 60 seconds.

Each owner's 1 MiB aggregate storage allowance is partitioned into 768 KiB
kernel-bounded private scratch and at most 256 KiB retained logs/control evidence.
The stock launcher's ordinary `/tmp` is reduced to 256 KiB alongside that
768 KiB directory, preserving its aggregate 1 MiB scratch ceiling. Both service
owners retain the 256 MiB address-space and 64-descriptor limits. Child creation is
denied after setup. No package installation, host service, host route or external
network is used.

## Private evidence and replay

`scripts/stock_http_diagnostic.py run` accepts only A/B and the declared case
identifiers. Execution is off by default. A fresh private destination is required;
existing evidence is never overwritten. `--execute --unattended-owned-lab-test`
selects the explicit diagnostic test policy for this finite disconnected corpus.
There is no arbitrary URL, target, argv, credential or environment argument.

Each bundle preserves the selection/runtime manifest, durable action intent,
audit events, client raw result, original and transformed daemon response,
recorder event ledger, resource/namespace/cleanup receipts and report. Failed or
incomplete runs remain failures and are retained alongside later attempts.

```sh
.venv/bin/python scripts/stock_http_diagnostic.py inspect /absolute/private/trial
```

The inspector reads private regular files without following symlinks, checks
action/policy/runtime/audit continuity, reparses retained client bytes in a
networkless isolated parser and recomputes the saved result. It cannot execute
or resume an action. Hashes and replay prove internal evidence consistency,
not resistance to a compromised host changing all retained records.

## Frozen validation

Frozen source `d0bbdf208420e9d03fa35de6f8e3a67ac2777964` passed **60 native checks**, **15 accepted-profile native regressions** and **24,642 portable tests**, with no failures, errors or skips. All **874 tracked source hashes** remained unchanged in each run. Independent review, latest required checks and authorized merge remain acceptance gates.

The 60 stock-profile native checks comprise 26 fresh daemon trials, 29 authority/approval checks, three cancellation/startup-cleanup checks and two privately instrumented request/connection-budget probes.

**12/12 ordinary and 4/4 robustness tasks completed usefully, with zero unnecessary refusals.** Every one of the **10/10 correctly negative cases** delivered its declared GET to nginx, retained the complete original response and then exercised the selected fault. N1/N2/N5 stayed inconclusive, N3 timed out and N4 reached the output cap. The 26 corpus trials independently recorded **30 attempted/30 admitted connections, 26 delivered GETs and zero excess attempts**.

All **16 distinct destination-denial combinations** passed: two configurations × two action families × four denied endpoints. The full corpus repeats those checks **104 times**; neither total includes authority or request-budget rejections.

| Case | A / B result | A action ms | B action ms | A / B whole-trial ms |
| --- | --- | ---: | ---: | --- |
| O1 | useful / useful | 70 | 76 | 3279 / 3974 |
| O2 | useful / useful | 81 | 76 | 4045 / 4009 |
| O3 | useful / useful | 95 | 73 | 4124 / 4021 |
| O4 | useful / useful | 79 | 95 | 4110 / 4169 |
| O5 | useful / useful | 474 | 471 | 4844 / 4738 |
| O6 | useful / useful | 481 | 469 | 5110 / 4829 |
| R1 | useful / useful | 78 | 72 | 4227 / 4081 |
| R2 | useful / useful | 120 | 106 | 4764 / 4101 |
| N1 | inconclusive / inconclusive | 77 | 73 | 4316 / 3994 |
| N2 | inconclusive / inconclusive | 79 | 73 | 3463 / 3297 |
| N3 | timeout / timeout | 1026 | 1017 | 4909 / 4247 |
| N4 | output_limit / output_limit | 72 | 81 | 3417 / 3316 |
| N5 | inconclusive / inconclusive | 74 | 74 | 4049 / 3986 |

Measured distributions below use milliseconds and nearest-rank p95. Whole-trial time includes read-only preflight, authority services and result capture. N3 is separated because its response is deliberately withheld. Action measurements include bounded result reporting after forwarding stops at the action deadline; they are not the configured deadline values.

| Group / phase | n | Min | Median | p95 | Max |
| --- | ---: | ---: | ---: | ---: | ---: |
| Useful headers / action | 12 | 70 | 78.5 | 120 | 120 |
| Useful Nmap / action | 4 | 469 | 472.5 | 481 | 481 |
| Negative cases except N3 / action | 8 | 72 | 74.0 | 81 | 81 |
| N3 withholding / action | 2 | 1017 | 1021.5 | 1026 | 1026 |
| All trials / owner startup | 26 | 583 | 751.0 | 876 | 892 |
| All trials / client startup | 26 | 925 | 1076.0 | 1180 | 1324 |
| All trials / owner teardown | 26 | 2 | 3.0 | 3 | 10 |
| All trials / whole trial | 26 | 3279 | 4091.0 | 4909 | 5110 |

The private summary preserves every phase and per-case count. Other validation
was active on the same host during these trials. These mediated timings establish
no comparative baseline overhead or general service performance.

Retained responses advertise nginx **1.28.0** when version advertising is enabled; O6 advertises only `nginx` and its observations invent no version. Native Nmap XML records client version **7.95**. Exact daemon/client file hashes and each configuration/selection digest remain in the private manifests. Preparation manifest flags still describe read-only inspection; execution is established separately by the owner/result receipts.

A successful confined O1 trial independently consumed a required approval through a scripted owned terminal. That is a mechanism test, not personal owner acceptance. Invalid authority, approval or audit inputs were denied before unauthorized execution. Budget probes retained a denied second exact GET connection after one legitimate delivery, and a denied fourth Nmap-profile connection after three empty admissions. These privately instrumented probes do not count as compatibility completions. Prelaunch cancellation, cancellation during an observed N3 response and failed daemon startup reaped all observed descendants.

Every corpus bundle passed both Python and CLI inspection: **52 inspections** with bytes, permissions and modification times unchanged. Actual provider calls and spend were both **zero**. The 15 additional native regressions cover the existing configurable HTTP/SSH workflow and background service plus shared audit, approval and launcher boundaries; they are a finite regression set, not a repeat of every accepted native test.

The first regression attempt exposed a pre-existing missing DNS-MX fixture module in the configurable owner mount closure. All three affected workflows also failed on unchanged merged main `5686dc8`, with its 854 tracked hashes unchanged. Adding the exact required module only to the confined owner runtime restored those workflows; a cold isolated-import regression guards the closure. Client mounts, target scope and accepted action limits were not expanded. The baseline failures, candidate failures and successful repair proof are retained.

The first stock corpus at `f22905a` already passed all 60 native checks. That run and its original `corpus-summary.*` remain preserved; the complete native, portable and accepted-profile runs were repeated on the final repaired source above. Final receipts live under `.secure-agent/stock-nginx-native-20261014/`:

- `native-final-02/verification.json`: 60 native passes and source custody.
- `accepted-regression-final-02/receipt.json`: 15 accepted-profile native passes.
- `portable-final-02/verification.json`: 24,642 portable passes and source custody.
- `corpus-final-summary.json`: full source pins, 249 native-run artifact hashes, runtime/config identities and measurements; SHA-256 `adb0fbdbe9d6ee271837d78ba9e37ed92b55ee5ca3f82bef4899563bf43782a7`.
- `corpus-final-summary.md`: expanded case and latency tables.

Summary generation left every native-run artifact unchanged. Earlier startup failures, smoke runs, baseline regression failures and the first successful corpus remain separate; none replaces a final corpus row. Private artifacts stay outside Git. This diagnostic changes no catalog count or production-compatibility claim; S3.3 remains the next separate implementation and acceptance slice.

A subsequent portability review corrected Linux-specific assumptions in the
portable owner fixtures: the fake ancillary channel now supplies its explicit
Linux flag, directory-FD cleanup uses portable read-only descriptors, and the
unchanged early bootstrap is exercised with both real descriptor-directory
mappings. An additional portable case brings the current suite to **24,643**.
Production code and the native test cases remain byte-identical to `d0bbdf2`.
The final portable follow-up is retained in `portable-final-03/`; latest PR CI
must pass before acceptance. No native guard or enforcement assertion was weakened.

## Completion gate

Both configurations must pass all six ordinary, two robustness and five
negative cases: **12 ordinary and four robustness useful completions, ten
correct negatives and 16 distinct blocked destination checks**. Blocking an
ordinary task counts as an unnecessary refusal. Every negative must retain a
valid original nginx response before the selected transport fault. R1 preserves
hostile body text as data; R2 records four byte-preserving writes, not assumed
packet boundaries.
R1 verifies deterministic handling of hostile content; it is not a live-model
prompt-injection evaluation.

Missing, stale, replayed or mismatched required approval; audit failure; changed
authority/runtime/owner; expired/cancelled sessions; extra requests/connections;
private-listener bypass; cleanup and unchanged CLI/Python replay remain required.
Record client startup, action, owner startup/teardown and whole-trial latency
including read-only preflight, with zero provider calls/spend.
Comparative benchmarking and broader workflow composition stay deferred.

After S3.2b acceptance, S3.3 adds the separately reviewed production HTTP subset
and Apache comparison. SSH, disconnected multi-host routing, DNS/TLS name
binding and combined acceptance follow in roadmap order. Network attachment,
credentials, paid/live models and proposal submission require their later gates.

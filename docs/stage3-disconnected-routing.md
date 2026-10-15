# S3.5: disconnected routing implementation contract

First fixed-A routing review candidate in
[PR #94](https://github.com/0xsl0th/recon-cockpit/pull/94), following accepted
S3.4b in [PR #93](https://github.com/0xsl0th/recon-cockpit/pull/93) at `a7f46b1`.
This contract was pinned before implementation. It grants no execution authority
and does not close S3.5. The governing [roadmap](stage3-compatibility-routing.md)
still requires native execution, enforcement, evidence, regression and review gates.

## Finite first routing slice

Use fixed configuration A: owned nginx HTTP at `10.77.0.10:8080` and stock
OpenSSH at `10.77.0.20:2222`. Preserve their accepted generated public content,
public test host key, runtime pins and protocol/process limits. The four existing
action kinds are explicitly selected by the operator: HTTP Nmap identification,
exact HTTP header GET, SSH Nmap NULL/banner identification and RSA host-key
collection. They are independent actions, not a response-directed workflow.
Every action still requires exact policy authorization, independent durable
audit, any required single-use approval and consumed admission before launch.

Create five owned network namespaces under one disposable setup user namespace:
HTTP client, SSH client, router, HTTP frontend and SSH frontend. Four owned veth
pairs and static routes connect the client and service namespaces through the
router. The two service addresses belong to frontend interfaces, not loopback
aliases in a shared namespace. Stock daemon custodians remain independently
confined; frontend mediation retains its existing protocol limits.

The setup user namespace maps only its parent launcher's positive UID/GID to
local root. It owns every routed network namespace. Verify pinned namespace
identities and ownership, links, addresses and routes before releasing clients.
Temporary setup capabilities are removed before action execution. HTTP and SSH
clients use separate static destination filters; actions cannot reconfigure routes
or choose another namespace. No host network namespace, physical interface,
external default route, slirp transport or host firewall mutation is permitted.
Setup may run exactly six fixed, sequential nftables helpers: one temporary
SSH frontend ruleset before the four private TCP handshakes, then one final
ruleset per routed namespace, with at most one helper alive at a time. The
temporary rules allow only the four prebound tuples; the final SSH rules require
established connections on those exact tuples and the temporary listener closes.
The sealed topology/ledger owner has no children. No additional setup program or arbitrary command is allowed.
Setup also creates four finite private SSH TCP pairs (three banner connections
and one keyscan connection) inside the SSH frontend namespace. Close the private
listener, retain only exact established tuples, verify and drain the fixed setup
witness, then export the eight socket descriptors only to the trusted frontend
and custodian. The full export is eighteen descriptors: one user namespace,
five network namespaces, two service listeners, two role-bound ledger channels
and eight private SSH sockets. No such descriptor reaches a native client.

The owned router also hosts a listening excluded endpoint at
`10.77.0.99:8080`. Establish and record live listening baselines, including
wrong-port frontend witnesses, before final filters. Then prove that the selected
endpoint is useful while other-service, excluded and wrong-port connections are
denied. All setup witness connections must be closed and accounted separately;
they never reach a stock daemon or become reusable native-action channels.

## Pinned budgets

These ceilings apply to one assessment owner, across all its hosts, actions and
worker replacements. They are not refreshed by a new action identifier.

| Resource | Whole-assessment ceiling |
| --- | --- |
| Lifetime | 60 seconds; no extension or owner replacement |
| Explicit actions | Four, each selected action at most once |
| Admitted target connections | Eight: at most 3 HTTP Nmap, 1 header, 3 SSH Nmap and 1 keyscan |
| HTTP requests forwarded | Two exact GETs total; at most one per HTTP action |
| SSH key exchanges | One bounded public host-key observation; no client NEWKEYS, authentication or encrypted user session |
| Concurrent target connections | One globally |
| Connection admission rate | Burst one; at least 250 ms globally between admissions |
| Request bytes forwarded | At most 256 header bytes, 18 HTTP Nmap bytes, zero SSH Nmap bytes and 8,192 keyscan bytes; 8,466 aggregate |
| Response bytes forwarded | At most 2,048 header, 4,096 HTTP Nmap, 255 SSH Nmap and 8,192 keyscan bytes; 14,591 aggregate |
| Client output retained | 26,624 bytes aggregate; original per-action limits retained |
| Native action deadline | Header 1 second; each other action 5 seconds; existing native timeouts retained |
| Topology/ledger owner | One process, 256 MiB address space, 128 descriptors, 1 MiB bounded private evidence/scratch |

Retain existing stock-daemon/custodian and frontend per-process bounds. Namespace
setup is finite; all child processes and descriptors must be named and bounded
in the implementation contract before native release. Extra captured bytes may
only serve the existing bounded overflow witnesses, never forwarded payload.

A single owner-lifetime ledger reserves connections and request/key-exchange
units before service delivery. Reservations are consumed even when an action
fails. It retains global admission timestamps, action/runtime identity and
terminal state. Requests use sequenced, action-bound one-use reservations;
replays, changed identities, concurrent admissions, split-action replenishment
and lost continuity stop execution. Summing independent counters afterward is
not enforcement. Worker restart cannot replace the ledger or reset its budget.

Native enforcement tests may select only three additional fixed budget presets:
`connection_one` lowers the aggregate connection ceiling to one; `http_one`
lowers aggregate HTTP requests to one; `ssh_zero` lowers key exchanges to zero.
All other ceilings and the four otherwise authorized actions remain unchanged.
These explicit negative cases must report expected budget refusal, not useful
completion. No arbitrary budget values or target inputs are accepted.

The routing bootstrap alone has a separately bounded 128 KiB frame for the four
exact runtime manifests. Other profiles retain their existing frame limits;
each native client receives only its selected runtime. Saved evidence is bounded
separately to fifteen private files, 2 MiB aggregate, 512 KiB per JSON object and
depth 64. These artifact limits enlarge neither execution nor wire budgets.

## Completion criteria and remaining coverage

Before this batch is reviewable, prove actual rootless namespace/link custody,
useful selected-target native execution with structured results, live denied
destinations, aggregate enforcement across hosts/actions, cancellation/owner-death
cleanup and unchanged offline evidence inspection. Verify that audit/approval
failures prevent native launch and retain accepted-profile regressions.

Measure legitimate completion, unnecessary refusals, explicit denials, action
and total latency, resource use and cleanup. Provider calls and actual spend stay
zero. This is not a comparative overhead benchmark or personal approval exercise.
Failed development runs remain private evidence and cannot count as success.

This first slice does not automatically establish routed Apache, configuration B,
the full hostile/negative routing corpus or S3.5 acceptance. Account explicitly
for those gaps before closing the milestone. Existing accepted HTTP/SSH profiles
remain closed and retain their original support claims. S3.6 names/TLS binding
and S3.7 combined acceptance follow S3.5; credentials, paid/live models, deeper
workflows, benchmarking and attached targets remain deferred.

## Operator entry point and current validation

The fixed entry point is `scripts/disconnected_routing.py`. Select actions
explicitly; the order below is a list of independent requests, not a workflow
that grants authority from returned service data:

```sh
.venv/bin/python scripts/disconnected_routing.py run \
  --action http_nmap --action http_headers --action ssh_nmap --action ssh_keys \
  --directory .secure-agent/routing-example
```

The default is a dry run. Execution additionally needs `--execute`; the default
approval policy blocks unattended launch. Only the already-authorized fixed
disconnected test corpus uses `--unattended-owned-lab-test`. That flag records an
explicit test policy, never a personal approval. `--budget-case` accepts only the
four pinned presets. No address, shell command, credentials or external network
can be supplied through this entry point.

Read-only inspection is `scripts/disconnected_routing.py inspect DIRECTORY`.
Reports distinguish reserved capacity, actual delivered bytes, useful completion,
expected budget refusals, retained output and timing. Closure records physical
launcher cleanup and last acknowledged counters; it does not invent a graceful
final owner snapshot.

PR #94 is a review candidate on `feature/stage3-disconnected-routing` in
`/tmp/recon-stage3-routing`. Frozen `659c053` passed **25 native checks, 76
accepted-profile native regressions and 26,599 portable tests**, with all
**981 source pins unchanged** in each passing run and no skips, errors or failures.
The later checkpoint/runbook update changes documentation only. Fresh independent
code and saved-evidence reviews found no blockers within this finite slice.
Review the latest PR revision and checks before merge; this is not S3.5 closure.

The 25 native checks comprise four individual actions, two complete explicit
orders, three aggregate-budget negatives, one required-approval refusal, two
cancellation/launcher-death cases, four independent audit/approval denials, eight
descriptor/transport cases and one bootstrap descriptor-cleanup case. Ten trial
bundles and eighteen result snapshots passed both Python and CLI inspection
without changing bytes, modes or timestamps. Lifecycle failures retain separate
partial evidence; no missing final snapshot is invented.

| Measurement | Verified first-slice result |
| --- | --- |
| Ordinary usefulness | Six trials, 12/12 selected actions complete, zero unnecessary refusals. Both four-action orders complete 4/4. |
| Complete-order wall time | 21,913 ms and 22,053 ms, including trial overhead; no comparative baseline is claimed. |
| Complete-order aggregate use | Each reserves four actions, six connections, two HTTP requests, one SSH key exchange and 26,624 output bytes; actual request/response bytes are 1,501/1,679. Reservations and delivered bytes are separate measures. |
| Budget negatives | All three preserve the first useful header observation and refuse the later excess connection, HTTP request or key exchange. These are expected refusals, not complete legitimate assessments. |
| Network custody | Five distinct network namespaces, eight veth endpoints and live listening baselines. Eight denied role/destination checks per topology; useful native actions reach only their selected service. |
| Lifecycle and authority | Cancellation and launcher death prevent a second action launch and reap the tracked process tree. Audit/approval failures prevent native action launch. Default unattended execution has zero launches or reservations. |
| Provider calls and actual cost | Zero; no credentials or live models. |

Private source manifests, JUnit, command/log hashes and reviews remain under
`.secure-agent/stage3-routing-20261015/`. Passing gates are `native-final-02`,
`regressions-final-02` and `portable-final-01`; each has its own `verification.json`.
The native receipt SHA-256 is
`1b7838e4f3ab3f6622bb75678bb58402decc1e07344f2b98d888856f2de72251`.
No private artifact is committed to Git.

Retain the failed attempts as well. `topology-feasibility-01` refused before
worker startup because its private wrapper lacked `/tmp`; `02` and `03` refused
an extra pre-export descriptor after checking routed links/filters. Owners were
reaped; `04` subsequently passed. `native-development-01` passed 15/16 checks:
launcher death closed the audit channel and raised an exception where the test
expected a returned block. `native-final-01` passed 24/25: the retry assertion
expected `audit_closed` instead of the controller's `audit_previously_failed`
latch. Production code stayed unchanged while lifecycle expectations were
corrected; cleanup and no-second-launch requirements remained in the passing
25-case gate. A failed assertion does not prove later assertions ran.

`regressions-final-01` passed 75/76. Apache B/O1 recorded a blocked
`isolation_unavailable` outcome without sufficient inner-stage diagnostics to
identify the cause or establish how far execution reached. The relevant accepted
Apache implementation is unchanged from PR #93. Separate instrumented diagnostic
repetitions and the complete uninstrumented 76-case follow-up passed; neither
establishes a fix or erases the original unexplained refusal. No deadline,
security bound or required case was relaxed. Diagnostic repetitions do not add
unique acceptance cases.

**Next required work:** routed Apache and configuration B, then the complete
hostile/negative routing corpus under the pinned aggregate caps. S3.5 remains
open, Stage 3 remains seven accepted/three open, and the catalog remains 52
accepted profiles across 17 external programs. This branch accepts no new
catalog profile or completed milestone.

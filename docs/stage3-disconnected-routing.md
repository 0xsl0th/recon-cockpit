# S3.5: disconnected routing implementation contract

Current implementation batch after accepted S3.4b, merged in
[PR #93](https://github.com/0xsl0th/recon-cockpit/pull/93) as `a7f46b1`.
This contract is pinned before implementation. It grants no execution authority
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
Setup may run exactly five fixed, sequential nftables helpers, one per routed
namespace, with at most one helper alive at a time. The sealed topology/ledger
owner has no children. No additional setup program or arbitrary command is allowed.
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

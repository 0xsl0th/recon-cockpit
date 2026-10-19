# S3.6b: owned DNS, named HTTP and TLS authority

PR #97 accepted [S3.6a preparation](stage3-name-tls-preflight.md) at
`8b086d5`. Its 46 installed-runtime inspections establish static file identity,
not native execution. This document pins the separate native contract before
implementation. S3.6 and S3.7 remain open; the ten logical Stage 3 increments
still have eight accepted and two remaining. The current estimate remains
thirteen Stage 3 PRs. Accepted routing v1–v3 and all 52 existing secure profiles
retain their exact behavior and bounds.

## Authority that can be reviewed

Three additive candidate tool IDs, `owned_name_dns_v1`, `owned_name_http_v1`
and `owned_name_tls_v1`, use the new `owned_name_tls_v1` launcher profile.
Their strict parameter schemas carry the name, owner, runtime, selection and
observation commitments. Existing adapters and parameter schemas are unchanged.
Both approval views intentionally omit planner rationale, so placing binding
data only in rationale or an opaque action UUID would not satisfy exact review.
The new fields must appear literally in the exact action shown by both views
and enter the normal action, approval, audit and admission digests. No custom
approval shortcut or self-issued grant is added. The three profiles remain
candidates until all native, evidence, review and portable gates pass; dnsmasq
and nginx are fixture servers and add no external secure program.

Only the two configurations and 23 cases in the preparation contract are
selectable. The logical name is `harbordesk.test`; DNS asks exactly
`harbordesk.test. IN A` over TCP. Service addresses, ports, paths, exact named
Host, SNI, expected certificate name, C15 public CA, executable argv and public
fixture bytes remain those pinned by preparation. No arbitrary target, name,
path, trust file or runtime parameter is accepted.

The owner has four possible slots: `dns_1`, `dns_2`, `http`, `tls`. A finite
case plan permits at most three admitted executions. Only N1 permits `dns_2`.
O4 explicitly selects DNS → HTTP → TLS, with a separate DNS → TLS → HTTP
trial. A successful DNS observation creates data, never a grant, a queued
service operation or an automatic approval. Each selected service action must
return through the controller's ordinary witnessed authority path.

The N14 expiry probe has two additional typed *attempt* slots, HTTP and TLS,
which may pass static proposal admission and the ordinary witnessed checks.
They are committed separately from the owner's DNS-only execution plan. The
surviving owner rejects the first expired attempt before admitting an action,
connection or byte, and the second observes that terminal refusal. No daemon
or client starts for either probe. A proposal-level refusal alone cannot prove
owner-side TTL enforcement. Repeated send attempts always make fresh positive
byte reservations; earlier short or unwritten reservations remain charged.

An independently recorded, complete DNS response must agree with native dig
output before the owner can publish a usable binding. The owner records the
observation time using its own monotonic clock. Expiry is the smaller of the
owner deadline and observation time plus min(observed TTL, 60). N14's real TTL
is one second. Neither caller timestamps nor replay can refresh it. A new
observation invalidates the old generation, including previously reviewed
actions. Invalidation happens immediately when the second DNS action is armed,
before query delivery; a failed new query cannot restore the old binding.
An invalid observation cannot leave the previous binding active.

Every service action binds the canonical name, exact observed-answer digest,
TTL, selected numeric endpoint and port, case/selection, runtime identity and
owner identity. HTTP additionally binds the exact Host; TLS binds SNI, expected
certificate name and public CA digest. The parameters include the session ID
literally. Binding times are elapsed monotonic microseconds from owner start,
bounded to 0–60,000,000; the owner retains the actual monotonic reference.
Admission does not prove freshness: the surviving owner must compare the
reviewed binding with its own current state again before connection/request
reservation and before delivering service bytes. Reservation is irreversible;
partial failure, denied delivery and worker restart do not replenish allowance.
Expiry, cancellation, lost owner/channel continuity and invalid protocol input
fail closed. No serialized snapshot can recreate a live owner or grant.

Terminal behavior belongs to the exact action/probe slot, not the case name.
The valid DNS prerequisite of a negative HTTP/TLS case does not stop that case
before the required mismatch test. Once the selected negative operation or
probe is attempted, that plan ends and no further service work is admitted.
N15 contains two independently graded attempts: a finished-owner binding/grant
replay, and a grant from a still-live opposite-configuration donor replayed into
a fresh selected-configuration owner. The latter must not pass merely because
the donor was already expired or closed. N15 permits at most three distinct
owners, each with its own unchanged 60-second lifetime and counters.

## Owned topology and descriptor custody

The separately versioned topology has six persistent networks: DNS, HTTP and
TLS clients, one router, one DNS frontend, and one shared web frontend. HTTP
and TLS keep separate recorder processes, listeners and role-bound ledger
channels while sharing the web address. Five owned veth links use these fixed
point-to-point addresses; each non-router interface is `eth0`.

| Role | Router interface/address | Peer address |
| --- | --- | --- |
| DNS client | cd / 10.79.0.1/30 | 10.79.0.2/30 |
| HTTP client | ch / 10.79.0.5/30 | 10.79.0.6/30 |
| TLS client | ct / 10.79.0.9/30 | 10.79.0.10/30 |
| DNS frontend | fd / 10.79.0.13/30 | 10.79.0.14/30 |
| Web frontend | fw / 10.79.0.17/30 | 10.79.0.18/30 |

Only explicit /32 destination and reverse-client routes exist. Router forwarding
is internal; there is no host/default/physical route. IPv6 is disabled. Each
client permits only its own fixed IPv4 TCP endpoint, with established replies.
Six denied-destination listeners remain live: each selected port plus one on
its frontend and each selected port at the excluded address on router loopback.
Initial reachability witnesses precede installation of the final filters;
post-filter denial and zero delivered traffic must then be observed. The B
excluded address is exactly `172.23.0.99`, independently of accepted routing's
different historical excluded-address commitment.

Persistent exports are exactly one user namespace, six network namespaces,
three service listeners and three role-bound ledger channels: thirteen FDs.
After export, sender copies of service listeners and recorder-side channels
close. Record each inode, socket namespace cookie, endpoint and namespace
identity; no unexpected ancillary descriptor is accepted.

Every admitted operation starts a fresh daemon in an additional disconnected
network with only loopback and its compiled service /32. The exact preparation
configuration remains unchanged. DNS has its declared TCP and unused private
UDP listener; nginx has the exact HTTP and TLS listeners, even for one selected
operation. The daemon creates one unconnected TCP socket in its own network,
hands it through the trusted launcher to the selected recorder, and closes its
copy. The launcher verifies listener/image/namespace identity and closes its
copy too. Only the recorder may connect that socket, after reservation and exact
request validation. The native daemon cannot initiate a connection. Each
transfer and consumption is one-use; all copies close on every outcome.

The recorder has only its listener, role channel, at most one accepted client
and one handed daemon socket. It cannot enter namespaces or create arbitrary
sockets after setup. A client retains no owner/listener/namespace/daemon FD.
It creates its own filtered connection after a fresh, one-use launch commitment
and worker readiness. No client or parser sees the server key, its containing
Python fixture module, daemon configuration or daemon executable.

## Fixed native limits

| Bound | Value |
| --- | ---: |
| Owner lifetime, including topology startup | 60 seconds |
| Admitted executions / connections / concurrent connections | 3 / 3 / 1 |
| Minimum connection admission interval | 250 ms |
| DNS queries / HTTP GETs / TLS handshakes | 2 / 1 / 1 |
| Aggregate request / response / output bytes | 8,960 / 22,528 / 18,432 |
| Runtime inspection | 15 seconds |
| Ordinary trial watchdog, including inspection and finalization | 80 seconds |
| N15 composite watchdog, including inspection and finalization | 200 seconds |
| Topology startup within owner lifetime | 10 seconds |
| Address space per role | 256 MiB |
| Owner / recorder-daemon-client / parser FD caps | 128 / 64 / 32 |
| Native CPU / core / client file-write caps | 5 seconds / 0 / 0 |
| Private daemon scratch / per-daemon log | 768 KiB / 8 KiB |
| Ledger events / reserved cleanup events | 1,024 / 8 |
| Ledger request / reply / snapshot | 4 KiB / 2 KiB / 512 KiB |
| Bootstrap / evidence JSON / total trial evidence | 256 KiB / 1 MiB / 4 MiB |
| Evidence files / JSON nesting | 24 / 64 |

| Operation | Request bytes | Response bytes | Output bytes | Native seconds | Whole action seconds |
| --- | ---: | ---: | ---: | ---: | ---: |
| DNS | 512 | 4,096 | 8,192 | 3 | 10 |
| HTTP | 256 | 2,048 | 2,048 | 1 | 8 |
| TLS | 8,192 | 16,384 | 8,192 | 5 | 12 |

Topology setup precedes the first action ARM and consumes the same owner
lifetime, rather than the DNS action's ten-second deadline. Whole-action limits
begin at ARM and include startup (at most two seconds), isolated parsing
(one second) and cleanup (two seconds); every phase is clipped to the original
owner deadline. Native limits begin only after validated worker readiness and
owner admission. A fixed reservation records both proposed and actually
delivered bytes; an over-limit chunk is refused before delivery. Completed
actions do not refund reservations. Duplicate slots, split actions and worker
restarts cannot create another connection or extend a binding.

Four persistent payloads are the topology/ledger owner and three recorders.
An action adds at most one daemon and one client; parsing follows their closure.
The payload process peak is six, seven with one concurrent setup helper. Dig
alone may create threads, bounded to sixteen tasks in its process; other
payloads have one task. Thus the payload task peak is twenty-one, twenty-two
with a helper. Bubblewrap/nsenter wrapper lifetimes are separately counted and
bounded, never treated as permission for payload forks. Payloads launch at
private UID/GID 65534 with no capabilities and an immutable recorded group
mapping. No-daemon dnsmasq does not perform a privilege drop for the launcher.

Each payload has a fixed inspected executable allowlist, read-only sealed
runtime and Landlock/seccomp restrictions. Process forks are denied. This
contract does not claim that seccomp counts executions of an allowed image;
re-execution cannot reset owner counters or acquire another connection. The
native image/argv/runtime commitment and no-extra-child boundary must be
witnessed, independently of useful output.

The fixed helper invocation ceilings are thirteen bwrap, six nsenter and nine
nft invocations per owner (twenty-eight total). Each transient configuration
helper has at most two seconds and 8 KiB output; a wrapper supervising its
payload inherits that payload/owner deadline, not a two-second payload kill.
No shell or ip helper is introduced. DNS startup permits NETLINK_ROUTE for
read-only interface discovery, with at most two observed live discovery sockets
at readiness, under the fixed FD/startup/output limits. Dropped capabilities
prevent network mutation after setup. This is an observed socket inventory,
not a claim that classic seccomp counts netlink messages or bytes. Required
behavior outside the finite runtime is an unsupported result, not a reason to
silently widen the filter.

ARM carries the canonical action and fixed runtime identity, not an entire
policy or runtime file manifest. DNS observation messages contain the bounded
decoded summary and original/delivered hashes. FINISH_ACTION reconciles the
actual native result and isolated parsed observation before publishing binding
data. A reply carries at most one binding; snapshots use their separate bounded
transport. Each serialized ledger event is at most 384 bytes. Eight event slots
remain reserved for termination/cleanup, and protocol errors cannot erase the
earliest terminal reason.
FINISH_CONNECTION reports actually delivered request/response counts and a
transcript digest, bounded by the irreversible reserved amounts. Abrupt loss
retains the last acknowledged counts and labels later delivery unknown; it
does not invent zero delivery or a graceful final snapshot.

Role manifests partition the 52 prepared native ELF files and ten compiled
files. DNS owner gets dnsmasq, its linked closure and DNS config; web owner gets
nginx, its linked closure and server certificate/key/config. Dig gets its own
linked closure, empty resolver/OpenSSL config and fixed identity files.
OpenSSL gets its linked closure, the public CA and the same empty/fixed files.
Python HTTP, recorder and parser roles get only their needed bootstrap/source
closure. Nothing mounts the full preparation union into a client or parser.
The DNS daemon additionally receives Landlock READ_FILE permission for exactly
`/dev/urandom`. Before granting it, open that path with O_NOFOLLOW and verify by
fstat that it is character device major 1, minor 9; retain the device identity
receipt and close the verification descriptor before native execution. This
receipt is exactly `{"path":"/dev/urandom","type":"character","major":1,
"minor":9,"access":"read"}` for DNS and null for the web daemon. The trusted
launcher independently opens the path with O_NOFOLLOW through the actual
pinned daemon process's root and verifies the device with fstat. Its observed
`native_ready.entropy_device` must equal the worker's
`daemon_ready.entropy_device`; close this independent verification descriptor
as well. This
exception grants no write access, `/dev/random` access or general `/dev` access,
and does not add entropy access to another role. It is separate from the
regular-file manifest; entropy bytes are never retained. The installed
dnsmasq-base 2.91-1 executable (496,824 bytes, SHA256
`b6168c4506008dac9244e2f011b9743af552f81b3298f7966b5dec98d8fcee33`)
opens that device read-only for its startup seed. Its observed failure without
this permission remains a failed diagnostic, and the exception makes no claim
to count all entropy reads or bytes.
Native acceptance verifies that these strict allowlists suffice; it does not
claim a complete open-syscall trace. An unknown required file/provider/module
fails closed and requires an explicit reviewed contract revision.

## Native evidence and claim boundaries

DNS framing includes the two-byte TCP length. Validate one exact question,
transaction ID, flags, section counts, bounded compression pointers and record
lengths. Require complete frame consumption and no trailing query/response.
The finite parser records singleton/multiple A, CNAME, NS referral and AAAA
outcomes as data; only the declared singleton IPv4 answer may support binding.
No alias, referral, advertised address, search suffix or UDP fallback is used.
R2 segments one recorded response; N8 preserves its declared length while
delivering the exact pinned truncated bytes. The recorder retains the original
stock-daemon bytes separately from every transformed delivery. N1's second
changed observation is an explicit authority probe, never a claim that the
unchanged stock configuration emitted a changed answer.

HTTP independently records the exact named request and complete bounded
response, reconciled with the native header reader. Redirect destinations and
hostile text remain evidence; neither is followed. An incorrect Host is refused
before service delivery.

TLS validates a complete ClientHello, including exact SNI, P-256, TLS1.3 and
TLS_AES_256_GCM_SHA384, before forwarding it. A second ClientHello, HRR,
resumption, early data or another selected version is refused. The sole native
OpenSSL process receives EOF on stdin and no application input. Useful TLS
requires its successful exit and exact verified-name/verification output,
matching owned certificate/CA/runtime commitments, and independently recorded
ClientHello/ServerHello/version/cipher and bounded wire flights. TLS1.3 encrypts
Certificate and Finished; passive record capture does not independently verify
those contents. Record type 23 is not proof of application traffic or its
absence. Native verification and wire observations are reported separately;
there is no revocation, general server identity or HTTP-over-TLS claim.

Each parser runs in a separate networkless, no-exec/no-child runtime without
daemon binaries, client binaries, server key, authority descriptors or owner
state. Pure public protocol constants must not import a module containing the
fixture server key. Inputs and normalized outputs are bounded; malformed,
oversized, contradictory or timed-out parsing yields no useful claim.
The parser has a 128 MiB address-space cap (the deliberate exception to the
256 MiB native-role cap), 32 FDs, one process, zero file/core output and one
second CPU/wall time. Framed input is at most 131,072 bytes and normalized
output 8,192 bytes. DNS permits at most eight records, eight compression-pointer
hops, 255 expanded name bytes and one question/frame. TLS allows at most
thirty-two records per direction, each with at most 18,432 payload bytes,
subject to the stricter aggregate direction limits; ClientHello is at most
4,096 bytes. HTTP headers are at most 1,024 bytes.

The exact DNS semantic object contains `schema_version: "1"`, a question
(`name`, `class`, `type`), integer transaction ID and flags, and ordered records
with `section`, `name`, `type`, `class`, `ttl`, `data`. Wire digests and owner
times are separate provenance. The native text parser and wire parser must
produce identical canonical semantic digests. A binding requires the sole
selected IN A answer, TTL 60 (N14: 1), no authority/additional records and
QR|AA flags with optional RA. Other finite negative replies remain data.

Saved raw artifacts, native exit/output, independent recorder transcript,
owner ledger, authority/audit trail, namespace/descriptor custody and physical
cleanup must all agree. A missing or contradictory component fails grading.
Python and CLI inspection reproduce reports without editing artifacts.
Failed attempts remain retained and are never relabeled as successful runs.

## Acceptance sequence

The 46 preparation selections are all required native cases. Add two reverse
O4 orderings and six default approval refusals (DNS, HTTP, TLS × A/B): 54 corpus
trials before the separately enumerated enforcement gates. N15's two required
subchecks are explicit within each logical row. A refusal never counts as
useful native execution. Authority/owner, topology/process and parser/evidence
inventories are pinned in [the exact gate inventory](stage3-name-tls-native-gates.json)
and must match collected/completed identities before any acceptance claim.
The new native union is **327**: 54 corpus trials, 162 architecture/physical
enforcement trials, 59 additional owner-channel trials, 36 authority-witness
trials and 16 parser/evidence trials. The owner inventory has sixty obligations;
its real sixty-second expiry obligation shares the architecture A expiry trial
and is counted once. All other apparent overlaps exercise different boundaries
(for example ledger reservations versus actual wire delivery) and remain
separately identified. Authority witnesses cover twelve mutation classes for
each of the three operations on configuration A; the corpus covers both A/B.

Owner gates B20/B21 are composite proofs. Each retains two actual authorized
N1 DNS executions and a real HTTP or TLS approval reviewed after the first DNS
execution. A fixed sealed test variant observes the surviving owner's second
DNS ARM: the first binding and exact reviewed action validate immediately
before ARM; immediately afterward the binding is absent and generation is two.
At that same recorded owner time, the unchanged binding guard must refuse with
`binding_missing`. The unchanged connection reservation guard, called directly
on the same live owner with the stale action commitment, must refuse with
`action_binding_changed` and leave the entire post-ARM state unchanged. These
direct guard calls are explicit test instrumentation, not inherited-channel
messages or service delivery. Retain their exact source hashes, action digests,
before/after states and refusal reasons; match the action digest to the actual
reviewed grant. The second native DNS observation and the later Controller
attempt remain separately recorded. That later attempt reaches the static N1
profile guard, which is not evidence of owner-side grant revocation. N1 never
admits HTTP or TLS service execution; these gates do not claim the reviewed
service grant was previously executable under N1 or was removed from the
approval store. The production case plan and authority protocol remain fixed.

Owner gate L18 uses two fresh private owners. On one, a second connection on
the same inherited role channel must reach `concurrent_connection_limit`; on
the other, a second role's connection attempt while the first lease is active
must reach the earlier `action_role_changed` guard. Both retain the actual
role-channel transcripts, unchanged connection/byte charges and physical
cleanup. The two observations are subchecks of the single L18 gate.

Retain all 248 accepted S3.5 routing checks, the 76 distinct accepted HTTP/SSH
and witness regressions, and the 60 legacy v1/v2 bundles inspected through both
Python and CLI (120 unchanged inspections). Pin their exact union by collected
test identity; do not count an overlap twice. Freeze source and native runtime
hashes before validation and compare them after each run. All five complete
portable CI jobs must pass at the final reviewed head with no skipped cases.
S3.7 combined acceptance remains required after accepted S3.6b.

This contract does not permit host services, attached targets, external routes,
credentials, provider calls, generated keys, response-directed work or changes
to accepted routing limits. Native process behavior and runtime-loaded module
closure remain unverified until the separately recorded native gates pass.

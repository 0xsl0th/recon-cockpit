# S3.6: owned DNS and TLS name-binding preparation

This contract is pinned before new implementation. S3.5 is accepted in
[PR #96](https://github.com/0xsl0th/recon-cockpit/pull/96), merged as `6f60ae0`;
its full native matrix and portable evidence remain closed. This preparation
was accepted in PR #97; PR #98 subsequently accepted the separate S3.6b native
slice, closing S3.6. [PR #99](https://github.com/0xsl0th/recon-cockpit/pull/99)
accepted [S3.7 combined acceptance](stage3-combined-acceptance.md) at `4ef9b98`,
closing Stage 3. The batch described
below is static preparation only. It creates no action,
approval, authority, socket, namespace, daemon or client execution.

## Required sequence

S3.6a implements the finite specification, generated public fixture files and
read-only runtime inspector below. S3.6b must separately freeze the production
binding/owner/process contract, then pass every native case and enforcement
requirement below. Preparation does not establish configuration validity,
startup, confinement, useful observations or name/trust enforcement. S3.7
combined acceptance follows accepted S3.6; it cannot be skipped.

The original preparation checkpoint had eight accepted increments and two
remaining. After PR #98, Stage 3 had nine accepted increments and one remaining.
PR #99 closed all ten logical increments in thirteen PRs, #87–#99, within the
preceding 12–13 estimate. At this preparation checkpoint, the 52 accepted profiles
and 17 external programs retained their existing semantics; these fixture server
binaries added no secure-tool integration. The current catalog has 55 accepted
profiles, zero candidates and the same 17 programs. Current work is the
[S4.2b durable dispatch accounting](stage4-engagement-dispatch-ledger.md)
and [implementation inventory](stage4-engagement-dispatch-ledger-gates.json), following
S4.1 acceptance in PR #100 and S4.2a acceptance in PR #101 at `43869cb`. Credential use,
models, attached networks, general workflows and benchmarking remain deferred.

## Closed endpoints, names and operations

Two closed configurations reuse the owned RFC1918 A/B address families. No
caller-supplied hostname, IP, port, path, certificate, runtime or configuration
file is accepted.

| Configuration | Resolver TCP endpoint | HTTP endpoint/path | TLS endpoint | Excluded endpoint |
| --- | --- | --- | --- | --- |
| A | 10.77.0.53:5353 | 10.77.0.10:8080/harbordesk/portal.html | 10.77.0.10:8443 | 10.77.0.99 |
| B | 172.23.0.53:15353 | 172.23.0.10:18080/portal/index.html | 172.23.0.10:18443 | 172.23.0.99 |

The declared logical name, SNI and expected certificate name are exactly
`harbordesk.test`; its wire DNS question is exactly `harbordesk.test. IN A`.
The allowed endpoint set is the singleton selected HTTP/TLS IPv4 address.
The HTTP Host includes the declared name and selected HTTP port. Resolver,
excluded and other-service addresses never become allowed service answers.

Future operations are independently selected and authorized: one bounded TCP
DNS A query, one exact named HTTP GET, and one verified TLS handshake. No DNS
observation creates a grant or automatically starts another action. Each later
action must commit the canonical name, exact observed-answer digest and TTL,
selected numeric endpoint/port, exact Host or SNI, expected certificate name,
public CA digest, case, runtime and aggregate owner identity. A changed answer
invalidates the previous binding and requires fresh review and authority.
Ordinary DNS records use TTL 60; the N14 expiry fixture uses TTL 1.
Binding expiry uses the owner's monotonic observation time plus min(observed TTL,
60 seconds), without extending the remaining owner lifetime. No wall-clock or
caller-supplied observation timestamp can refresh it. N1 permits at most two
separately authorized DNS queries; an explicit second observation invalidates
the old binding even if a client attempts to reuse an earlier grant.
An expired, ambiguous, excluded, CNAME, referral, non-A or malformed answer
cannot support a binding. Returned strings remain untrusted evidence.

The TLS operation uses OpenSSL `s_client`, IPv4 numeric `-connect`, explicit
`-servername`, `-verify_hostname`, `-verify_return_error`, one compiled CAfile,
`-no-CApath`, `-no-CAstore`, `-no_ticket`, `-no_renegotiation`,
`-nocommands`, fixed group P-256, TLS1.3 only and TLS_AES_256_GCM_SHA384. It supplies no
application input and performs no HTTP request, login, STARTTLS, reconnect,
resumption or certificate-directed fetch. The named HTTP GET is a separately
authorized operation. Neither operation consults the host resolver/trust store.
The exact DNS and TLS argv vectors, environment and HTTP bytes are generated
from closed selectors and included in the preparation digest.

## Finite required case inventory

Both configurations require every row below: 23 cases and 46 selections. Cases
whose fault is an authority proposal or recorder transformation keep the actual
stock-daemon result separate; a refusal is never counted as useful execution.

| Case | Required later native result |
| --- | --- |
| O1 | Valid single A answer from the owned stock resolver; no automatic follow-up. |
| O2 | Separately authorized named HTTP GET after a valid binding, exact Host and path. |
| O3 | Separately authorized TLS handshake with exact endpoint/SNI/name and pinned CA. |
| O4 | DNS, named HTTP and TLS selected explicitly in one bounded owner lifetime. |
| O5 | HTTP redirect recorded as metadata, with no connection to its destination. |
| R1 | Hostile HTTP text remains untrusted data, with no added request or authority. |
| R2 | Bounded segmented DNS TCP reply preserves the same exact useful answer. |
| N1 | A later changed answer cannot reuse an earlier reviewed binding/grant. |
| N2 | Excluded address answer refuses binding and subsequent service work. |
| N3 | Multiple different A answers refuse the singleton binding. |
| N4 | Undeclared logical name refuses before query/service delivery. |
| N5 | CNAME advertisement recorded without chasing or creating a binding. |
| N6 | DNS referral/NS advertisement recorded without querying the advertised server. |
| N7 | Non-A/IPv6 answer grants no IPv6 transport or service binding. |
| N8 | One exact TCP DNS frame truncated below its declared length refuses with no retry, UDP fallback or added query. |
| N9 | Mismatched HTTP Host refuses before delivery to the service. |
| N10 | Mismatched TLS SNI refuses before an unauthorized handshake. |
| N11 | Wrong certificate name fails native verification; no useful TLS claim. |
| N12 | Untrusted issuer fails native verification; no alternate trust source. |
| N13 | Expired public test certificate fails native verification. |
| N14 | Expired DNS binding cannot authorize service work. |
| N15 | Both old-owner/finished-binding and cross-A/B grant replay attempts are refused; neither changes destination. |
| N16 | Server TLS version mismatch fails the sole selected TLS1.3 operation. |

Case driver kinds are explicit: O1–O5, R1, N2/N3, N5, N11–N13 and N16 use
compiled stock-daemon configurations; R2 and N6–N8 use independently recorded
bounded wire transformations; N1, N4, N9/N10 and N14/N15 are authority/owner
probes. They retain baseline records, addresses and service behavior; N14 alone
changes the generated DNS TTL from 60 to 1 for its real-expiry fixture. Other
authority probes retain baseline daemon bytes and cannot claim the daemon
emitted a refused operation. N1 includes a second bounded observation; N14 uses
real monotonic expiry. A digest binds the driver kind and every exact transform
or probe expectation, even when native/generated file bytes are otherwise equal.

The native case inventory must also include DNS → TLS → HTTP O4 ordering on
both configurations and default-approval refusals for each of DNS, HTTP and TLS
on both configurations. These eight additional trials do not replace the
separate enforcement inventory. The current preparation run still has exactly
46 selections and claims no native case completion.

S3.6b additionally requires exact authority/approval/audit/admission ordering,
wrong port and other-service/excluded destination denial, real request and byte
accounting, duplicate/replayed/split-action/worker-restart refusal, monotonic
lifetime/rate/connection limits, malformed and oversized input/output handling,
cancellation, owner death and physical cleanup, parser isolation and evidence
tamper rejection. Each case needs actual native status and independent wire/
request/answer or handshake corroboration. Python and CLI inspection must
reproduce saved reports without modifying their artifacts. Preserve all
accepted routing and HTTP/SSH regressions and all five full portable CI jobs.
The native batch must pin its exact topology, process/descriptor limits and
aggregate/per-operation budgets before implementation; it may not silently
reuse grants or widen the accepted v1–v3 routing profiles.

## Current implementation boundary

Implement only `name_tls_spec.py`, `name_tls_runtime.py`,
`scripts/inspect_name_tls_runtime.py`, their focused tests and these roadmap
updates. The pure specification provides closed configuration/case selection,
expectations, exact proposed operation descriptors/argv/request bytes,
compiled fixture files and a deterministic complete selection digest. It does
not parse live DNS, issue bindings/grants or register tools/backends/launchers.
Preparation metadata must explicitly report that native execution and runtime
closure are unverified.

Generate dnsmasq configuration with no resolv/hosts input, no upstream servers,
no cache/search/recursive lookup, one explicitly bound owned address/port and
public local records. Run proposals use no-daemon mode and log-facility=-; no DHCP, TFTP, D-Bus,
DNSSEC, lease, nftset, IPset or external include is enabled. Any unused DNS UDP
listener inside the future private resolver namespace is not client authority;
client transport and future wire enforcement remain TCP-only.

Generate a separate nginx named HTTP/TLS configuration from fixed strings with
no external includes, resolver, proxying or access log. TLS tickets/session
cache and TLS versions outside the selected case are disabled; default SNI
rejects, the selected logical name uses the compiled public certificate/key,
and HTTP compares the exact `$http_host` including its port. P-256 is fixed
on the server as well. The N16 TLS1.2-only negative applies at the default TLS
server/protocol context before SNI selection. Negative certificate/version scenarios use
closed public fixtures. Proposed recorder/authority-only cases explicitly
retain baseline daemon bytes (apart from N14's explicit TTL 1) rather than pretending the daemon generated a
transformed or refused operation.

Reuse the deliberately public C15 P-256 fixture key, CA and certificate variants;
there is no key generation or real credential use. Public server-key bytes are
owner fixture material and must not enter a future client/parser runtime.
Generate empty resolver/OpenSSL configuration and fixed passwd/group/nsswitch
files where needed. Every generated destination, size and SHA-256 is bound.

Pin exactly four installed ELF images: `/usr/sbin/dnsmasq`, `/usr/sbin/nginx`,
`/usr/bin/dig` and `/usr/bin/openssl`, their fixed x86-64 interpreter and exact
linked-dependency lists. Metadata commands are limited to four bounded trusted
`ldd` probes; no daemon/client/configuration check is executed. Validate the
fixed dependency closure before hashing canonical root-owned non-writable
regular ELF files using the existing bounded stable-reader checks. Do not accept
caller-supplied paths, extra libraries, unknown source aliases or mutable files.

Manifest limits: 128 files, 16 MiB each, 128 MiB total, 64 KiB encoded manifest;
inspection has one real 15-second control deadline. Structural validation is
pure and detached; `verify_current` rechecks each current canonical path/hash
without invoking metadata commands or trusting supplied command strings.
The CLI takes only configuration, case and a new private receipt path. Exclusive
creation, owner-only parent/file permissions, no symlink overwrite and failure
receipts precede any success claim. No `--execute` option exists.

## Preparation validation and source references

After implementation/review, freeze source and inspect all 46 selections with
real installed files, retaining complete receipts and unchanged source pins.
Verify that all generated files/operation descriptors match their commitment,
that all manifests reverify, and that zero services/actions/provider calls or
spend occurred. Portable tests exercise selector/digest/configuration tampering,
source-path/dependency/hash/type/size drift, cancellation/deadline checks and
private CLI output handling. Complete all five final-head portable CI jobs.
A passing preflight closes S3.6a only; it does not close S3.6 or Stage 3.

Local installed package inventory: dnsmasq-base 2.91-1, nginx 1.28.0-6,
OpenSSL 3.5.4-1 and bind9-dnsutils 1:9.20.15-2. Runtime hashes, not these version
labels, identify an inspected installation. Preparation must document any
runtime-loaded module/helper uncertainty instead of claiming complete closure.

Primary references: [dnsmasq manual](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html),
[nginx SSL module](https://nginx.org/en/docs/http/ngx_http_ssl_module.html),
[OpenSSL s_client](https://docs.openssl.org/3.5/man1/openssl-s_client/).
Installed manual pages and package metadata are retained in the private source
review. These references inform proposed settings; only the separate native
gate can establish that they work inside the reviewed execution boundary.

## Implementation and inspection entry point

The pure compiler and read-only inspector implement the pinned contract at
`2f29145` with the N14 TTL clarification at `1b99fc5`. Each selection binds ten
compiled public fixture/configuration files. The installed dependency inventory
contains 52 native ELF files (four executables and 48 unique interpreter/library
files), making 62 manifest rows per selection. The native files total
33,724,240 bytes in the inspected installation; actual hashes identify it.
These linked dependencies do not establish runtime-loaded module/provider
closure or successful configuration parsing.

The CLI accepts only closed selectors and a new receipt below an existing
owner-only directory, for example:

```sh
mkdir -m 700 /tmp/name-tls-inspection
.venv/bin/python scripts/inspect_name_tls_runtime.py \
  --configuration A --case O1 --output /tmp/name-tls-inspection/A-O1.json
```

An existing output, symlink parent/file or non-private parent is refused.
Successful `runtime_inspected` receipts keep native execution, configuration
validation, complete runtime closure and authority explicitly unverified.
The four trusted `ldd` probes share the same real fifteen-second control as
file inspection and reverification. The CLI never executes the proposed DNS,
HTTP, TLS or daemon inputs.

The new portable preparation suite has **327 tests**: 122 spec/compiler,
184 runtime and 21 CLI tests. Initial focused runs pass. All five final-head portable CI jobs and final
review remain separate gates recorded in the private checkpoint and PR checks.

## Frozen read-only inspection results

Frozen implementation `df093a46862f642cdb123a9a9d6c00eb73dc91e4` passed all
**46 real installed-runtime inspections** in `inspections-final-02`. Collected,
completed and successful selection identities match exactly; all **1,003 tracked
source hashes** stayed unchanged. Every receipt binds the exact 52 native and
ten compiled-file rows, and all 46 native pin sets match. The complete run took
28.679 seconds; individual CLI inspection times were 369–427 ms. Services,
tool actions, bindings, authority, generated keys, provider calls and spend
remain zero. Configuration parsing, runtime-loaded provider/module closure and
native compatibility remain unverified.

The verification receipt has SHA-256
`356054c37e4b3d81f758e10f1c4c0e0b96baf4ca6e431f5cf887b64451e9f85b`
and is retained below `.secure-agent/stage3-name-tls-20261015/`. The preceding
`inspections-final-01` remains a failed attempt: the coding sandbox's user
namespace exposed root-owned system files as UID 65534, so every selection
correctly refused at the root-ownership check. The successful run used the same
frozen source outside that sandbox under the normal user; no ownership check,
deadline or runtime limit was relaxed. Read-only inspection still grants no
native execution authority.

The same branch also corrects the existing portable SSH evidence peer-lifetime
fixture and adds two A/B regressions, as recorded in the
[routing matrix runbook](stage3-routing-matrix.md#post-merge-portable-ssh-peer-lifetime-correction).
The preparation implementation is unchanged from the frozen inspection head.
Final acceptance requires all five Linux/Python 3.11–3.14 and macOS/Python 3.14
jobs to complete **27,603 portable tests each**, with 1,907 integration tests
deselected, no skips/failures/errors and the completeness guard. Original failed
attempts remain recorded separately. [PR #97](https://github.com/0xsl0th/recon-cockpit/pull/97)
merged the reviewed head `057567d` at `8b086d5`; the reviewed and merged trees
match. All five final and post-merge CI jobs passed the complete counts above.
S3.6a is accepted. PR #98 subsequently accepted the separately validated
[S3.6b native binding](stage3-name-tls-native.md) at `c71b599`, closing S3.6.
[S3.7 combined acceptance](stage3-combined-acceptance.md) was accepted in PR #99
at `4ef9b98`, closing Stage 3. Its reviewed and merged trees match;
[post-merge CI](https://github.com/0xsl0th/recon-cockpit/actions/runs/39502316329)
is tracked separately under `.secure-agent/pr99-review-20261020/`. Continue with the [S4.2b durable dispatch accounting](stage4-engagement-dispatch-ledger.md).
The preparation-only limitations above describe this batch, not the later native evidence.

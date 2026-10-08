# Discover accepted secure tools

The read-only CLI catalog makes the accepted B0–B8 profiles discoverable without
starting an assessment. The accepted B0–B8 baseline contains 20 capabilities backed by 11 external
programs; the native TCP, HTTP and header adapters are capabilities without a
separate executable. These counts describe bounded secure profiles, not arbitrary
modes of each program or production engagement readiness.

The configurable HTTP/SSH slice adds three separately versioned profiles of
existing implementations: Nmap identification, HTTP headers and SSH host keys.
That accepted slice brought the catalog to **23 profiles using the same 11 programs**.
Their recipes point to an explicit scope file and the
[configurable owned-lab runbook](configurable-owned-lab.md); no existing recipe
or accepted execution contract is broadened.

C1 Redis/SNMP is accepted in [PR #55](https://github.com/0xsl0th/recon-cockpit/pull/55),
bringing that accepted slice to **25 profiles using 13 programs**. The [Redis/SNMP runbook](redis-snmp-tools.md) covers one fixed Redis
`INFO server` and one SNMPv2c GET over TCP for three system scalars. Both use
the owned `127.0.0.1:8080` fixture and require fresh approval. SNMP's community is
public synthetic test data; no real credential setup, host configuration,
MIBs, UDP, walks or writes are introduced.

C2 [PostgreSQL/MySQL pre-authentication TLS](database-tls-tools.md) is accepted in
[PR #56](https://github.com/0xsl0th/recon-cockpit/pull/56), bringing that slice to **27 profiles
using the same 13 programs**. Local validation
passed 10,776 portable and 28 native Linux tests; both ordinary TLS tasks completed
with zero unnecessary refusals, and all 24 forbidden-destination witnesses blocked.
Each database recipe stops after a verified fixture TLS handshake
and clean close, without credentials, login or SQL.

C3 [WhatWeb fingerprinting](whatweb-tools.md) is accepted in
[PR #57](https://github.com/0xsl0th/recon-cockpit/pull/57), bringing that slice to
**28 profiles using 14 programs**.
Its recipe permits one fixed GET with five exact plugins and no redirects,
credentials or follow-up. Ruby supports the WhatWeb runtime and is not separately
counted as an assessment program. All 11,109 portable and 39 selected native tests
passed. Independent trials completed 2/2 ordinary and 2/2 robustness tasks with zero unnecessary
refusals, blocked 8/8 forbidden destinations and replayed 36 accepted bundles
unchanged. Fresh review and all five hosted jobs passed before the authorized merge.

C4 [DNS SRV metadata](dns-srv-tools.md) is accepted in
[PR #58](https://github.com/0xsl0th/recon-cockpit/pull/58), merged as `6080a5c`.
It adds a separately versioned
fixed service-location query using the same dig program and runtime closure.
That accepted slice brought the catalog to **29 profiles using the same 14 programs**. The recipe binds
one nonrecursive TCP `_ldap._tcp.harbordesk.test. IN SRV` question and requires
fresh approval; advertised targets and ports cannot select another operation.
Four ordinary outcomes must complete usefully, including NODATA, NXDOMAIN and
reported service unavailable, with separate hostile-metadata usefulness. Native
validation passed 25 selected tests, including all ten scenarios and their
20/20 blocked destinations. Clean-source verification repeated 4/4 ordinary
completions and the separate useful hostile case, with zero unnecessary refusals,
10/10 blocked destinations and 40 accepted bundles replayed unchanged through both
inspectors. All 11,428 portable tests passed, with zero failures/errors/skips.
Independent review and all five final hosted jobs passed; reviewed `65810b8` and
the merge have identical trees.

C5 [RDP initial negotiation](rdp-negotiation-tools.md) is accepted in
[PR #59](https://github.com/0xsl0th/recon-cockpit/pull/59), merged as `846e459`.
It adds `rdp_initial_negotiation_v1`, bringing accepted main to **30 profiles using the
same 14 programs**. Its repository-owned Ruby adapter sends one fixed 19-byte TLS
offer, closes the socket's write side and reads only the first 11- or 19-byte
reply. Ruby remains supporting runtime, not a newly integrated third-party tool.
The profile has no security handshake, authentication, NTLM collection or session.
Its 13 owned scenarios passed validation: 5/5 ordinary and 2/2 separate robustness
tasks completed, six negative outcomes remained inconclusive and 26/26
unauthorized destinations were blocked. Local validation passed 11,898 portable
and 36 native tests; clean-source replay preserved all 45 accepted bundles.
All five [final hosted checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37678942749)
and the [post-merge checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37684453123)
passed.
The runtime is limited to the
exact reviewed Linux Ruby 3.3 x86-64 files; early write-half-close can limit server
compatibility. There is no new GUI workflow or real-network attachment.

The accepted C6 [SMB2 negotiation profile](smb2-negotiation-tools.md) adds
`smb2_negotiate_metadata_v1`, bringing accepted main to **31 profiles using the same
14 programs**. The repository-owned Ruby adapter sends one fixed 108-byte request
offering SMB 2.1 and 3.0.2 with client capabilities zero, closes its write side and
reads one response frame of at most 4,100 bytes. Supported negotiation metadata
permits an opaque security or error buffer of at most 256 bytes; bounded raw
evidence can retain rejected frames with larger buffers. Peer bytes remain
uninterpreted data. No SESSION_SETUP, authentication, NTLM challenge collection
workflow, credentials, login, share access or follow-up is available. Local
validation, source review and all five final/post-merge jobs passed; C6 is
accepted in PR #60 at `aa65bff7`. Catalog visibility does not establish
arbitrary server compatibility, signing enforcement or service identity.

The accepted C7 [SMTP STARTTLS profile](smtp-starttls-tools.md) adds one bounded
profile through existing OpenSSL, for **32 profiles using the same 14 programs**.
It sends fixed EHLO/STARTTLS, verifies the fixture CA/name and records clean TLS
closure without authentication, mail or application requests. Structured output
means verified TLS only; SMTP reply codes, advertisement and product identity
are not verified. Full portable, native/usefulness, enforcement and evidence
checks passed. C7 is accepted in PR #61 at `7c5e88ad`; all five final and
post-merge jobs passed.

The accepted C8 [LDAP STARTTLS profile](ldap-starttls-tools.md) adds one fixed
extended request and verified fixture TLS/clean close through existing OpenSSL,
for **33 profiles using the same 14 programs**. It permits no bind, search,
credentials, referral follow-up or application request. The native client leaves
response IDs/remaining LDAP fields unchecked and discards the raw LDAP reply;
only TLS facts are reported. Validation passed **13,683 portable** and **70 native
tests**, including 2/2 ordinary and 2/2 separate robustness completions, eight
inconclusive cases and 24/24 blocked destinations. Four clean-source trials and
63 accepted evidence replays also passed. C8 is accepted in PR #62 at `a582bd6c`;
all five final and post-merge jobs passed.

The accepted C9 [FTP explicit TLS profile](ftp-starttls-tools.md) adds one fixed
AUTH TLS command and verified fixture TLS/clean close through existing OpenSSL,
for **34 profiles using the same 14 programs**. It exposes no login, credentials,
listing, transfer or data connection. The native client discards unchecked AUTH
replies and retains only the final greeting; the bounded result reports TLS only.
Validation passed 14,231 portable tests and a 65-test native confirmation, with
2/2 ordinary and 3/3 robustness completions, 22/22 blocked destinations and 67
accepted-bundle replays. One initial legacy stall error did not reproduce;
its cause remains undetermined and is recorded in the verification report.
C9 is accepted in [PR #63](https://github.com/0xsl0th/recon-cockpit/pull/63) at `e06e1a4`; all five final and post-merge jobs passed.

The accepted C10 [DNS NSID profile](dns-nsid-tools.md) adds one fixed nonrecursive TCP query
requesting opaque server metadata through existing dig. Empty and absent replies
are distinct; identifiers remain unverified, and no returned text selects follow-up.
C10 brings accepted main to **35 secure profiles using 14 programs**. Validation passed
**14,814 portable / 62 native tests**, six useful clean-source trials and 72
unchanged accepted-bundle replays. PR #64 is merged at `dea8c7a`; all final and post-merge checks passed. Credentials
and paid calls stay deferred. The initial historical snapshot-test failure was
corrected without changing production code and remains recorded.

The accepted C11 [DNS AXFR profile](dns-axfr-tools.md) observes one fixed
synthetic zone transfer through existing dig. Completed transfer and explicit refusal
are useful outcomes; partial/malformed transfers remain inconclusive. Accepted main
has **36 profiles using 14 programs**. Validation passed **15,464 portable and 61
native tests**, 3/3 ordinary and 2/2 robustness trials, five clean-commit trials and
78 unchanged accepted-bundle replays. PR #65 merged at `82dd85a`; all five final
and post-merge jobs passed. Returned data cannot select follow-up.

The accepted C12 [HTTP OPTIONS profile](http-options-tools.md) adds one fixed
resource-specific request through existing curl, for **37 profiles using 14 programs**.
Typed status, distinct absent/empty Allow and authentication-scheme names remain
untrusted advertisements; no advertised method, redirect or login is executed.
Validation passed **16,138 portable and 40 native tests**, with 6/6 ordinary and
2/2 robustness completions, six inconclusive negatives, 28/28 blocked destinations,
zero unnecessary refusals and 83 unchanged accepted-bundle replays.
[PR #66](https://github.com/0xsl0th/recon-cockpit/pull/66) merged at `7faf974` after
all five final CI jobs passed; its [post-merge run](https://github.com/0xsl0th/recon-cockpit/actions/runs/37713341040)
also passed. C12 remains closed.

The accepted C13 [SNMP successor profile](snmp-next-tools.md) adds one fixed
TCP GETNEXT for the ifDescr column through snmpgetnext, for **38 profiles using
15 programs**. It distinguishes a reported description, empty description,
endOfMibView and a supported outside-subtree successor without walks, UDP,
credentials or returned-OID follow-up. **16,687 portable/43 native tests and
91 accepted-bundle replays passed**. [PR #67](https://github.com/0xsl0th/recon-cockpit/pull/67)
merged at `7cc6645` after independent review and all five final CI jobs passed.
C13 remains closed; all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37715717067) also passed.

The accepted C14 [SSH algorithm profile](ssh-algorithms-tools.md) adds one
bounded identification/KEXINIT exchange through the sealed Ruby runtime, for
**39 profiles using 15 programs**. Its finite directional advertisements do not
complete key exchange or authentication. **17,728 portable/44 native tests and
97 accepted-bundle replays passed**. [PR #68](https://github.com/0xsl0th/recon-cockpit/pull/68)
merged at `a6f11b7` after review and all five final CI jobs passed; all five
[post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37719116743)
also passed. C14 remains closed with its documented half-close/capture limits.

[C15 TLS certificate coverage](tls-certificate-tools.md) is accepted in
[PR #69](https://github.com/0xsl0th/recon-cockpit/pull/69), merged as `e4c9d64`
after independent review and all five final jobs passed. That slice reached
**40 secure profiles using 15 external programs**. Its fixed fixture-verified
OpenSSL handshake yields bounded DER fingerprint, validity and DNS/IP SAN metadata.
**18,396 portable/39 native tests and 103 accepted-bundle replays passed.**
Finite compatibility, CN fallback and trust/revocation limits remain documented.

The accepted [C16 Nuclei check](nuclei-tools.md) adds one pinned directory-listing
signature check through a separate static runtime with bounded private scratch.
The feasibility assessment was accepted in [PR #70](https://github.com/0xsl0th/recon-cockpit/pull/70)
at `2f7fb5a`; the operator then authorized implementation and owned execution.
[PR #71](https://github.com/0xsl0th/recon-cockpit/pull/71) brings accepted coverage
to **41 profiles using 16 programs**, with 18,958 portable and 23 Linux checks
passed plus 107 unchanged accepted-bundle replays. Fresh independent reviews
found no blockers; all five final CI jobs gate the merge.
Useful matched and unmatched results require complete independent owner bytes,
a supported native dump and recomputed signature agreement. This is no generic
vulnerability scan or CVE claim; credential/model/paid work remains deferred.

From the repository root, with the project installed:

```sh
python -m recon_cockpit.secure_agent --list-tools
python -m recon_cockpit.secure_agent --describe-tool ssh_host_keys_v1
python -m recon_cockpit.secure_agent --describe-tool kerbrute_userenum_v1
python -m recon_cockpit.secure_agent --describe-tool redis_server_info_v1
python -m recon_cockpit.secure_agent --describe-tool snmp_system_get_v1
python -m recon_cockpit.secure_agent --describe-tool postgresql_tls_handshake_v1
python -m recon_cockpit.secure_agent --describe-tool mysql_tls_handshake_v1
python -m recon_cockpit.secure_agent --describe-tool whatweb_http_fingerprint_v1
python -m recon_cockpit.secure_agent --describe-tool dig_dns_srv_v1
python -m recon_cockpit.secure_agent --describe-tool rdp_initial_negotiation_v1
python -m recon_cockpit.secure_agent --describe-tool smb2_negotiate_metadata_v1
python -m recon_cockpit.secure_agent --describe-tool smtp_starttls_handshake_v1
python -m recon_cockpit.secure_agent --describe-tool ldap_starttls_handshake_v1
python -m recon_cockpit.secure_agent --describe-tool ftp_starttls_handshake_v1
python -m recon_cockpit.secure_agent --describe-tool curl_http_options_v1
python -m recon_cockpit.secure_agent --describe-tool snmp_interface_next_v1
python -m recon_cockpit.secure_agent --describe-tool ssh_transport_algorithms_v1
python -m recon_cockpit.secure_agent --describe-tool openssl_peer_certificate_v1
```

Both operations return deterministic JSON. They work without Linux isolation,
installed tool binaries or a policy file. They do not inspect runtime availability,
read credentials, create audit/evidence or approvals, or launch a tool. The output
states `runtime_availability: not_checked`; an entry is not a readiness probe.
Unknown tool IDs and combinations with assessment, execution, policy, audit or
model options are rejected. Use one catalog operation at a time.

## What a description tells you

| Field | Meaning |
| --- | --- |
| `tool_id`, `implementation`, `external_program` | Exact capability identity and whether it uses a native adapter or an external program. |
| `adapter` | Registry descriptor, including capability/API/parser versions, effect, result contract and execution requirements. |
| `owned_scope`, `fixed_parameters` | Numeric owned endpoint and exact parameters for this example. The registry's broader parameter schema describes syntax and grants no additional scope. HTTP can have more than one fixed action. |
| `run.selector`, `case`, `policy`, `runbook` | Existing CLI selector, normal fixture case, shipped approval-required policy and detailed documentation. Paths are relative to the repository root. |
| `run.actions`, `action_count`, `tool_ids` | Complete planned normal sequence, including other capabilities used by the same selector. Later actions depend on predecessor evidence and fresh authority checks. |
| `run.session_limits` | Session allowances, distinct from each action's timeout/output cap and the number of planned actions. |
| `run.dry_run_argv` | An argument array for the existing CLI; it contains no execution switch and explicitly selects `--dry-run`. |
| `limitations` | What the result establishes and where the accepted profile stops. Follow the linked runbook for full invocation, prerequisite and evidence details. |

Descriptions derive action parameters and session limits from the existing pure
contracts. A reviewed mapping supplies the normal selector, executable family,
policy, runbook and semantic caveats. There is no plugin discovery or generic
run-any-tool entrypoint. A description cannot choose another binary, target,
dictionary, credential or execution profile.

## Use the existing owned recipe

Listing a recipe is inert. Running it is an ordinary secure CLI dry run: it needs
the documented Linux prerequisites and writes private audit/evidence. Replace
both `<NEW-AUDIT>` and `<NEW-ASSESSMENT>` path placeholders with unique names under
an existing private parent. Pass the returned array as arguments; do not paste
unquoted angle-bracket placeholders into a shell.

Every recipe retains all seven existing gates:

```text
--owned-lab --isolated-audit --isolated-approvals
--isolated-launch-admission --isolated-launcher
--require-launch-audit --require-launch-approval
```

Dry runs record proposals and decisions; they are not actual execution evidence.
They may stop before proposing later actions because no predecessor execution
result exists. The catalog's `action_count` describes the conditional normal
sequence, not a promise of that many proposals in a dry run.

The TCP and HTTP entries use the existing TCP → two-GET workflow; Nmap's TCP
entry uses Nmap → two GETs. The header entry uses Nmap → one header GET. Other
entries use existing single-tool selectors. The header recipe plans two actions
within its accepted three-step session allowance; the catalog does not silently
change that allowance.

Actual execution remains a separate invocation under the existing policy and
personal approval requirements. Retain all seven catalog gates, even where an
older linked runbook shows a simpler example, and choose fresh paths for the new
run. Reading the catalog provides no grant, reusable approval or permission for
an external target.

## Preserve result semantics

Kerbrute's two principal statuses remain `tool_report_only`, with
`authentication_verified: false`. A spoofed error string can look like an unknown
principal, so these reports do not verify existence or absence. The SMB share-list
profile's ambiguous empty/denied/malformed replies remain inconclusive. Nmap's unidentified result
means no match from the finite probes. Advertised ports, names, paths and schemes
never authorize follow-up actions.

Redis requires its complete selected server metadata; empty or denied replies
remain inconclusive. SNMP requires all three ordered typed responses, including
explicit `noSuchObject` where applicable. Those exception replies differ from
missing output and can complete the query without verifying device identity or
absence of a service. Hostile strings remain escaped, untrusted data. Neither
profile permits metadata to choose another target or action.

The database TLS profiles report `verified_tls_handshake_only` and
`authenticated_database_session: false`. The `service` field binds the selected
pre-authentication protocol; it does not identify an authenticated database product.
No readiness, server version, account access or SQL result is claimed. Refused,
untrusted, malformed and stalled handshakes stay inconclusive. MySQL greeting text
is ignored as metadata, and a fragmented greeting can fail closed with this native
client; neither behavior permits a plaintext fallback.

WhatWeb reports `untrusted_application_hints` from Title, HTTPServer,
X-Powered-By, MetaGenerator and JQuery. A completed HTTP 200 with no hints is
useful completion, not technology absence. Hostile strings remain escaped literal
metadata. Matches do not prove product identity, installed versions or vulnerabilities;
redirects, denied, incomplete and unsupported responses stay inconclusive.

DNS SRV returns at most four `untrusted_dns_service_metadata` rows with priority,
weight, port, target and TTL. A complete no-data reply, NXDOMAIN and a sole
zero-valued root target have separate response meanings; none establishes service
identity, availability or independently verified absence. One bounded additional
TXT record may be counted and discarded; its text stays in raw evidence. No
recursion, target resolution, endpoint follow-up or transfer is authorized.

RDP reports `untrusted_rdp_negotiation_metadata`: a protocol selected in response
to the fixed offer, a distinct legacy confirmation, or a known negotiation failure.
All three can complete a metadata task. No TLS handshake, authentication, service
identity or exhaustive protocol-support claim follows. Malformed, unoffered,
unknown-failure, truncated, oversized and stalled replies remain inconclusive.
The trailing-data robustness case reads only the first frame; it does not claim
to inspect or detect the trailing content. Returned fields cannot authorize
another operation.

SMB2 negotiation reports `untrusted_smb2_negotiation_metadata`: an offered dialect
selection with signing/capability fields, or one of three known refusal statuses.
Neither outcome verifies a security channel, identity or the cause of a refusal.
Capability bits depend on the fixed zero-capability client offer, so missing bits
do not establish missing server support. The parser releases only the length of
a supported opaque security buffer; its contents stay in private raw evidence.
Malformed, unsupported, unoffered, truncated, oversized and stalled responses
remain inconclusive. The first-frame capture does not inspect trailing data or
detect injection, and no returned field authorizes a second request.

HTTP OPTIONS reports `untrusted_http_options_metadata` with status, explicit
Allow presence, at most 16 case-sensitive method tokens and eight authentication
scheme names. A complete 401/405 can be useful metadata; it is not an unnecessary
refusal or proof of authenticated access. Realm, challenge and body text stay out
of the closed summary. Only supported complete retained HTTP/1.1 framing is
accepted; unseen trailing wire bytes cannot be checked. Advertisements establish
neither method execution nor a vulnerability and authorize no further request.

SNMP GETNEXT reports `untrusted_snmp_successor_metadata` for one fixed ifDescr
seed. A description may be empty; endOfMibView is bound to that seed, and the
supported outside-subtree result retains only its numeric OID. Descriptions and
indexes remain server reports, not verified interface identity, inventory or
absence. A successor must increase numerically; its OID never selects another
request. Only the documented finite client rendering and typed values are accepted.

SSH algorithm metadata retains the first identification/KEXINIT advertisement
only. Eight typed lists preserve direction, case and preference order; optional
banner comments stay raw evidence. The compact summary is capped at 3072 bytes,
with at most 32 names/1024 bytes per list and 64 bytes per name. The three fields
for key-exchange completion, authenticated session and verified identity remain
false. Unknown names and guessed-packet flags cannot authorize further work.
The owner hashes the request template; the actual random cookie is not retained.

The C15 certificate recipe reports one bounded leaf fingerprint, validity range and
DNS/IP SAN subset after native fixed-CA/name verification. Absent SAN is distinct
from an empty extension; subject text and unknown extension values remain raw.
The parser does not perform trust-path or revocation validation, and historical
replay does not reclassify validity dates against today's clock. Unsupported
certificate forms remain inconclusive. No certificate name grants scope or
triggers resolution, AIA/OCSP fetching or an application request.

The B0–B8 [coverage checklist](secure-tool-coverage.md) is closed under those
accepted limits. The original catalog was accepted in PR #46 at `0d5cbdc`;
its recipes retain their accepted behavior. The separately versioned
[Nmap service → ffuf → headers workflow](service-web-assessment.md) and
[configurable owned-lab slice](configurable-owned-lab.md) remain distinct from
accepted C15 coverage. Further composition and comparative benchmarking
remain later work. Model
credentials, paid calls and live-model evaluation stay deferred until much later.

C17 [Git HEAD marker coverage](nuclei-git-tools.md) is an authorized implementation
candidate with validation pending. It adds one finite synthetic check through
the same Nuclei runtime: accepted coverage remains 41 profiles/16 programs;
the candidate has 42/16. No repository download, credentials or live-model work
is included.

# Professional-v1 coverage contract

Current continuation (14 October 2026):
**T01–T06 meet G1–G6; the finite Stage 2 coverage tranche is closed.**
The accepted catalog contains **52 profiles across 17 programs, with no candidates**.
[T06 PR #86](https://github.com/0xsl0th/recon-cockpit/pull/86) merged as
`f0542a8df2bbe8051178f587859af82b2780f7ad` after review of
`28f1a18d2def230f3a337e50e9c365b4ce607e58`. The reviewed and merged trees match
`c475c0cb3648938fcbe0d66a3bb9a9168ed424d3`. Fresh validation passed 646 focused,
700 authority/runtime and 337 parser/evidence tests; independent reviews found
no blockers and all five [final PR checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/38595455084)
passed. All five [post-merge checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/38597857953)
also passed at `f0542a8`; preserve `.secure-agent/stage3-20261014/pr86-merge-review.json`.

The [accepted AAAA/PTR runbook](dns-address-tools.md) retains **83 frozen native
and 24,163 portable passes**, with all 747 recorded source files unchanged during
each run. All 11 ordinary tasks completed without unnecessary refusals, four
robustness tasks completed and 23 negatives remained inconclusive. Four
out-of-scope proposals were blocked; 57 reports passed 114 unchanged CLI/Python
inspection checks. Preserve `.secure-agent/dns-address-20261014/` and its original
source pins, failed-run history and evidence limitations. These exact disconnected
profiles do not establish general server compatibility or professional readiness.

T05 remains accepted at `8ca3887`, with its 51 native and 23,170 portable passes,
37 reports/74 inspection checks and five final/post-merge checks intact. Preserve
`.secure-agent/dns-address-20261014/pr85-merge-review.json` and the original
`.secure-agent/snmp-page-20261014/` receipts. No accepted milestone is reopened.

**S3.1, S3.2a and S3.2b are accepted in PRs #87/#88/#89.** PR #89
merged as `c068a9d` after fresh review and five passing final CI jobs (24,643
portable tests each). The [nginx diagnostic](stock-nginx-native.md) retains 60
native checks, 15 accepted-profile regressions, 16 useful completions, ten
correct negatives and 16 distinct destination denials. S3.2 is closed; this
adds no catalog profile or production HTTP support claim.

Accepted [S3.3a PR #90](https://github.com/0xsl0th/recon-cockpit/pull/90) prepared the fixed Apache runtime and
separate production HTTP contract. Preparation itself proves no native startup.
**S3.3b is accepted in [PR #91](https://github.com/0xsl0th/recon-cockpit/pull/91)
at `061c057`. S3.3 is closed.** Its [production evidence](stage3-http-production.md)
records **106 native passes at `1cfa59a`**: 52 corpus rows and 54 boundary cases,
32 useful completions with zero unnecessary refusals, 20 correct negatives and
32 distinct destination denials. All 52 bundles passed 104 unchanged inspections;
68 distinct accepted-profile native regressions and three separate Apache
extra-request repetitions passed. All 904 source pins stayed unchanged during
each native run. Full local portable validation at `d19eef3` passed
**25,312 tests** with 904 unchanged source pins; all five [hosted checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/38649179063)
passed at that revision. Original failed attempts remain recorded, including the
unconfirmed cause of the earlier Apache budget-test failure.

Fresh final review passed 605 focused tests; all five final CI jobs at
`77aeb7b` passed 25,314 tests each. The merged tree matches that reviewed head.
Stage 3 now has **ten increments, six accepted and four remaining**.
[S3.4a preparation](stock-ssh-feasibility.md) is accepted in PR #92 at `bfe6680`.
Current [S3.4b native SSH](stage3-ssh-compatibility.md) must separately prove the
fork/exec, transport and compatibility boundary. This split removes no required case. Accepted
coverage stays **52 profiles / 17 programs**; Stage 3 remains open and adds no
catalog entry merely for running a fixture server.

PRs #80/#81 (T02/T03), #82 (catalog/source review), #83/#84 (T04), #85/#86
(T05/T06) and proposal PR #31 remain closed. Proposal submission and its broader
refresh remain deferred to November. Model credentials, paid calls, live-model
evaluation, attached/external targets, deeper workflows and comparative benchmarking
remain deferred. The dated baseline and candidate wording below preserve historical
snapshots; this continuation supersedes their pre-merge status.

Historical pre-merge status: **9 October 2026, PR #79 merged at `5f4197f`**. The owner agreed
the [product roadmap](product-roadmap.md) and authorized continued coverage work.
**T01/C18 is accepted; T02–T06 remain open.** PR #78 accepted closed diagnostic
observations and networkless replay. Four separate [production TLS posture
profiles](tls-posture-tools.md) now integrate the secure authority/evidence path
as candidates for review. They are not yet accepted capabilities. Keep accepted
coverage at 43 profiles / 16 programs until T02 passes G6 review/checks and
authorized merge. PR #80 already validates its acceptance corpus.
The post-merge macOS cancellation failure and its correction are recorded in the
checkpoint; original diagnostic receipts remain unchanged.

This is the finite **Stage 2 tool-coverage gate**, not a declaration that the
professional product or its final release contract is complete. Existing exact
profiles remain accepted. Real-service compatibility, configurable engagement
targets, credentials, durable sessions, workflows, reports, GUI expansion and
release acceptance retain the separate roadmap gates described below.

The supported direction is operator-assisted internal-network assessment with
web services on the supported Linux environment. The completed tranche covers
unauthenticated observations and bounded, non-destructive checks in disconnected
owned fixtures. It does not authorize attached networks, real credentials,
intrusive effects, live models or paid calls.

## Accepted foundation: exact capabilities, not general engagement coverage

These rows account for all **52 accepted profiles across 17 external programs**.
The IDs are the exact entries in the [secure catalog](secure-tool-catalog.md) and
[registry](../recon_cockpit/secure_agent/tool_adapters.py). Each row retains its
accepted G1–G6 evidence and limitations; it does not need to be reopened to start
the remaining tasks. Its broader professional-use gap remains visible in the last
column.

| Operator task | Accepted secure profiles | Verified scope and remaining professional-use gap |
| --- | --- | --- |
| A01. Observe reachability and service hints | `tcp_connect`, `nmap_tcp_connect_v1`, `nmap_service_identify_v1`, `configurable_nmap_service_v1` | Bounded TCP and finite HTTP/SSH service probes; configurable addresses still identify disconnected owned fixtures. Multi-host/port inventories, scan budgets and general service compatibility belong to Stage 3. |
| A02. Retrieve web responses, inspect headers, discover paths and check selected exposure signatures | `http_probe`, `http_headers_v1`, `configurable_http_headers_v1`, `curl_https_get_v1`, `ffuf_content_discovery_v1`, `ffuf_web_hierarchy_v1`, `whatweb_http_fingerprint_v1`, `curl_http_options_v1`, `nuclei_directory_listing_v1`, `nuclei_git_head_v1` | Fixed responses, eight flat discovery paths and T04's separate twelve-path hierarchy corpus, five passive WhatWeb plugins and two finite Nuclei signatures. Header gaps and advertisements are observations; signatures do not prove exploitability. Arbitrary URLs, web/API authentication, general crawling and vulnerability scanning are not accepted. |
| A03. Collect selected DNS metadata | `dig_dns_query_v1`, `dig_dns_srv_v1`, `dig_dns_nsid_v1`, `dig_dns_axfr_v1`, `dig_dns_mx_v1`, `dig_dns_aaaa_v1`, `dig_dns_ptr_v1` | Fixed nonrecursive TCP A/SRV/NSID/AXFR/MX/AAAA/PTR operations with finite responses. T01/C18 MX and T06 address/reverse metadata are accepted. Returned names and addresses grant no follow-up authority; resolver selection and actual engagement naming need Stage 3. |
| A04. Observe verified TLS, certificate metadata and finite version posture | `openssl_tls_handshake_v1`, `openssl_peer_certificate_v1`, `postgresql_tls_handshake_v1`, `mysql_tls_handshake_v1`, `smtp_starttls_handshake_v1`, `ldap_starttls_handshake_v1`, `ftp_starttls_handshake_v1`, `openssl_tls10_posture_v1`, `openssl_tls11_posture_v1`, `openssl_tls12_posture_v1`, `openssl_tls13_posture_v1` | Fixture CA/name verification, bounded handshake/certificate facts and T02's separately authorized fixed-version observations or explicit rejections. These are not authenticated application sessions or unrestricted protocol/cipher assessments; real trust configuration and service compatibility stay in Stage 3. |
| A05. Collect SSH host keys and assess transport advertisements | `ssh_host_keys_v1`, `configurable_ssh_host_keys_v1`, `ssh_transport_algorithms_v1`, `ssh_transport_policy_v1` | One fixed host-key mode, bounded KEXINIT metadata and T03's pinned local policy assessment in both directions. None verifies host identity or authenticates; unknown algorithms remain inconclusive. General server compatibility remains open. |
| A06. Read anonymous LDAP RootDSE | `ldap_rootdse_v1` | Fixed base query and attributes; no arbitrary search base, user/group enumeration, referrals or bind credentials. Real directory compatibility and selected authenticated queries need Stages 3/4. |
| A07. Observe SMB shares, SMB negotiation and RDP negotiation | `smb_share_list_v1`, `smb2_negotiate_metadata_v1`, `rdp_initial_negotiation_v1` | Finite anonymous metadata/negotiation only. Ambiguous SMB listing failures remain inconclusive; advertised security modes do not prove enforcement. Authentication, share access and remote sessions remain separate work. |
| A08. Record finite Kerberos tool reports | `kerbrute_userenum_v1` | Two synthetic names against an error-only owned KDC. Existence/absence is unverified and error-text spoofing is documented. General KDC use and upstream ticket-handling behavior are outside this accepted profile and require a separate boundary review. |
| A09. Observe RPC registrations and NFS exports | `rpcinfo_dump_v1`, `showmount_exports_v1` | Fixed TCP metadata requests; no discovered-port follow-up, mounting or file access. Real service routing and compatibility need Stage 3. |
| A10. Observe FTP listing and SMTP capabilities | `curl_ftp_list_v1`, `curl_smtp_capabilities_v1` | Synthetic anonymous names and fixed EHLO/QUIT only. Passive connections are predeclared; no transfers, mail, recipient probes or authentication. Real-server compatibility stays open. |
| A11. Observe Docker and WinRM endpoints | `curl_docker_ping_v1`, `curl_docker_version_v1`, `curl_winrm_metadata_v1` | Fixed read-only paths and bounded metadata/authentication-scheme advertisements. No container operation, login, SOAP operation or shell session. |
| A12. Observe Redis and SNMP metadata | `redis_server_info_v1`, `snmp_system_get_v1`, `snmp_interface_next_v1`, `snmp_interface_page_v1` | One Redis INFO selection and fixed SNMP GET/GETNEXT/GETBULK over TCP with public synthetic fixture data. Accepted T05 adds one bounded interface-description page; no keys/writes, walks, continuation, real communities or authenticated device identity. |

Interactive suggestions are a separate inventory. They use the host runner and
do not satisfy secure execution gates. Existing suggestions cover Nmap, curl,
ffuf, feroxbuster, ssh-keyscan, ssh, NetExec, smbclient, ldapsearch and kerbrute.
Of those, **feroxbuster has an applicable precedent for this tranche but no secure
profile**. SSH login and broader NetExec modes require deferred credential/session
and effect boundaries. Reuse their UX knowledge where relevant, never their host
execution path as a fallback. See the [original inventory](secure-tool-coverage.md#what-the-inventory-measures)
and [inert suggestions](../recon_cockpit/suggestions.py).

## Six required tasks, in priority order

The task is the requirement; a candidate engine is not an accepted integration
or a mandatory brand choice. A short feasibility review must pin the chosen
version, executable/data closure, exact wire behavior, finite invocation, parser,
limits and useful lab corpus before a new engine is implemented. Reuse an accepted
engine when it fulfills the same task more cleanly. Record an engine substitution
without removing or weakening the required operator outcome.

Numeric bounds below are initial contract targets for review, not supported
runtime settings or permission to raise existing limits. If a candidate cannot
complete the task within its reviewed boundary, keep the row blocked while
reviewing a concrete substitute or revised contract. A descriptor or feasibility
report alone cannot complete any row.

| ID / priority | Required operator outcome and present gap | Candidate implementation and bounded task | Required useful cases and honest negative results | Status |
| --- | --- | --- | --- | --- |
| **T01 / C18 — accepted** | Observe a domain's advertised mail routing; C18 closes the former fixed-MX gap. | Reuse `dig`; one fixed nonrecursive TCP MX question, at most four typed preference/exchange rows. No mail delivery, additional name resolution or returned-server connection. | Ordinary MX records, null-MX, NODATA and NXDOMAIN all complete. Distinguish explicit no-mail advertisement from missing data. Reject malformed/null-MX mixtures and incomplete or excess-record responses; hostile names remain data. | **G1–G6 closed in [PR #74](https://github.com/0xsl0th/recon-cockpit/pull/74).** |
| **T02 — accepted** | Determine acceptance/rejection of TLS 1.0, 1.1, 1.2 and 1.3; the accepted TLS profile proves only its selected handshake. | Stock **sslscan** rejected because it discards received rejection evidence. Use four separately versioned **OpenSSL** probes with the reviewed mediator: one numeric owned endpoint and one ClientHello delivered to the peer per action, exact version, independent grants and bounded connection ledger. Four independent actions preserve the original at-most-eight-connection whole-task target without an implicit retry allowance. No client credential, application request, retry escalation or peer-directed fetch; accepted OpenSSL profiles stay unchanged. | A modern-only fixture and a deliberately legacy-enabled fixture produce correct observations for all four versions. Explicit protocol rejection is useful only with retained client-received evidence, independently corroborated by owner records. Reset, timeout or unsupported-client behavior is inconclusive. Unknown or incomplete results cannot be reported as disabled versions. | **G1–G6 closed in [PR #80](https://github.com/0xsl0th/recon-cockpit/pull/80) at `f2e7b785`.** The [acceptance corpus](tls-posture-acceptance.md) passed 65 native and 21,593 portable tests, independent review and all five final checks. Four accepted profiles reuse OpenSSL. |
| **T03 — accepted** | Assess SSH transport advertisements against an explicit pinned local policy; collection alone supplies no assessment. | Pinned [ssh-audit source review](ssh-policy-feasibility.md) rejects its extra host-key/KEX probes. A separate `ssh_transport_policy_v1` reuses byte-identical C14 collection and a networkless immutable policy evaluator. One numeric owned endpoint, one 184-byte request/write-half-close, one bounded packet; no login, completed key exchange, rate/stress test, session or downloaded policy. | Six ordinary and two robustness tasks complete usefully, including deliberate deviations in either direction. Two complete unknown cases and nine malformed/pressure cases stay inconclusive. Policy judgments do not verify exploitability, identity, negotiated strength or general compliance. | **G1–G6 closed in [PR #81](https://github.com/0xsl0th/recon-cockpit/pull/81) at `b90a365e`.** 52 native and 21,898 portable passes, independent review and all five final checks; no program added. See [runbook](ssh-policy-tools.md). |
| **T04** | Discover a controlled one-level web directory hierarchy beyond the flat eight-path ffuf corpus. | The [source review](web-hierarchy-feasibility.md) selected a separate finite **ffuf** profile after stock feroxbuster calibration conflicted with the boundary. Three predeclared prefixes, each with two resource and two compiled control names: useful completion needs twelve unique serial GETs and one active request. Native error retries may occur; the owner retains up to sixteen attempts/connections and duplicate or partial captures stay inconclusive. No recursion, arbitrary link extraction, redirects, credentials, uploads or response-directed follow-up; preserve the original ffuf profile. | Known nested resources and an empty hierarchy both complete; every planned path/request is accounted for. Wildcard responses do not invent resources. Redirects, path traversal, hostile links, unexpected paths and partial scans cannot expand scope or claim complete discovery. | **Accepted; G1–G6 closed in [PR #84](https://github.com/0xsl0th/recon-cockpit/pull/84) at `435a271`.** The [secure hierarchy profile](web-hierarchy-tools.md) retains 26 native and 22,577 portable passes; review and all five final/post-merge checks passed. |
| **T05** | Obtain one bounded page of SNMP interface descriptions; C13 returns a single successor, not a page. | The accepted `snmp_interface_page_v1` profile uses **snmpbulkget**, reusing Net-SNMP confinement and finite fixture patterns. One TCP GETBULK, one fixed ifDescr seed, non-repeaters zero and maximum repetitions four; public synthetic community only. No paging continuation, walks, SET, UDP or real credentials. | A populated page, empty descriptions, endOfMibView and a supported outside-column boundary have explicit results. Require typed ordered rows and either four normal bindings or an explicit terminal boundary within four bindings. Excess, malformed or short nonterminal output stays inconclusive; shortened replies can be valid SNMP but are unsupported here. A full page means capped observation, not complete interface inventory. | **[Accepted](snmp-page-tools.md), G1–G6 closed in PR #85 at `8ca3887`.** 51 native and 23,170 portable passes, independent review, 357 fresh focused passes and all five final/post-merge checks. |
| **T06** | Observe selected IPv6-address and reverse-name metadata alongside accepted A records. | Reuse `dig` in separate fixed nonrecursive TCP AAAA and PTR profiles, one question and at most four typed answers per action. Returned IPv6 addresses are data, not IPv6 network authorization. No reverse-to-forward lookup, recursion, alias chasing or returned-host follow-up. | Positive records, NODATA and NXDOMAIN complete for both questions. Validate the exact question, record type, name and complete bounded response; malformed names, unsupported alias chains and excess/partial records remain inconclusive. | **[Accepted profiles](dns-address-tools.md); G1–G6 closed in [PR #86](https://github.com/0xsl0th/recon-cockpit/pull/86) at `f0542a8`.** 83 native passes: 11 ordinary completions with zero unnecessary refusals, four robustness completions and 23 inconclusive negatives. Four out-of-scope proposals blocked; 57 reports/114 inspection checks unchanged. 24,163 portable passes, fresh independent review and all five final checks passed. |

T01–T06 are accepted and stay closed. PR #86 closes the final required task in
this finite tranche: separate AAAA/PTR observations through existing dig
confinement. The accepted [S3.1 contract](stage3-compatibility-routing.md) defines
finite actual-service compatibility and controlled target routing; S3.2a pins
source/runtime preparation before S3.2b's authorized disconnected diagnostic. This is new compatibility work,
not a new claim for the accepted synthetic profiles. Network attachment remains
separately authorized.

T02's accepted version posture adds a distinct outcome beyond one certificate
or handshake. Its [source feasibility](tls-posture-feasibility.md)
found that stock sslscan cannot distinguish received rejection from other failed
probes. Owner-sent bytes cannot replace missing client evidence. The OpenSSL
diagnostic retains client-received evidence for all four versions. Its initial
HRR trial failed prevention, 0/1; that historical result remains intact. New
mediation preserves useful observations while preventing the tested second
ClientHello from reaching the peer, 1/1; PR #77 accepted that diagnostic boundary.
PR #78 accepted [observation/replay](tls-posture-observations.md), keeping
process failure distinct from useful rejection. The current [production slice](tls-posture-tools.md)
registers four accepted profiles with separate action approvals and permits,
case-bound owner evidence and both assessment inspectors. PR #80 closed G1–G6
with the hostile-usefulness, ambiguity/pressure and regression corpus: 65 native
and 21,593 portable passes, independent review, required checks and authorized
merge. The mediator checks plaintext
framing and encrypted record shapes; it does not decrypt application traffic. The
already-installed sslscan remains outside the secure catalog. Do not substitute
another HTTP signature solely because its existing adapter is convenient.

Accepted T05 registers snmpbulkget as a seventeenth program. The two accepted
T06 profiles reuse dig and add no external program. T02 reuses OpenSSL, T03 the repository-owned SSH
collector, and accepted T04 reuses ffuf. None of those three added a program. The
historical **4–6-program assumption is not a quota, gate or reason to add
overlapping tools**. The six outcomes are unchanged. Registered and accepted counts remain distinct until actual secure execution
and G1–G6 justify acceptance; new modes of `dig` or `openssl` add profiles,
not programs. The historical 8–12-PR coverage allowance was an estimate, not
a completion criterion; all six required outcomes are now accepted. Use the
product roadmap's separate Stage 3 estimate for subsequent work.

T02's four OpenSSL profiles, T03 SSH policy, T04 hierarchy and T05's bounded
SNMP page are accepted. T05 retains 51 native and 23,170 portable passes;
PR #85 closed its G6. T06 retains 83 native and 24,163 portable passes;
PR #86 closed its G6 after review and all five final checks. Primary
documentation establishes features, not confinement or compatibility:

- The [pinned sslscan source review](tls-posture-feasibility.md#why-stock-sslscan-is-unsuitable)
  explains why its version-check output is unsuitable despite supporting version
  selection and XML. The [OpenSSL mediation runbook](tls-posture-mediation.md)
  records native usefulness and the narrow retry-enforcement result; the later
  [acceptance corpus](tls-posture-acceptance.md) closes T02's product gates.
- The [pinned ssh-audit source review](ssh-policy-feasibility.md) found that
  `--skip-rate-test` still permits other probes before policy evaluation. T03
  therefore uses the accepted bounded collector and a local policy snapshot.
- The [pinned feroxbuster source review](web-hierarchy-feasibility.md) found
  six generated concurrent wildcard GETs in stock feroxbuster calibration. The
  selected finite ffuf profile has [native diagnostic evidence](web-hierarchy-native.md):
  eight native and 22,113 portable tests passed. Its separate [production
  profile](web-hierarchy-tools.md) passed 26 native and 22,577 portable tests;
  review and PR #84 closed G1–G6. Diagnostic success alone did not establish
  product acceptance.
- [Net-SNMP's snmpbulkget manual](https://www.net-snmp.org/docs/man/snmpbulkget.html)
  defines the non-repeaters and maximum-repetitions fields needed for a single
  finite response. The [accepted T05 profile](snmp-page-tools.md) passed 51 frozen
  native tests, including actual owned execution, and 23,170 portable tests.
  PR #85 closed G6 after independent review and required checks.

## Completion and measurement

Each T01–T06 row must independently satisfy the existing
[G1–G6 gates](secure-tool-coverage.md#completion-gates-for-every-required-capability).
Before implementation, its runbook must name the exact ordinary, supported absent,
hostile, malformed, pressure and cancellation cases, with expected outcomes and
request ceilings. Test counts are not substitutes for those task denominators.

For every row, require:

1. **Useful execution:** all predeclared ordinary and supported absent tasks
   complete through the real secure executable in the disconnected owned lab;
   zero unnecessary refusals in that finite corpus. Unsupported or malformed
   responses remain explicitly inconclusive. Keep hostile-case completion in a
   separate denominator. Blocking every task fails the gate.
2. **Correct bounded observations:** every accepted result agrees with independently
   reparsed raw tool bytes, the finite result contract and available owner protocol
   evidence. State retained-evidence limits explicitly; client-rendered DNS text
   is not an independently retained owner-wire transcript. No unsupported fact
   or finding is asserted. A tool-reported rule judgment remains labelled as such.
3. **Enforcement:** all predeclared unauthorized actions/destinations are blocked,
   with zero unauthorized executions. Test approval/permit consumption, private
   inputs, resource/request limits, cancellation and closure. A negative fixture
   counts only after the expected real request progress; startup refusal does not
   stand in for protocol handling.
4. **Evidence:** all new bundles replay identically through both inspectors;
   tamper tests fail, accepted predecessor bundles and source pins remain intact,
   and no replay restores authority. Private raw data remains outside Git.
5. **Operational measurements:** record actual requests/connections, wall-clock
   duration per case, caps reached, stop reason and cleanup. Provider calls and
   actual cost remain zero. Report descriptive latency without claiming baseline
   overhead or comparative performance during this coverage tranche.
6. **Review:** exact implementation/source pins, relevant portable/native checks,
   independent review, required CI and an authorized merge. Review-pending,
   blocked, skipped or unexecuted capabilities remain incomplete.

Stage 2 is now closed: **all six tasks are accepted**, their required corpus and
G1–G6 results passed, no required row remains blocked or review-pending, and the
baseline profiles retain their accepted contracts. Required outcomes cannot be silently
deleted, weakened or moved to optional work to claim completion. Any scope change
must be explicit in the roadmap and brought to the owner. A successful gate
review names the next Stage 3 work; it does not automatically authorize deeper
composition, attached networks or comparative benchmarking.

## Product gates that this tranche does not close

| Later roadmap gate | Required work that remains visible |
| --- | --- |
| Stage 3 — realistic services and target handling | Accepted [S3.1 contract](stage3-compatibility-routing.md); accepted S3.2a/S3.2b nginx preparation and native diagnostic; S3.3a Apache preparation/production contract, then S3.3b production HTTP/native compatibility. A finite supported host/port/service matrix; representative actual services and fragmentation/denial behavior; configurable target/SNI/name bindings; exclusions; global rate/network budgets; explicit redirect/referral/DNS decisions; out-of-scope traffic witnesses. Owned synthetic fixtures alone cannot satisfy this gate. Network attachment requires separate authorization. |
| Stage 4 — engagement and session custody | Rules of engagement, persistent limits, expiry/revocation, secret custody and a finite selected authenticated-operation contract. Develop with synthetic credentials; real credentials and intrusive effects remain separately authorized. No existing profile grants these operations. |
| Stage 5 — workflows, findings, reports and retests | Evidence-linked multi-asset coordination, reviewed findings/severity, deduplication, remediation, client deliverables and retest history. Deeper composition and comparative benchmarks remain deferred during Stage 3. |
| Stages 6/7 — GUI and release | Expose accepted operations through the existing authority services, engagement/report usability, installation/upgrade/recovery, supported-platform and operator acceptance. The current GUI's completed local milestone remains closed; broader professional release does not follow from profile counts. |
| Broader product | Remaining distinct programs toward roughly 40, wider authenticated/intrusive/post-access work and later bounded live-model evaluation. The broader ambition is preserved; credentials, paid calls and live evaluation remain much later. |

Full cipher inventories, arbitrary web/API testing, extra DNS record families,
general UDP/device discovery, broader dictionaries, NetExec modes, login sessions
and general vulnerability-template sets are not hidden additions to these six
tasks. They remain explicit later scope to prioritize under the wider product
roadmap; no claim of full professional pentest coverage is made here.

Offline R5, accepted local R6, B0–B8, C1–C18 and the initial GUI stay closed.
Competition proposal documents, private PDFs, email draft and the saved GUI mocks
remain separate and unchanged. The owner deferred the proposal refresh until
November 2026, before the 15 November deadline; submission needs its separate
decision. Model credentials, external target access, paid calls, publication and
submission are not authorized by this coverage contract.

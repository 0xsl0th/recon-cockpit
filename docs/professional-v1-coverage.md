# Professional-v1 coverage contract

Current continuation (9 October 2026): PR #79 is merged at `5f4197f`.
[T02 acceptance PR #80](https://github.com/0xsl0th/recon-cockpit/pull/80) and
[T03 SSH policy PR #81](https://github.com/0xsl0th/recon-cockpit/pull/81) are separate
review candidates; review and merge #80 first. T02 has 65 native passes and full
historical replay. T03 has 52 native passes, including 27 TLS/SSH regressions.
Accepted coverage remains **43 profiles / 16 programs**, with **five candidates**
(four TLS, one SSH policy). G6 remains open for those tasks until their authorized
merges. T01/C18 and earlier milestones stay closed. T04 web hierarchy is next
after these reviews; credentials, paid/live models, deeper workflows and
comparative benchmarks remain deferred.


Status: **9 October 2026, PR #79 merged at `5f4197f`**. The owner agreed
the [product roadmap](product-roadmap.md) and authorized continued coverage work.
**T01/C18 is accepted; T02–T06 remain open.** PR #78 accepted closed diagnostic
observations and networkless replay. Four separate [production TLS posture
profiles](tls-posture-tools.md) now integrate the secure authority/evidence path
as candidates for review. They are not yet accepted capabilities. Keep accepted
coverage at 43 profiles / 16 programs until the remaining T02 corpus and G1–G6 pass.
The post-merge macOS cancellation failure and its correction are recorded in the
checkpoint; original diagnostic receipts remain unchanged.

This is the finite **Stage 2 tool-coverage gate**, not a declaration that the
professional product or its final release contract is complete. Existing exact
profiles remain accepted. Real-service compatibility, configurable engagement
targets, credentials, durable sessions, workflows, reports, GUI expansion and
release acceptance retain the separate roadmap gates described below.

The supported direction is operator-assisted internal-network assessment with
web services on the supported Linux environment. The current tranche develops
unauthenticated observations and bounded, non-destructive checks in disconnected
owned fixtures. It does not authorize attached networks, real credentials,
intrusive effects, live models or paid calls.

## Accepted foundation: exact capabilities, not general engagement coverage

These rows account for all **43 accepted profiles across 16 external programs**.
The IDs are the exact entries in the [secure catalog](secure-tool-catalog.md) and
[registry](../recon_cockpit/secure_agent/tool_adapters.py). Each row retains its
accepted G1–G6 evidence and limitations; it does not need to be reopened to start
the remaining tasks. Its broader professional-use gap remains visible in the last
column.

| Operator task | Accepted secure profiles | Verified scope and remaining professional-use gap |
| --- | --- | --- |
| A01. Observe reachability and service hints | `tcp_connect`, `nmap_tcp_connect_v1`, `nmap_service_identify_v1`, `configurable_nmap_service_v1` | Bounded TCP and finite HTTP/SSH service probes; configurable addresses still identify disconnected owned fixtures. Multi-host/port inventories, scan budgets and general service compatibility belong to Stage 3. |
| A02. Retrieve web responses, inspect headers, discover paths and check selected exposure signatures | `http_probe`, `http_headers_v1`, `configurable_http_headers_v1`, `curl_https_get_v1`, `ffuf_content_discovery_v1`, `whatweb_http_fingerprint_v1`, `curl_http_options_v1`, `nuclei_directory_listing_v1`, `nuclei_git_head_v1` | Fixed responses, eight compiled discovery paths, five passive WhatWeb plugins and two finite Nuclei signatures. Header gaps and advertisements are observations; signatures do not prove exploitability. Controlled hierarchy discovery is T04; arbitrary URLs, web/API authentication, general crawling and vulnerability scanning are not accepted. |
| A03. Collect selected DNS metadata | `dig_dns_query_v1`, `dig_dns_srv_v1`, `dig_dns_nsid_v1`, `dig_dns_axfr_v1`, `dig_dns_mx_v1` | Fixed nonrecursive TCP A/SRV/NSID/AXFR/MX operations with finite responses. T01/C18 MX is accepted; address/reverse metadata remains T06. Returned names and addresses grant no follow-up authority; resolver selection and actual engagement naming need Stage 3. |
| A04. Observe verified TLS and certificate metadata | `openssl_tls_handshake_v1`, `openssl_peer_certificate_v1`, `postgresql_tls_handshake_v1`, `mysql_tls_handshake_v1`, `smtp_starttls_handshake_v1`, `ldap_starttls_handshake_v1`, `ftp_starttls_handshake_v1` | Fixture CA/name verification and bounded handshake/certificate facts. These are not authenticated application sessions or full protocol/cipher assessments. T02 adds a finite version-posture task; real trust configuration and service compatibility stay in Stage 3. |
| A05. Collect SSH host keys and transport advertisements | `ssh_host_keys_v1`, `configurable_ssh_host_keys_v1`, `ssh_transport_algorithms_v1` | One fixed host-key mode and bounded KEXINIT metadata; neither verifies host identity nor authenticates. T03 adds an explicit pinned policy assessment. General server compatibility remains open. |
| A06. Read anonymous LDAP RootDSE | `ldap_rootdse_v1` | Fixed base query and attributes; no arbitrary search base, user/group enumeration, referrals or bind credentials. Real directory compatibility and selected authenticated queries need Stages 3/4. |
| A07. Observe SMB shares, SMB negotiation and RDP negotiation | `smb_share_list_v1`, `smb2_negotiate_metadata_v1`, `rdp_initial_negotiation_v1` | Finite anonymous metadata/negotiation only. Ambiguous SMB listing failures remain inconclusive; advertised security modes do not prove enforcement. Authentication, share access and remote sessions remain separate work. |
| A08. Record finite Kerberos tool reports | `kerbrute_userenum_v1` | Two synthetic names against an error-only owned KDC. Existence/absence is unverified and error-text spoofing is documented. General KDC use and upstream ticket-handling behavior are outside this accepted profile and require a separate boundary review. |
| A09. Observe RPC registrations and NFS exports | `rpcinfo_dump_v1`, `showmount_exports_v1` | Fixed TCP metadata requests; no discovered-port follow-up, mounting or file access. Real service routing and compatibility need Stage 3. |
| A10. Observe FTP listing and SMTP capabilities | `curl_ftp_list_v1`, `curl_smtp_capabilities_v1` | Synthetic anonymous names and fixed EHLO/QUIT only. Passive connections are predeclared; no transfers, mail, recipient probes or authentication. Real-server compatibility stays open. |
| A11. Observe Docker and WinRM endpoints | `curl_docker_ping_v1`, `curl_docker_version_v1`, `curl_winrm_metadata_v1` | Fixed read-only paths and bounded metadata/authentication-scheme advertisements. No container operation, login, SOAP operation or shell session. |
| A12. Observe Redis and SNMP metadata | `redis_server_info_v1`, `snmp_system_get_v1`, `snmp_interface_next_v1` | One Redis INFO selection and fixed SNMP GET/GETNEXT over TCP with public synthetic fixture data. T05 adds one bounded interface-description page. No keys/writes, walks, real communities or authenticated device identity. |

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
| **T02 — mediated usefulness and retry prevention proved; product gates open** | Determine acceptance/rejection of TLS 1.0, 1.1, 1.2 and 1.3; the accepted TLS profile proves only its selected handshake. | Stock **sslscan** rejected because it discards received rejection evidence. Use four separately versioned **OpenSSL** probes with the reviewed mediator: one numeric owned endpoint and one ClientHello delivered to the peer per action, exact version, independent grants and bounded connection ledger. Four independent actions preserve the original at-most-eight-connection whole-task target without an implicit retry allowance. No client credential, application request, retry escalation or peer-directed fetch; accepted OpenSSL profiles stay unchanged. | A modern-only fixture and a deliberately legacy-enabled fixture produce correct observations for all four versions. Explicit protocol rejection is useful only with retained client-received evidence, independently corroborated by owner records. Reset, timeout or unsupported-client behavior is inconclusive. Unknown or incomplete results cannot be reported as disabled versions. | **Current: integration merged in PR #79; [acceptance corpus](tls-posture-acceptance.md) under review.** Separate version actions, approvals/permits and case-bound owner evidence are implemented. G6 remains open; accepted count unchanged. |
| **T03 — candidate review pending** | Assess SSH transport advertisements against an explicit pinned local policy; collection alone supplies no assessment. | Pinned [ssh-audit source review](ssh-policy-feasibility.md) rejects its extra host-key/KEX probes. A separate `ssh_transport_policy_v1` reuses byte-identical C14 collection and a networkless immutable policy evaluator. One numeric owned endpoint, one 184-byte request/write-half-close, one bounded packet; no login, completed key exchange, rate/stress test, session or downloaded policy. | Six ordinary and two robustness tasks complete usefully, including deliberate deviations in either direction. Two complete unknown cases and nine malformed/pressure cases stay inconclusive. Policy judgments do not verify exploitability, identity, negotiated strength or general compliance. | **[PR #81](https://github.com/0xsl0th/recon-cockpit/pull/81): 52 native passes; review after T02.** G6 remains open and no program is added. See [runbook](ssh-policy-tools.md). |
| **T04** | Discover a controlled one-level web directory hierarchy; accepted ffuf covers only its flat eight-path corpus. | Assess **feroxbuster**, reusing its interactive precedent but creating a separate secure profile. Use compiled words, predeclared same-origin prefixes and a finite path universe, depth at most one below the starting path, one active request and an initial total target of at most 24 GETs including calibration. No arbitrary link extraction, off-origin redirects, credentials, uploads or unbounded recursion. | Known nested resources and an empty hierarchy both complete; every planned path/request is accounted for. Wildcard responses must not invent resources. Redirects, path traversal, hostile links, unexpected paths and partial scans cannot expand scope or claim complete discovery. | **Required; no secure profile yet.** |
| **T05** | Obtain one bounded page of SNMP interface descriptions; C13 returns a single successor, not a page. | Assess **snmpbulkget**, reusing the Net-SNMP runtime/fixture patterns. One TCP GETBULK, one fixed ifDescr seed, non-repeaters zero and maximum repetitions four; public synthetic community only. No paging continuation, walks, SET, UDP or real credentials. | A populated page, empty descriptions, endOfMibView and a supported outside-column boundary all have explicit results. Require ordered typed OIDs and a complete response; excess, malformed or partial rows stay inconclusive. A full page means capped observation, not a complete interface inventory. | **Required; no secure profile yet.** |
| **T06** | Observe selected IPv6-address and reverse-name metadata alongside accepted A records. | Reuse `dig` in separate fixed nonrecursive TCP AAAA and PTR profiles, one question and at most four typed answers per action. Returned IPv6 addresses are data, not IPv6 network authorization. No reverse-to-forward lookup, recursion, alias chasing or returned-host follow-up. | Positive records, NODATA and NXDOMAIN complete for both questions. Validate the exact question, record type, name and complete bounded response; malformed names, unsupported alias chains and excess/partial records remain inconclusive. | **Required; no secure profiles yet.** |

T02 remains the next gap because version posture adds a distinct outcome beyond
one certificate or handshake. [Source feasibility](tls-posture-feasibility.md)
found that stock sslscan cannot distinguish received rejection from other failed
probes. Owner-sent bytes cannot replace missing client evidence. The OpenSSL
diagnostic retains client-received evidence for all four versions. Its initial
HRR trial failed prevention, 0/1; that historical result remains intact. New
mediation preserves useful observations while preventing the tested second
ClientHello from reaching the peer, 1/1; PR #77 accepted that diagnostic boundary.
PR #78 accepted [observation/replay](tls-posture-observations.md), keeping
process failure distinct from useful rejection. The current [production slice](tls-posture-tools.md)
registers four candidate profiles with separate action approvals and permits,
case-bound owner evidence and both assessment inspectors. Complete the remaining
hostile-usefulness, ambiguity/pressure and regression corpus before G1–G6 acceptance. The mediator checks plaintext
framing and encrypted record shapes; it does not decrypt application traffic. The
already-installed sslscan remains outside the secure catalog. Do not substitute
another HTTP signature solely because its existing adapter is convenient.

Two additional programs are plausible if feroxbuster and snmpbulkget prove
suitable. T02 reuses OpenSSL; T03 reuses the accepted repository-owned SSH
collector after the pinned ssh-audit source review. Neither adds a program. The
historical **4–6-program assumption is not a quota, gate or reason to add
overlapping tools**. The six outcomes are unchanged. Program count changes only
after accepted actual secure execution; new modes of `dig` or `openssl` add
profiles, not programs. Keep the 8–12-PR coverage allowance subject to native
findings; re-estimate it without silently reducing the task list.

OpenSSL has native diagnostic results and four production candidates merged;
T03 now has a separate verified native candidate, while the remaining candidate engines are unverified. Primary documentation establishes features,
not confinement or compatibility:

- The [pinned sslscan source review](tls-posture-feasibility.md#why-stock-sslscan-is-unsuitable)
  explains why its version-check output is unsuitable despite supporting version
  selection and XML. The [OpenSSL mediation runbook](tls-posture-mediation.md)
  records native usefulness and the narrow retry-enforcement result, with product
  gates still open.
- The [pinned ssh-audit source review](ssh-policy-feasibility.md) found that
  `--skip-rate-test` still permits other probes before policy evaluation. T03
  therefore uses the accepted bounded collector and a local policy snapshot.
- [feroxbuster's upstream project](https://github.com/epi052/feroxbuster)
  provides directory discovery, but its stock recursion/configuration behavior is
  not an accepted authority boundary.
- [Net-SNMP's snmpbulkget manual](https://www.net-snmp.org/docs/man/snmpbulkget.html)
  defines the non-repeaters and maximum-repetitions fields needed for a single
  finite response. Actual TCP execution and output semantics remain to be proved.

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

Close Stage 2 only when **all six tasks are accepted**, their required corpus and
G1–G6 results pass, no row remains blocked or review-pending, and the baseline
profiles retain their accepted contracts. Required outcomes cannot be silently
deleted, weakened or moved to optional work to claim completion. Any scope change
must be explicit in the roadmap and brought to the owner. A successful gate
review names the next Stage 3 work; it does not automatically authorize deeper
composition, attached networks or comparative benchmarking.

## Product gates that this tranche does not close

| Later roadmap gate | Required work that remains visible |
| --- | --- |
| Stage 3 — realistic services and target handling | A finite supported host/port/service matrix; representative actual services and fragmentation/denial behavior; configurable target/SNI/name bindings; exclusions; global rate/network budgets; explicit redirect/referral/DNS decisions; out-of-scope traffic witnesses. Owned synthetic fixtures alone cannot satisfy this gate. Network attachment requires separate authorization. |
| Stage 4 — engagement and session custody | Rules of engagement, persistent limits, expiry/revocation, secret custody and a finite selected authenticated-operation contract. Develop with synthetic credentials; real credentials and intrusive effects remain separately authorized. No existing profile grants these operations. |
| Stage 5 — workflows, findings, reports and retests | Evidence-linked multi-asset coordination, reviewed findings/severity, deduplication, remediation, client deliverables and retest history. Deeper composition and comparative benchmarks stay deferred during the current tranche. |
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

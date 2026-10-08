# Professional-v1 coverage contract

Planning baseline: **8 October 2026, PR #73 accepted at `993c83d`**. The owner
agreed the [product roadmap](product-roadmap.md) and authorized the next coverage
work. This document turns its open-ended coverage tranche into six required
operator tasks. C18 has passed local implementation validation; none of the six is yet
accepted on main.

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

These rows account for all **42 accepted profiles across 16 external programs**.
The IDs are the exact entries in the [secure catalog](secure-tool-catalog.md) and
[registry](../recon_cockpit/secure_agent/tool_adapters.py). Each row retains its
accepted G1–G6 evidence and limitations; it does not need to be reopened to start
the six new tasks. Its broader professional-use gap remains visible in the last
column.

| Operator task | Accepted secure profiles | Verified scope and remaining professional-use gap |
| --- | --- | --- |
| A01. Observe reachability and service hints | `tcp_connect`, `nmap_tcp_connect_v1`, `nmap_service_identify_v1`, `configurable_nmap_service_v1` | Bounded TCP and finite HTTP/SSH service probes; configurable addresses still identify disconnected owned fixtures. Multi-host/port inventories, scan budgets and general service compatibility belong to Stage 3. |
| A02. Retrieve web responses, inspect headers, discover paths and check selected exposure signatures | `http_probe`, `http_headers_v1`, `configurable_http_headers_v1`, `curl_https_get_v1`, `ffuf_content_discovery_v1`, `whatweb_http_fingerprint_v1`, `curl_http_options_v1`, `nuclei_directory_listing_v1`, `nuclei_git_head_v1` | Fixed responses, eight compiled discovery paths, five passive WhatWeb plugins and two finite Nuclei signatures. Header gaps and advertisements are observations; signatures do not prove exploitability. Controlled hierarchy discovery is T04; arbitrary URLs, web/API authentication, general crawling and vulnerability scanning are not accepted. |
| A03. Collect selected DNS metadata | `dig_dns_query_v1`, `dig_dns_srv_v1`, `dig_dns_nsid_v1`, `dig_dns_axfr_v1` | Fixed nonrecursive TCP A/SRV/NSID/AXFR operations with finite responses. MX and address/reverse metadata are T01/T06. Returned names and addresses grant no follow-up authority; resolver selection and actual engagement naming need Stage 3. |
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
| **T01 / C18 — now** | Observe a domain's advertised mail routing; accepted DNS profiles do not query MX. | Reuse `dig`; one fixed nonrecursive TCP MX question, at most four typed preference/exchange rows. No mail delivery, additional name resolution or returned-server connection. | Ordinary MX records, null-MX, NODATA and NXDOMAIN all complete. Distinguish explicit no-mail advertisement from missing data. Reject malformed/null-MX mixtures and incomplete or excess-record responses; hostile names remain data. | **G1–G5 passed locally; G6 final review/CI/merge open.** |
| **T02 — next** | Determine acceptance/rejection of a declared finite set of TLS protocol versions; the accepted TLS profile proves only its selected handshake. | Assess **sslscan** first. Start with version posture rather than an unrestricted cipher or vulnerability scan: one numeric owned endpoint, explicit version set, bounded connection ledger, no client credential, application request, retry escalation or peer-directed fetch. A target of at most eight connections must be proved or revised explicitly during feasibility. Disable unrelated tests; preserve current OpenSSL profiles. | A modern-only fixture and a deliberately legacy-enabled fixture produce the correct per-version observations. Explicit protocol rejection is useful when supported by a complete witnessed response; reset, timeout or unsupported-client behavior is inconclusive. Unknown or incomplete results cannot be reported as disabled versions. | **Required; feasibility first after T01.** |
| **T03** | Assess SSH transport advertisements against an explicit pinned hardening policy; accepted collection alone supplies no policy assessment. | Assess **ssh-audit** first, with an immutable local policy/data snapshot and strictly bounded pre-authentication behavior. No rate test, stress test, client-listener mode, authentication or session. Pin the complete connection/request ceiling before implementation; preserve C14. | A conforming and a deliberately nonconforming synthetic peer both complete with correct observed algorithm lists and rule outcomes. Unknown algorithms and incomplete handshakes stay unknown/inconclusive. Report a policy deviation, not verified exploitability or host identity. | **Required; no secure profile yet.** |
| **T04** | Discover a controlled one-level web directory hierarchy; accepted ffuf covers only its flat eight-path corpus. | Assess **feroxbuster**, reusing its interactive precedent but creating a separate secure profile. Use compiled words, predeclared same-origin prefixes and a finite path universe, depth at most one below the starting path, one active request and an initial total target of at most 24 GETs including calibration. No arbitrary link extraction, off-origin redirects, credentials, uploads or unbounded recursion. | Known nested resources and an empty hierarchy both complete; every planned path/request is accounted for. Wildcard responses must not invent resources. Redirects, path traversal, hostile links, unexpected paths and partial scans cannot expand scope or claim complete discovery. | **Required; no secure profile yet.** |
| **T05** | Obtain one bounded page of SNMP interface descriptions; C13 returns a single successor, not a page. | Assess **snmpbulkget**, reusing the Net-SNMP runtime/fixture patterns. One TCP GETBULK, one fixed ifDescr seed, non-repeaters zero and maximum repetitions four; public synthetic community only. No paging continuation, walks, SET, UDP or real credentials. | A populated page, empty descriptions, endOfMibView and a supported outside-column boundary all have explicit results. Require ordered typed OIDs and a complete response; excess, malformed or partial rows stay inconclusive. A full page means capped observation, not a complete interface inventory. | **Required; no secure profile yet.** |
| **T06** | Observe selected IPv6-address and reverse-name metadata alongside accepted A records. | Reuse `dig` in separate fixed nonrecursive TCP AAAA and PTR profiles, one question and at most four typed answers per action. Returned IPv6 addresses are data, not IPv6 network authorization. No reverse-to-forward lookup, recursion, alias chasing or returned-host follow-up. | Positive records, NODATA and NXDOMAIN complete for both questions. Validate the exact question, record type, name and complete bounded response; malformed names, unsupported alias chains and excess/partial records remain inconclusive. | **Required; no secure profiles yet.** |

T02 is the next gap after C18 because version posture adds a distinct assessment
outcome beyond collecting one certificate or handshake. Its first PR should be a
small feasibility/contract slice using primary tool sources and local read-only
inspection; installation or execution must then follow the concrete reviewed
runtime and owned-lab plan. Do not replace it with another tiny HTTP signature
solely because the existing Nuclei adapter is convenient.

Four additional programs are plausible if all four candidates are suitable. The
roadmap's **4–6-program assumption is not a quota, gate or reason to add overlapping
tools**. The six outcomes above are the fixed gate. Program count changes only
after accepted actual secure execution; alternate modes of `dig` add profiles,
not programs. Re-estimate the 8–12-PR coverage allowance after feasibility findings,
without silently reducing the task list to fit the estimate.

Candidate suitability is unverified. Primary documentation establishes available
features, not confinement or compatibility with this repository:

- [sslscan's upstream manual](https://raw.githubusercontent.com/rbsec/sslscan/master/sslscan.1)
  documents version selection, XML output and options to disable cipher and other
  tests. Defaults are not this proposed bounded profile.
- [ssh-audit's upstream documentation](https://github.com/jtesta/ssh-audit)
  describes policy evaluation and `--skip-rate-test`; the ordinary audit's broader
  behavior must be inspected and constrained before use.
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

Offline R5, accepted local R6, B0–B8, C1–C17 and the initial GUI stay closed.
Competition proposal documents, private PDFs and the saved GUI mocks remain
separate. Model credentials, external target access, paid calls, publication and
submission are not authorized by this coverage contract.

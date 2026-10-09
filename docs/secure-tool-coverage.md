# Secure-tool coverage milestone

Current continuation (9 October 2026):
[T02 acceptance PR #80](https://github.com/0xsl0th/recon-cockpit/pull/80) merged as
`f2e7b785dbea5c8c9f86526f9b3c4deede544125`, followed by
[T03 SSH policy PR #81](https://github.com/0xsl0th/recon-cockpit/pull/81) as
`b90a365ef01fb6a6841b367fe52b4597aa6a219f`, after review and all five final checks.
**T02 and T03 meet G1–G6 and are closed: 48 accepted profiles / 16 programs.**
T02 retains 65 native and 21,593 portable passes; T03 retains 52 native and
21,898 portable passes. The compiled catalog now reports **48 accepted profiles,
zero candidates and 16 programs**, matching those merges. This metadata
reconciliation changes no accepted contract, execution control or runtime limit.

The [T04 source review](web-hierarchy-feasibility.md) selects a separate bounded
ffuf hierarchy candidate. Native prototype, registration and G1–G6 remain open;
no T04 profile is accepted. T05/T06 remain required. Earlier milestones stay closed. Proposal PR #31's
section 3 architecture correction merged as `e23f561` after review, Mermaid
validation and five passing final checks. All five [post-merge checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37870742628)
also passed; do not repeat the merge. Submission and the
wider proposal refresh remain deferred to November. Credentials, paid/live
models, attached targets, deeper workflows and comparative benchmarking remain
deferred.

The dated baseline and candidate wording below preserve their historical
snapshots; this continuation supersedes their pre-merge status.

**Closed on 6 October 2026:** all required rows B0–B8 are accepted on main,
with 20 bounded secure capabilities backed by 11 external programs. The operator's
1 October priority was to broaden useful secure coverage before deeper workflows
and comparative benchmarks. The gate reconciliation below closes that finite
milestone; it does not certify general professional deployment. Completed offline
R5 and accepted local R6 also remain closed.

The [read-only secure-tool catalog](secure-tool-catalog.md) is accepted in PR #46
at `0d5cbdc`. The later service/web workflow, configurable owned endpoints,
shared service and initial owned GUI are accepted through PR #54. Current work
returns to successive product-coverage batches below, without reopening B0–B8.
Deeper workflow composition and comparative benchmarking remain deferred.

[PR #38](https://github.com/0xsl0th/recon-cockpit/pull/38) accepted B1 DNS/TLS.
[PR #39](https://github.com/0xsl0th/recon-cockpit/pull/39) merged as `79abaab` and
accepted B2 SSH/LDAP; its final and post-merge checks passed. Main reached
**11 secure capabilities backed by 8 external programs** after [PR #40](https://github.com/0xsl0th/recon-cockpit/pull/40)
accepted B3 anonymous SMB metadata at `775352e`. [PR #41](https://github.com/0xsl0th/recon-cockpit/pull/41)
accepted B4 RPC/NFS metadata at `6623aa0`, bringing main to **13 secure capabilities
backed by 10 external programs**. [PR #42](https://github.com/0xsl0th/recon-cockpit/pull/42)
accepted B5 FTP/SMTP at `38cbd43`, bringing main to **15 secure capabilities backed
by the same 10 programs**. [PR #43](https://github.com/0xsl0th/recon-cockpit/pull/43) accepted B6 Docker/WinRM
at `02a7d7f`, bringing main to **18 secure capabilities backed by the same 10
programs**. [PR #44](https://github.com/0xsl0th/recon-cockpit/pull/44) accepted B7
bounded Nmap service identification at `fcb9419`; all final and post-merge checks
passed. [PR #45](https://github.com/0xsl0th/recon-cockpit/pull/45) accepted B8
synthetic Kerberos at `47d70a2`, after fresh review and all five final checks.
Main now has **20 accepted capabilities backed by 11 programs**. Native TCP,
HTTP and header adapters account for three capabilities without another program.

## What the inventory measures

The inventory baseline is main `ba0d6f8` (PR #37). Interactive support means the
cockpit builds a command, asks the operator, and uses the host runner. It does
not establish an agent-safe execution boundary. Secure support means a specific
versioned capability has passed actual owned-lab execution through policy,
approval, audit, admission and a confined launcher, with independently checked
results and evidence. It does not mean every mode of that executable is safe.

Repository sources are [interactive suggestions](../recon_cockpit/suggestions.py),
[interactive execution](../recon_cockpit/cli.py), the
[host runner](../recon_cockpit/runner.py), and the
[secure registry](../recon_cockpit/secure_agent/tool_adapters.py). Installed binaries
are prerequisites, not implementation or verification evidence.

There are **10 interactive executable families** and, at the baseline, **6 secure
capabilities backed by 3 external programs**. Native TCP/HTTP adapters are counted
as capabilities, not additional installed tools. The product's roughly 40-tool
direction is a long-term integration target; there is no previously approved
40-name catalog. This milestone closes the finite core-enumeration checklist below,
not an arbitrary executable count or the full professional product scope.

| Tool / capability | Interactive repository support | Secure support at baseline | Remaining product gap |
| --- | --- | --- | --- |
| Nmap | Scan profiles, XML import, service-specific NSE suggestions | `nmap_tcp_connect_v1`: one TCP port, no DNS, scripts or service detection | Useful bounded service identification; additional scan modes remain separate contracts. |
| curl | FTP listing, Docker API and WinRM command suggestions | `curl_https_get_v1`: one verified fixture HTTPS GET | FTP and fixed read-only API inspection; no general URL, credential or redirect support. |
| ffuf | Content discovery suggestions with operator wordlist selection | `ffuf_content_discovery_v1`: eight fixed paths | Existing finite profile satisfies this milestone's initial content-discovery row; broader dictionaries are later scope. |
| feroxbuster | Discovery suggestion | None | Overlaps ffuf; recursive crawling is later scope, not a prerequisite here. Binary absent on this development host at inventory. |
| ssh-keyscan | Host-key collection suggestion | None | Fixed host-key collection without login. |
| ssh | Known-credential login suggestion | None | Authenticated interactive sessions require a later credential/session boundary. |
| NetExec (`nxc`) | Anonymous SMB shares/RID and credential-related suggestions | None | Broad Windows/AD and authenticated behavior; initial SMB coverage should use the smaller explicit smbclient profile. |
| smbclient | Anonymous share listing suggestion | None | Fixed anonymous share metadata without downloading or writing files. |
| ldapsearch | RootDSE and user/group search suggestions | None | Fixed anonymous base-scope RootDSE; broader searches/referrals are separate scope. |
| kerbrute | Supplied-user enumeration suggestion | None | Finite synthetic principal enumeration against an owned KDC; no password testing. |
| Native TCP, HTTP and header adapters | No separate executable integration | `tcp_connect`, `http_probe`, `http_headers_v1` in accepted owned profiles | These existing narrow contracts remain regression anchors. |
| dig | New integration candidate; no current menu command | None | Fixed nonrecursive DNS record query accepted in B1; additional DNS modes remain later scope. |
| OpenSSL | New integration candidate; no current menu command | None | Structured verified TLS handshake metadata accepted in B1; broader TLS assessment remains later scope. |
| rpcinfo / showmount | Nmap RPC/NFS suggestions exist; these clients are not integrated | None | Fixed RPC program metadata and NFS export listing without mounting. |
| SMTP capability query | Nmap `smtp-commands` suggestion | None | Bounded banner/EHLO/QUIT, no mail, authentication or recipient probing. |
| Docker API / WinRM metadata | curl suggestions | None for these services | Fixed read-only metadata endpoints and authentication-scheme observations, no container operations or shell sessions. |

All existing secure execution evidence is Linux owned-fixture evidence. None of
these entries claims general external-target, Windows-host or production engagement
readiness. DNS/TLS add two executable integrations; another curl mode adds a
capability, not another executable to the count.

## Prioritized coverage checklist

Every required row must pass gates G1–G6 below. A checked baseline row refers only
to its accepted bounded scope. New rows stay unchecked until the implementation
and actual execution evidence are reviewable; a PR pending merge is labelled as
such and is not counted as accepted main coverage.

| Priority / batch | Required coverage | Status | Tool-specific completion evidence |
| --- | --- | --- | --- |
| B0 | TCP reachability and Nmap TCP profile | [x] Accepted | Existing owned success/failure, enforced scope and independently replayed XML. Preserve accepted profiles. |
| B0 | HTTP retrieval, response headers, verified HTTPS retrieval | [x] Accepted | Native HTTP/header and curl cases complete useful requests; malformed responses and untrusted TLS remain inconclusive/refused. |
| B0 | Finite web path discovery | [x] Accepted in PR #37 | ffuf records all eight paths; wildcard/partial output does not claim useful coverage. |
| B1 | DNS records with dig | [x] Accepted in PR #38 | One fixed A query over TCP to the owned server; answer and NXDOMAIN distinguished; no recursion, search, zone transfer or follow-up to returned addresses. |
| B1 | TLS handshake with OpenSSL | [x] Accepted in PR #38 | Fixed hostname/CA, verified negotiation and structured protocol/cipher facts; reject untrusted/malformed peers; no HTTP, client credential or protocol-scan claim. |
| B2 | SSH host keys with ssh-keyscan | [x] Accepted in PR #39 | One fixed key type and endpoint; validate bounded key/fingerprint output; no login or trust-on-first-use claim. |
| B2 | LDAP RootDSE with ldapsearch | [x] Accepted in PR #39 | Anonymous base query with fixed attributes; structured entries; referrals, arbitrary DNs and user enumeration disabled. |
| B3 | SMB share metadata with smbclient | [x] Accepted in PR #40 | Actual anonymous finite listing and replay in the owned lab; native empty/denied/malformed ambiguity stays inconclusive. No credentials, file retrieval, writes or remote execution. |
| B4 | RPC program metadata with rpcinfo | [x] Accepted in PR #41 | Real fixed TCP listing and explicit empty result replay in the owned lab; advertised ports remain metadata, with no follow-up. |
| B4 | NFS export metadata with showmount | [x] Accepted in PR #41 | Real export/empty listing and replay; malformed/hostile groups stay inconclusive and unapproved discovered ports are blocked. No mounts or export reads. |
| B5 | Anonymous FTP listing with curl | [x] Accepted in PR #42 | Real fixed NLST and valid empty result with complete control evidence; both connections stay on the predeclared endpoint. Forbidden passive IP/port blocked; no transfers. |
| B5 | SMTP advertised capabilities with curl | [x] Accepted in PR #42 | Real EHLO capabilities and valid no-extension result, followed by QUIT. Rejected EHLO/HELO, malformed and hostile replies remain inconclusive; no mail/auth/account probing. |
| B6 | Docker API metadata with curl | [x] Accepted in PR #43 | Separate fixed GET profiles for /_ping and /version; complete health and bounded JSON observations, no container lifecycle, filesystem or command endpoints. |
| B6 | WinRM endpoint metadata with curl | [x] Accepted in PR #43 | One fixed unauthenticated endpoint response; report status/authentication schemes; no login, SOAP operations or shell. |
| B7 | Nmap service identification | [x] Accepted in PR #44 | Real Nmap HTTP/SSH matches and honest unidentified results from two compiled probes and a pinned no-op NSE entrypoint. Structured XML replay, policy/approval/enforcement and cleanup verified; old TCP-only profile preserved. |
| B8 | Kerberos principal enumeration with kerbrute | [x] Accepted in PR #45 | Real Kerbrute against an error-only owned KDC, two compiled synthetic names, two requests, structured tool-reported exists/unknown with the error-text ambiguity disclosed. No passwords, spraying, ticket extraction or real directory. |

Batch order follows missing protocol families and existing interactive precedents,
then runtime/fixture complexity. At each batch handoff, compare the remaining
unchecked rows and prioritize the next tool gap. Change the order with a recorded
reason if prerequisites or findings warrant it. Do not silently delete, waive or
move a required row to deferred work to claim milestone completion. Keep each PR
small enough for an independent review; stop a tool on unsupported prerequisites
without falling back to the host runner. A blocked tool does not complete its row.

**B8 closes the final required protocol-family gap.** Its accepted scope is
finite synthetic Kerbrute reporting through an error-only owned KDC. The
response-spoof scenario documents a vendor limitation: an unknown report is not
proof that a principal is absent. It is neither verified negative discovery nor
successful injection detection. No tool report expands execution authority.

There is no hidden required B9 or automatic expansion to forty tools. The original
milestone stays closed; separately scoped product batches use the same six gates.
Model credentials, paid calls and live evaluation remain much later.

## Successive product coverage batches

Priority 3 follows the accepted initial GUI. C17 in PR #72 brings accepted coverage
to **42 bounded profiles from 16 external programs**. Installed binaries and
interactive commands do not satisfy secure coverage. The following rows
distinguish accepted operations from candidates. C18/T01 is now closed in
[PR #74](https://github.com/0xsl0th/recon-cockpit/pull/74), bringing accepted main
to **43 profiles/16 programs**. PR #75 accepted T02 source feasibility and
PR #76 accepted the [native diagnostic](tls-posture-native.md) with its retained
**0/1 retry-prevention failure**. PR #77 accepted the
[mediated diagnostic](tls-posture-mediation.md), retaining 8/8 ordinary and 4/4
absence observations while blocking the tested second ClientHello before peer
delivery, **1/1**. PR #78 accepted the
[closed observation/replay slice](tls-posture-observations.md), with 26/26 isolated
replays and 18/18 safe negative cases; its diagnostic receipts grant no authority.
PR #79 integrated four separately versioned [production profiles](tls-posture-tools.md)
through policy, fresh per-action approval, consumed permits, admission and both
evidence inspectors. PR #80 accepted T02 after 65 native and 21,593 portable
passes, review and required checks; PR #81 accepted T03 after 52 native and
21,898 portable passes, review and required checks. G1–G6 are closed for both,
bringing the catalog to 48 accepted profiles, zero candidates and 16 programs. Every new operation must satisfy G1–G6
independently. The
[finite professional-v1 contract](professional-v1-coverage.md) now fixes six
required task outcomes under the accepted [product roadmap](product-roadmap.md),
without changing the scope or closure of the accepted core milestone.

| Order | Capability gap and present support | Completion criteria | Status |
| --- | --- | --- | --- |
| C1 | Redis server metadata; redis-cli, no interactive menu integration | One RESP2 INFO server, four selected typed fields, no authentication/key access/writes/cluster follow-up; actual useful execution, error/hostile/bounded-output cases, replay and G1–G6. | [x] Accepted in PR #55. |
| C1 | SNMP system metadata; snmpget, no interactive menu integration | One v2c TCP GetRequest of three fixed system OIDs with public synthetic community; complete typed values/noSuchObject, no walks/writes/UDP/custom community; actual useful execution, adversarial cases, replay and G1–G6. | [x] Accepted in PR #55. |
| C2 | PostgreSQL pre-authentication TLS; existing secure OpenSSL runtime, no interactive database integration | One fixed SSLRequest followed by fixture-CA/name-verified TLS 1.3 and clean close without application data; structured handshake-only evidence, refusal/untrusted/malformed/stalled/injected cases, replay and G1–G6. No startup/login/SQL/readiness claim. | [x] Accepted in PR #56. |
| C2 | MySQL pre-authentication TLS; same existing OpenSSL runtime, no interactive database integration | Read one bounded initial greeting, send fixed SSLRequest, verify TLS 1.3 and close without application data; hostile greeting version remains inert, no account/auth-plugin/login/SQL operation; honest fragmented-greeting limitation, replay and G1–G6. | [x] Accepted in PR #56. |
| C3 | HTTP application fingerprinting; WhatWeb has no interactive integration | One fixed GET with five passive plugins and a finite sealed Ruby/WhatWeb runtime; ordinary hints and no-hints tasks both complete, hostile/meta redirects stay inert, all eleven scenarios retain scope/bounds/closure, structured untrusted evidence and G1–G6. | [x] Accepted in PR #57. |
| C4 | DNS service metadata; dig has accepted fixed A-query support, no interactive menu integration | One fixed `_ldap._tcp.harbordesk.test. IN SRV` question over TCP; at most four typed priority/weight/port/target/TTL rows; 4/4 ordinary record/NODATA/NXDOMAIN/unavailable completions with zero unnecessary refusals, separate injected-metadata usefulness, all ten scenarios with actual queries, enforced bounds, evidence and G1–G6. No recursion or advertised endpoint follow-up. | [x] Accepted in [PR #58](https://github.com/0xsl0th/recon-cockpit/pull/58), merge `6080a5c`; all five final and post-merge jobs passed. |
| C5 | RDP initial protocol negotiation; repository-owned Ruby socket adapter, no interactive profile | One fixed 19-byte TLS offer, write-half-close and first bounded reply only; 5/5 ordinary and 2/2 separate robustness completions, six inconclusive cases, 26/26 blocked destinations and 130/130 boundary fields with actual requests, typed metadata, enforced bounds, evidence and G1–G6. No TLS/CredSSP/NTLM, authentication or remote session. | [x] Accepted in [PR #59](https://github.com/0xsl0th/recon-cockpit/pull/59), merge `846e459` from reviewed `5a5f9b4`; all five final and post-merge jobs passed. |
| C6 | SMB2 negotiation metadata; separate repository-owned Ruby adapter alongside accepted B3 smbclient share listing | One fixed 108-byte offer of SMB 2.1/3.0.2, write-half-close and one response bounded to 4,100 bytes; require 5/5 ordinary and 2/2 robustness completions, seven inconclusive cases after actual requests, structured untrusted metadata, enforcement, replay and G1–G6. No SESSION_SETUP, NTLM exchange, login or share access. | [x] Accepted in [PR #60](https://github.com/0xsl0th/recon-cockpit/pull/60), merge `aa65bff7`; all five final and post-merge jobs passed. See the [C6 runbook](smb2-negotiation-tools.md). |
| C7 | SMTP STARTTLS before authentication; existing secure OpenSSL runtime, separate from accepted curl EHLO capability query | Fixed EHLO/STARTTLS and fixture-CA/name-verified TLS1.3 with owner clean-close witness; 2/2 ordinary, 2/2 separate robustness, eight inconclusive outcomes, 24/24 blocked destinations, 120/120 boundary fields, actual execution/replay and G1–G6. No auth/mail/credentials/application requests; disclose incomplete SMTP transcript/status validation. | [x] Accepted in [PR #61](https://github.com/0xsl0th/recon-cockpit/pull/61), merge `7c5e88ad`; all five final and post-merge jobs passed. See the [C7 runbook](smtp-starttls-tools.md). |
| C8 | LDAP STARTTLS before bind; existing OpenSSL runtime, separate from accepted anonymous RootDSE | One fixed extended request, fixture-verified TLS/clean close, 2/2 ordinary and 2/2 separate robustness completions, eight inconclusive cases after actual request progress, 24/24 blocked destinations, 120/120 boundary fields, evidence and G1–G6. No bind/search/credentials/referral follow-up; disclose unchecked response ID/fields and discarded LDAP reply. | [x] Accepted in [PR #62](https://github.com/0xsl0th/recon-cockpit/pull/62), merge `a582bd6c`; all five final and post-merge jobs passed. See the [C8 runbook](ldap-starttls-tools.md). |
| C9 | FTP explicit TLS before login; secure OpenSSL, separate from accepted anonymous FTP listing | Fixed AUTH TLS, verified fixture TLS/clean close, 2/2 ordinary and 3/3 robustness completions, six inconclusive cases, 22/22 blocked destinations, 110/110 boundary fields, actual execution/replay and G1–G6. No login/credentials/listing/transfer/data connections; disclose unchecked/discarded replies and strict retained-greeting support. | [x] Accepted in [PR #63](https://github.com/0xsl0th/recon-cockpit/pull/63), merge `e06e1a4`; all five final and post-merge jobs passed. Initial legacy stall failure remains unexplained. See the [C9 runbook](ftp-starttls-tools.md). |
| C10 | DNS server-reported NSID; interactive Nmap suggestion exists, new secure dig profile reuses the accepted runtime | One fixed nonrecursive TCP question with empty EDNS NSID; at most 64 opaque bytes; 5/5 ordinary and 1/1 hostile-metadata completions, eight inconclusive cases after actual query progress, 28/28 blocked destinations, 140/140 boundary fields, replay and G1–G6. No UDP, cookies, recursion, negotiation retries, zone transfer, verified identity or follow-up. | Implemented at `4e6d20e7`; 14,814 portable/62 native tests and 72 accepted-bundle replays passed. Initial historical test-selection failure and correction retained; [x] accepted in PR #64 at `dea8c7a`; all final and post-merge jobs passed. See the [C10 runbook](dns-nsid-tools.md). |
| C11 | DNS zone-transfer behavior; existing secure dig runtime, no interactive AXFR profile | One fixed synthetic TCP AXFR; accept four messages/16 records with matching SOAs; 3/3 ordinary complete/multiframe/refused tasks, 2/2 robustness, nine inconclusive cases, actual query progress, 28 destination/140 boundary checks, replay and G1–G6. Five-second/8192-byte native limits; no credentials, recursion or returned-host follow-up. | Implemented at `25b9395c`; 15,464 portable/61 native tests, five clean-commit trials and 78 accepted-bundle replays passed; [x] accepted in PR #65 at `82dd85a`; all five final and post-merge jobs passed. See [C11 runbook](dns-axfr-tools.md). |
| C12 | HTTP OPTIONS metadata; existing secure curl runtime, no interactive OPTIONS profile | One fixed resource, complete bounded HTTP/1.1 status/Allow/auth-scheme metadata; require 6/6 ordinary and 2/2 robustness tasks, six inconclusive negative cases, 28 destination/140 boundary checks, five authority gates, unchanged evidence replay and G1–G6. No advertised-method execution, redirects, credentials or GUI work. | Implemented at `c875820`; 16,138 portable/40 native tests and 83 accepted-bundle replays passed. [x] Accepted in [PR #66](https://github.com/0xsl0th/recon-cockpit/pull/66) at `7faf974`; all five final CI jobs passed. See [C12 runbook](http-options-tools.md). |
| C13 | SNMP interface successor metadata; accepted GET covers three system scalars, no interactive GETNEXT integration | One fixed ifDescr column seed through snmpgetnext; 4/4 ordinary and 2/2 robustness completions, eight inconclusive negatives, 28 destination/140 boundary checks, authority/cleanup gates, unchanged replay and G1–G6. No walk, GETBULK, SET, UDP, real community or returned-OID follow-up. | [x] Accepted in [PR #67](https://github.com/0xsl0th/recon-cockpit/pull/67) at `7cc6645`; 16,687 portable/43 native tests, 91 accepted replays and all five final CI jobs passed. See [C13 runbook](snmp-next-tools.md). |
| C14 | SSH transport algorithm advertisements; interactive Nmap suggestion, secure host-key collection separate | One fixed KEXINIT template with random cookie, write EOF and one bounded reply; 4/4 ordinary and 2/2 robustness completions, eight inconclusive negatives, 28 destination/140 boundary checks, replay and G1–G6. No completed key exchange, login or session. | [x] Accepted in [PR #68](https://github.com/0xsl0th/recon-cockpit/pull/68) at `a6f11b7`; 17,728 portable/44 native tests, 97 accepted replays and all final/post-merge CI jobs passed. See [C14 runbook](ssh-algorithms-tools.md). |
| C15 — accepted | TLS peer-certificate metadata; existing OpenSSL runtime, no interactive certificate inventory | One fixed CA/name-verified TLS 1.3 exchange with clean close, finite leaf DER fingerprint/validity and DNS/IP SANs; require 3/3 ordinary and 1/1 separate robustness completions, eight inconclusive negatives, actual request/closure/boundary evidence, unchanged replay and G1–G6. No application data, credentials, revocation/AIA fetch or name follow-up. | [x] Accepted in [PR #69](https://github.com/0xsl0th/recon-cockpit/pull/69) at `e4c9d64`: 18,396 portable/39 native passes, 3/3 ordinary + 1/1 robustness, eight inconclusive negatives, 24/24 destination and 120/120 boundary checks, 103 unchanged accepted replays; independent review and five final CI passes. G1–G6 complete. 40 profiles/15 programs. See [C15 runbook](tls-certificate-tools.md). |
| C16 — accepted | One harmless HTTP directory-listing signature using pinned Nuclei v3.11.1; no existing interactive Nuclei integration | One fixed GET and compiled matcher; 4/4 ordinary matched/unmatched completions, 1/1 separate hostile-body robustness task, eight inconclusive negatives, complete original owner and normalized native response reconciliation, scratch/enforcement witnesses, replay and G1–G6. No general templates, credentials, redirects or follow-up. | [x] Accepted in PR #71; 23 Linux tests, 4/4 ordinary + 1/1 robustness, eight inconclusive negatives, 107 unchanged accepted replays. 18,958 portable passes; fresh independent reviews and all five checks gate the merge. Separate static runtime/private scratch authorized after PR #70 feasibility acceptance at `2f7fb5a`. Accepted 41 profiles/16 programs. See [C16 runbook](nuclei-tools.md). |
| C17 — accepted | One fixed synthetic Git HEAD marker using the accepted Nuclei runtime | One GET; four ordinary completions, one hostile-HTML nonmatch, eight inconclusive cases, independent owner/native reconciliation, replay and G1–G6. New versioned response contract; preserve C16. No repository download or returned-ref follow-up. | [x] G1–G6 closed by PR #72 at `e004824` after fresh review and five passing final checks. 19,437 portable and 44 native checks, 4/4 ordinary + 1/1 robustness, eight inconclusive cases, 26/26 destination and 195/195 boundary fields, 120 unchanged accepted replays. Development refusals and test-routing correction retained. See [C17 runbook](nuclei-git-tools.md). |
| C18 / T01 — accepted | DNS MX metadata; separately versioned `dig_dns_mx_v1` reuses the accepted dig runtime | One fixed nonrecursive TCP question, at most four typed preference/exchange rows; ordinary records, null-MX, NODATA and NXDOMAIN must complete with zero unnecessary refusals. Actual bounded query/closure, malformed/hostile cases, enforcement, unchanged replay and G1–G6. No advertised-server follow-up, credentials or mail delivery. | [x] G1–G6 closed in [PR #74](https://github.com/0xsl0th/recon-cockpit/pull/74) at `b1afbbab`: 19,888 portable/37 native, 5/5 ordinary + 1/1 robustness, seven inconclusive, 26/26 destination and 130/130 boundary checks, 133 unchanged accepted replays. Fresh review, 407 focused tests and all five final CI jobs passed. Accepted 43 profiles/16 programs. See [C18 runbook](dns-mx-tools.md). |
| T02 — accepted | Finite TLS 1.0/1.1/1.2/1.3 posture through four separately versioned OpenSSL profiles | One delivered ClientHello per action, independent approval and consumed permit, complete-record mediation and corroborated owner/client evidence. Explicit rejection can be useful; retry refusal alone is safety evidence. No cipher sweep, credentials or encrypted application-data prevention claim. | [x] G1–G6 closed in [PR #80](https://github.com/0xsl0th/recon-cockpit/pull/80) at `f2e7b785`: 65 native / 21,593 portable passes, 20 useful observations, 20 inconclusive negatives, separate HRR/extra-stream refusals and unchanged replay. Fresh review and five final checks passed. The original 0/1 diagnostic failure remains historical evidence. See [acceptance corpus](tls-posture-acceptance.md). |
| T03 — accepted | Pinned local advertisement policy in both transport directions | Reuse byte-identical C14 collector; one request/write EOF/first packet, no login or extra probe. Known deviations useful, unknowns inconclusive. | [x] G1–G6 closed in [PR #81](https://github.com/0xsl0th/recon-cockpit/pull/81) at `b90a365e`: 52 native / 21,898 portable passes, six ordinary and two robustness completions, two unknown and nine malformed/pressure inconclusive cases. Fresh review and five final checks passed; no new program. See [runbook](ssh-policy-tools.md). |
| T04–T06 — remaining finite tranche | Controlled web hierarchy, one SNMP interface page and fixed AAAA/PTR metadata | Useful/absent/negative corpus, secure execution, evidence, enforcement and G1–G6 for each. | Required; T04 has a [source-reviewed ffuf candidate](web-hierarchy-feasibility.md), with native prototype and G1–G6 still open; deeper workflows and benchmarking remain deferred. |
| Later | Broader Windows/AD, authenticated SSH/LDAP/SMB, SQL readiness/queries and real SNMP deployments | Separate credential/session and engagement-scope design with relevant authorization, plus exact operation contracts and G1–G6. Existing interactive suggestions do not satisfy this row. | Deferred boundary work. |
| Later | Additional web discovery/scanning engines | Evaluate incremental coverage beyond accepted ffuf/HTTP profiles before selecting a finite operation and corpus; no arbitrary plugins/templates/crawling. | Optional; deeper composition and comparison deferred. |

C14 fills the gap between collected host keys and advertised SSH transport
algorithms. The existing Nmap interactive suggestion remains separate: a sealed
repository-owned Ruby client avoids its additional scan connection, larger NSE
closure and unbounded peer-declared packet read. B7's deny-all NSE shim stays fixed.
Advertisements do not verify algorithm implementation, identity or a vulnerability.

C15 fills the existing broader-TLS inventory gap with bounded certificate metadata,
preserving fixture trust/name verification and clean close. Its dedicated public
CA and owner-only synthetic key do not alter accepted fixtures. The finite parser
rejects unknown SAN kinds and size pressure; certificate contents never become
network authority. Detailed compatibility and prefix-counter limits are in the
[C15 runbook](tls-certificate-tools.md).

The accepted [Nuclei feasibility report](nuclei-feasibility.md) identified the
missing HTTP security-validation category and the stock CLI's incompatibility
with the existing runtime. Subsequent operator authorization selected C16's
separate static profile with bounded private scratch, preserving accepted defaults.
The accepted [C16 check](nuclei-tools.md) demonstrates useful positive and supported
negative completion, independently checked owner bytes and native dumps, and the
enforcement/review gates. Installed Nuclei, a scanner report or a false matcher
alone does not satisfy coverage. C17 has now passed its separate G1–G6 gate
through PR #72; its finite marker scope remains unchanged.

C1–C18 are closed. Redis/SNMP metadata remains `untrusted_service_report`, and
TCP SNMP does not establish UDP coverage. C2 reuses the existing single-action
authority, OpenSSL runtime, strict TLS parser and evidence infrastructure. Its two
profiles brought accepted main to **27 profiles from the same 13 programs**.
The selected database wire protocol is a contract binding;
`verified_tls_handshake_only` with `authenticated_database_session: false` does not
establish database product identity, version, readiness or account access. No
username, password, database startup/login, SQL, dynamic authentication plugin or
plaintext downgrade is allowed. C2 adds no GUI workflow or real-network attachment.

The [C2 runbook](database-tls-tools.md) defines 12 scenarios: six per profile.
The ordinary PostgreSQL/MySQL handshakes must complete 2/2, and the hostile MySQL
greeting must preserve successful TLS completion without acting on its text.
All refused, untrusted, malformed, stalled and hostile PostgreSQL replies remain
inconclusive. Record these utility and robustness outcomes separately; blocking
everything cannot satisfy G2. MySQL greeting fragmentation can produce an
inconclusive result with the pinned client's initial read; retain that limitation
without adding retries, another client or broader wire authority.

C2 local validation passed **10,776 portable and 28 native Linux tests** (24 C2,
four accepted OpenSSL regressions), with no selected failures/errors/skips. The
12 scenarios completed 2/2 ordinary tasks with zero unnecessary refusals and 1/1
separate hostile-MySQL task, blocked 24/24 forbidden destinations, passed all
120 native boundary fields and replayed unchanged. A separate clean-source run
repeated those three useful trials, blocked 6/6 destinations and replayed all
33 accepted bundles unchanged through CLI and shared inspection. Provider calls
and cost stayed zero. PR #56 passed review and all five final hosted jobs before
merge `9603a54`; all five post-merge jobs also passed. The portable macOS helper
correction retained real TLS tests, passed 224 focused cases and changed no
production/native source. See the [verification record](verification.md).

The accepted [C3 runbook](whatweb-tools.md) fixes Title, HTTPServer, X-Powered-By,
MetaGenerator and JQuery at aggression 1, one request and no follow-up. Both
ordinary tasks, including a complete response without hints, must finish 2/2 with
zero unnecessary refusals. Injection and meta-redirect utility are separate
robustness trials. HTTP redirects, denials, malformed/early EOF/stalled replies
and input/output pressure remain inconclusive. All eleven cases need actual native
execution, one connection/request, enforced bounds, closed owners and unchanged
replay; startup failures cannot satisfy a negative case. C3 brought accepted main to
**28 profiles from 14 programs**, with no broader GUI or network attachment claim.

C3's complete portable suite passed **11,109 tests**, with zero failures/errors/skips
and 914 integration cases deselected. The JUnit duration was 299.271 seconds.
Native validation passed **39 selected Linux tests**, including 17 C3 cases
and 22 accepted-tool regressions. All eleven scenarios matched their declared
outcomes, closed at one connection/GET, replayed unchanged and blocked 22/22
forbidden destinations. Ordinary and robustness tasks completed 2/2 each, kept
as separate denominators. A clean-source run at `0bdd9b6` repeated both pairs
with zero unnecessary refusals, blocked 8/8 destinations and replayed all 36
accepted bundles unchanged through CLI and shared inspection. Provider calls
and cost stayed zero. PR #57 passed fresh independent review and all five final
hosted jobs before the authorized `fdfe6e8` merge; all five post-merge jobs also
passed. The reviewed `cf69f4e` and merge
trees match; all 494 validated source hashes matched. C3's G6 is closed.

C4 accepted fixed SRV metadata while reusing the existing dig infrastructure. The
[C4 runbook](dns-srv-tools.md) defines ten cases and separate usefulness criteria:
four ordinary completions and one injected-metadata robustness completion.
Malformed, excess-record, refused, stalled and output-pressure cases stay
inconclusive; every negative still needs actual native execution and one validated
question. The six additional native checks cover grant consumption/replay,
missing-proof denial, cancellation, private-input isolation, UDP denial and the
task ceiling. All seven authority gates remain required; the shipped policy
requires fresh personal approval.

C4 native validation passed **25 selected tests** (16 C4 and nine accepted
regressions) with zero selected failures/errors/skips. The ten scenarios retained
one validated query/connection, closed owners, blocked 20/20 destinations, passed
100/100 boundary fields and replayed unchanged. A clean-source run at `0c6dcf5`
completed 4/4 ordinary tasks and one separate hostile-metadata task with zero
unnecessary refusals, blocked 10/10 destinations and replayed all five new and
40 accepted bundles unchanged through CLI and shared inspection. Calls/cost stayed
zero. Native JUnit time was 79.168 seconds; it is not comparative overhead.
The full portable suite passed **11,428 tests**, with 930 integration cases
deselected and zero failures/errors/skips, in 298.681 seconds. The first run's
one failure was a stale older-fixture snapshot selector; its test-only correction
passed 86 focused tests and left production/native source unchanged.

C4 brought accepted main to **29 profiles from the same 14 programs**. Independent
reviews passed 1,328 authority/runtime, 821 parser/evidence and 422 regression
tests; all 502 validated source hashes matched. All five
[final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37673798024)
passed 11,428 tests each. Reviewed `65810b8` merged as `6080a5c` on 7 October at
19:36:01 UTC with identical tree `fbb7092085e169f499d364355bf11c75c4ca2fcb`.
All five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37675710586)
also passed. Returned targets and ports remain untrusted evidence, never automatic
scope. C4's G6 is closed.

The [C5 runbook](rdp-negotiation-tools.md) binds `rdp_initial_negotiation_v1` to
one repository-owned Ruby socket operation in the existing confined runtime.
It sends a fixed TLS offer, closes its write side and reads only the first
11- or 19-byte confirmation. The two-second absolute operation deadline sits
within the existing five-second tool limit. The owned fixture must witness one
exact request and write-half-close. No TLS handshake, CredSSP, NTLM, authentication
or session can follow; metadata does not prove identity or all supported protocols.

Five ordinary cases cover TLS selection,
explicit standard RDP, legacy confirmation, NLA-required failure and Entra-required
failure. Fragmented replies and valid first frames followed by hostile trailing
data form two separate robustness completions. Six negative cases cover malformed,
unoffered, unknown-failure, truncated, oversized and stalled replies. All 13 cases
executed and replayed with enforced bounds and closed ownership;
no startup failure counts as a negative success. Trailing data is not inspected,
so that trial makes no injection-detection claim.

C5 local validation passed **11,898 portable tests** (949 deselected;
270.690 JUnit seconds) and **36 native tests** (19 C5 and 17 WhatWeb;
109.828 seconds), with zero failures, errors or skips. **5/5 ordinary** and
**2/2 robustness** tasks completed with zero unnecessary refusals;
**26/26 unauthorized destinations** were blocked and **130/130 boundary fields**
passed. Clean-source verification at `f24a2528` repeated seven useful trials with
**14/14 blocked destinations** and replayed all **45 accepted bundles** through
CLI and shared inspection without changing bytes, mtimes or modes. All **514
source hashes** matched. Independent source review passed 1,395 tests; focused
runs overlap, so their totals are not added. The receipt and detailed counts are
recorded in the [C5 runbook](rdp-negotiation-tools.md). Reviewed head `5a5f9b4`
merged as `846e459` in [PR #59](https://github.com/0xsl0th/recon-cockpit/pull/59).
All five [final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37678942749)
and all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37684453123)
passed. C5's G6 is closed; accepted main contains **30 profiles using the same
14 external programs**.

**C6 is accepted in [PR #60](https://github.com/0xsl0th/recon-cockpit/pull/60).**
Reviewed head `b2d5fce0` merged as `aa65bff7` on 7 October at 21:46:24 UTC;
reviewed and merged trees match `bbccb66ce76107cf2febb4f4c66b6964a5634a25`.
Independent authority/runtime and evidence reviews found no blockers. All five
[final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37688048570)
and all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37691744431)
passed. Preserve 12,654 portable and 56 native tests, 5/5 ordinary and 2/2 separate
robustness completions, zero unnecessary refusals, 28/28 blocked destinations,
140/140 boundary fields and 52 accepted-bundle replays. Accepted main now has
**31 profiles using 14 programs**. C6 stays closed; private review receipt:
`.secure-agent/pr60-merge-review.json`.

**C7 is accepted in [PR #61](https://github.com/0xsl0th/recon-cockpit/pull/61).**
Reviewed head `4239834d` merged as `7c5e88ad` on 7 October at 22:32:58 UTC;
reviewed and merged trees match `e07e810f7995f5f17aca942ccb4ebeede2152e0e`.
Fresh authority/runtime and parser/evidence reviews found no blockers, with
432 and 399 focused tests passing. All 532 tested source hashes, 75 reports,
90 referenced artifacts and six inherited receipt links matched. All five
[final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37694217980)
and all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37696888315)
passed. Preserve 13,175 portable and 52 native tests, 2/2 ordinary and 2/2 separate
robustness completions, zero unnecessary refusals, 24/24 blocked destinations,
120/120 boundary fields and 59 accepted-bundle replays. Accepted main now has
**32 profiles using 14 programs**. C7 stays closed; private review receipt:
`.secure-agent/pr61-merge-review.json`.

**C8 is accepted in [PR #62](https://github.com/0xsl0th/recon-cockpit/pull/62).**
Reviewed head `7c853f6b` merged as `a582bd6c` on 7 October at 23:03:04 UTC;
reviewed and merged trees match `262e514cff571e7da39a89ede00bec3f93fa2cf3`.
Fresh source and evidence reviews found no blockers; 343 focused authority tests
passed. All 540 tested source hashes, 79 reports, 94 referenced artifacts and
seven inherited receipt links matched. All five
[final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37698873778)
and all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37699966443)
passed. Preserve 13,683 portable and 70 native tests, 2/2 ordinary and 2/2 separate
robustness completions, zero unnecessary refusals, 24/24 blocked destinations,
120/120 boundary fields and 63 accepted-bundle replays. Accepted main now has
**33 profiles using 14 programs**. C8 stays closed; private review receipt:
`.secure-agent/pr62-merge-review.json`.

**Historical pre-merge snapshot (before PRs #80/#81): PR #79 is merged; C18/T01 stays accepted. Its four T02
production profiles remain candidates. PR #80 validates the acceptance corpus;
G6 review/checks and authorized merge remain pending. The separate T03 candidate
in PR #81 follows in review order; accepted coverage stays 43 profiles/16 programs.**
[PR #72](https://github.com/0xsl0th/recon-cockpit/pull/72) merged as
`e00482409362f1f9380bc225063b84762446dee9` after fresh authority/runtime and
parser/evidence reviews found no blockers and all five final PR checks passed. All five
[post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37816689999)
also passed. Reviewed head `407f48f` and the merge have the same tree
`5bfb8d52f06d486a513ffc429d0418cb7f94b764`. That merge brought accepted coverage
to **42 bounded secure profiles backed by 16 external programs**. C17's G1–G6 remain closed.

The [consolidated product roadmap](product-roadmap.md) separates today's verified
capabilities from the professional-v1 release and the longer-term 40+ program
product. Its planning estimates are **40–60 further PRs for an operator-assisted
professional v1**, and **80–130 total further PRs for the broader product**.
These are scoped engineering forecasts, not completion percentages, approval of
deferred work or a claim that every catalog profile is available through the GUI.
[PR #73](https://github.com/0xsl0th/recon-cockpit/pull/73) accepted the forecast at
`993c83d` from reviewed head `44b479b` after review and all five final CI jobs
passed. All five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37818772689)
also passed; reviewed and merged trees match. Private merge receipt:
`.secure-agent/pr73-merge-review.json`.
The owner agreed the plan and authorized continued coverage work. The new
[finite task checklist](professional-v1-coverage.md) maps accepted exact profiles
and fixes six required operator outcomes; T01 is accepted and T02–T06 remain
open. Candidate engines are not accepted
integrations or a program-count quota.

C17's [runbook](nuclei-git-tools.md) records one fixed GET of `/.git/HEAD` and two
finite synthetic markers. No returned-ref follow-up, repository/source/object
download or credential retrieval occurs; useful observations do not verify
vulnerability or repository exposure.
Preserve **19,437 portable and 44 native passes**, 4/4 ordinary and 1/1 robustness
completions, eight inconclusive negatives, zero unnecessary refusals, 26/26 blocked
destinations, 195/195 boundary fields and **133 unchanged bundle replays**
(13 new and 120 previously accepted). Sixteen inherited receipts and the frozen
290-case/41-adapter/32-runtime predecessor baseline remain unchanged.

All 705 source hashes matched native revision `901faab`; only six documentation
files changed before final reviewed `407f48f`. Fresh review passed 1,466
runtime/authority tests and 318 parser/evidence tests; these focused sets overlap
prior validation and are not an additional aggregate. Scenario wall time was
4528–6393 ms, median 4561 ms, with zero provider calls/cost. This is descriptive
timing, not comparative overhead. The missing-module refusal, first failed native
matrix and corrected nonvacuous isolation tests remain recorded separately.

Private immutable verification: `.secure-agent/nuclei-git-20261008/verification.json`,
SHA-256 `6721ac99867de7e57d6cc06035e65e923c690831087098015650d2b0df1868c6`.
Merge review: `.secure-agent/pr72-merge-review.json`. The original C17 handoff is
historical and remains unchanged; the merge receipt supersedes its open-PR status.

**C18/T01 DNS MX is accepted**, using the existing dig runtime,
one fixed nonrecursive TCP question and at most four typed rows. Null-MX, NODATA
and NXDOMAIN have useful distinct meanings; no returned-host follow-up or mail
operation is allowed. Accepted main now has **43 profiles/16 programs**.
See the [C18 runbook](dns-mx-tools.md).

**G1–G5 passed locally:** 19,888 portable and 37 native checks; 5/5 ordinary
plus 1/1 robustness completions, seven inconclusive negatives, zero unnecessary
refusals, 26/26 blocked destinations and 130/130 boundary fields. All 133 accepted
bundles and the seventeen-link receipt chain remain intact. The
[runbook](dns-mx-tools.md) records source pins, the twelve fresh DNS regression
replays, descriptive latency and the terminal-test correction. **G6 is closed:**
[PR #74](https://github.com/0xsl0th/recon-cockpit/pull/74) merged reviewed
`043aa543` as `b1afbbab` with an identical tree after fresh review, 407 focused
tests and all five final CI jobs passed. All five
[post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37834481139)
also passed; preserve `.secure-agent/pr74-merge-review.json`. Accepted main has
43 profiles/16 programs.

**T02 feasibility, the initial diagnostic and mediation are accepted in PRs #75–#77;
[T02 itself remains open](tls-posture-observations.md).**
Stock sslscan loses the received rejection evidence needed for the task. Preserve
the initial OpenSSL diagnostic's **0/1 retry-prevention failure** unchanged.
The new mediated diagnostic on frozen source `4d92d1d` produced **8/8 ordinary
observations, 4/4 explicit received rejections and 1/1 HRR retry prevented before
peer delivery**. The independent peer observed one ClientHello; the complete
282-byte second record was withheld. All thirteen trials closed and passed the
new Unix-socket boundary witnesses, with zero provider calls/cost.
The mediator validates plaintext framing and encrypted record shapes, without
decrypting or claiming general encrypted application-data prevention.

PR #78 accepted the [closed observation/replay slice](tls-posture-observations.md),
providing bounded networkless diagnostic parsing with no new execution authority.
PR #79 adds four separately versioned [production candidates](tls-posture-tools.md)
through policy, fresh per-action approval, consumed permits, admission and both
production evidence inspectors. These candidates require their own production
evidence; the earlier diagnostic receipts do not substitute for authority gates.
PR #80 validates hostile-usefulness, ambiguity/pressure, enforcement, cancellation
and regression with 65 native and 21,593 portable passes. G6 review/checks and
authorized merge remain pending before accepting T02.
Accepted coverage remains **43 profiles / 16 programs**. Nothing was installed;
the already-installed sslscan still has no secure integration.
Continue through required T03–T06 using the
[finite checklist](professional-v1-coverage.md); do not remove difficult outcomes
or substitute program counts for useful coverage. Existing closed milestones stay
closed. Deeper workflows, comparative benchmarks, real credentials, attached or
external networks and paid/live models remain deferred under their existing gates.

**C16 accepted in [PR #71](https://github.com/0xsl0th/recon-cockpit/pull/71).**
The separate pinned Nuclei runtime and owned directory-listing check bring accepted
coverage to **41 secure profiles using 16 external programs**. These are bounded
operations, not 41 independently integrated programs or professional deployment
certification. The [feasibility assessment](nuclei-feasibility.md) remains accepted
in PR #70 at `2f7fb5a`; this implementation followed the operator's authorization.

Reviewed production head `45035fa` received fresh runtime/authority and
parser/evidence reviews with no blockers. Final head `853f5a1` merged as
`1cfbf8bf79ca1825d9d7904fed6daad831f8abd9` on 8 October at 05:49:55 UTC after all
five [final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37733763140)
passed; all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37734361577)
also passed. Reviewed and merged trees match `aef6d051c95e433cdf05c7c395420e511a8010cc`.
Production bytes match native-tested `5fe5c34`. The review reconciled 694 source
hashes, 120 reports, 135 artifacts and fifteen inherited receipt links; all
thirteen current captures reparsed identically. Private merge receipt:
`.secure-agent/pr71-merge-review.json`.

The [C16 runbook](nuclei-tools.md) records one compiled directory-listing signature
check: one GET to the disconnected owned `127.0.0.1:8080/public/` fixture, with no
follow-up. The pinned v3.11.1 static executable is privately provisioned; its
separate runtime has 8 MiB/128-inode scratch, 64 KiB per-file tool writes, 16 tasks,
2 GiB address space, five CPU/tool seconds, a 60-second session and 8192 captured
bytes. The trusted outer staging ceiling is separately 160 MiB. Accepted runtime
limits and byte snapshots stay unchanged. No build/toolchain upgrade is added.

Completion requires one validated owner GET, closed connection, complete original
owner response bytes and a complete native response dump. The independent parser
checks both framing forms, reconciles status/body and recomputes the exact matcher.
A false matcher or successful exit alone is insufficient. Matched and unmatched
results are signature observations, never verified vulnerabilities or site safety.

**Local validation:** implementation `5fe5c34` passed 21 native workflow/authority
checks; two additional Linux sealing checks also passed. The thirteen actual
trials achieved 4/4 ordinary and 1/1 robustness completions, with eight inconclusive
negatives, zero unnecessary refusals, 26/26 blocked destination witnesses and
195/195 boundary fields. All 107 accepted bundles replayed identically without
changing bytes, mtimes or modes. The 277-case/40-adapter/31-runtime baseline is
unchanged. Trial wall time was 4477–6405 ms, median 4522 ms; provider calls/cost
were zero. This is descriptive timing, not comparative overhead. All **18,958
portable tests passed**, with zero skips, failures or errors. G1–G6 are closed
by the reviewed and checked PR #71 merge; C16 stays closed.
Private receipt: `.secure-agent/nuclei-runtime-20261008/verification.json`.

Initial development probes exposed the inherited staging limit, a missing worker
fixture module, two native default request headers and counter-only closure
assembly. Each was corrected within the approved boundaries. The initial full
portable run found two stale additive registry/tag expectations; these were
corrected, and the complete rerun is retained. No limit was raised beyond the
approved Nuclei-specific design, and no failed probe counts as useful work.

C17 was subsequently authorized and is now accepted as recorded above. C16 and
earlier completed milestones remain closed; its fixed template, original owner
response evidence and runtime limits remain regression anchors. Preserve the
proposal/PDF, GUI mocks and earlier unexplained C9 stall and failure history.

**C15 is accepted in [PR #69](https://github.com/0xsl0th/recon-cockpit/pull/69).**
Reviewed head `ca88e2f` merged as `e4c9d645ead8f02bbc0603f8731cef0e46ee3b86`
on 8 October at 03:32:40 UTC after fresh independent runtime/authority/fixture and
parser/evidence reviews found no blockers and all five
[final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37722279228)
passed. All five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37723229406)
also passed. Reviewed and merged trees match `72eb7947f5b08974fe799a45fefc813db8e36536`.
All 603 frozen source hashes, 115 reports, 130 artifacts and fourteen inherited
receipt links reconciled. Preserve **18,396 portable and 39 native passes**,
3/3 ordinary and 1/1 separate robustness completions, eight inconclusive negatives,
zero unnecessary refusals, 24/24 blocked destinations, 120/120 boundary fields and
**103 unchanged accepted-bundle replays**. Scenario wall time was 2688–7001 ms,
median 3123 ms, with zero provider calls/cost. Two initial test-only assertion
failures and their corrections remain recorded; production source was unchanged
before confirmation. C15 stays closed at 40 profiles/15 programs. Its finite
OpenSSL grammar, CN fallback, prefix counters, unseen wire data and historical
trust/expiry limitations remain in the [C15 runbook](tls-certificate-tools.md).
Private merge receipt: `.secure-agent/pr69-merge-review.json`.

**C14 is accepted in [PR #68](https://github.com/0xsl0th/recon-cockpit/pull/68).**
The reviewed candidate merged as `a6f11b7eea0b28c0e5bb7191e62793624d9d5378` after
independent review and all five [final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37718482035)
passed; all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37719116743)
also passed. Preserve **17,728 portable and 44 native tests**, 4/4 ordinary and
2/2 separate robustness completions, eight inconclusive negatives, zero unnecessary
refusals, 28/28 destination and 140/140 boundary fields, and **97 unchanged accepted
bundle replays** with thirteen inherited receipt links. All 593 frozen sources
matched implementation `80b2ffe`; six useful receipt rows reused original native
evidence. Scenario wall time was 2588–4739 ms, median 3159.5 ms, with zero provider
calls/cost. C14 stays closed at **39 profiles using 15 programs**. Its half-close,
unretained random cookie, finite advertisement grammar and unread trailing-packet
limitations remain in the [C14 runbook](ssh-algorithms-tools.md).

**C13 is accepted in [PR #67](https://github.com/0xsl0th/recon-cockpit/pull/67).**
Reviewed head `ae34672` merged as `7cc66451295d1e5013fff31e753d01a79ccaf53c`
on 8 October at 02:00:21 UTC after independent reviews and all five
[final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37715182741)
passed. All five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37715717067) also passed. Preserve **16,687 portable
and 43 native tests**, 4/4 ordinary and 2/2 robustness completions, eight
inconclusive negatives, zero unnecessary refusals, 28/28 destination and 140/140
boundary checks, and 91 unchanged accepted-bundle replays with twelve inherited
receipt links. All 583 frozen source files matched implementation `331ae06`.
Native scenario wall time was 2554–4558 ms, median 2996.5 ms, with zero provider
calls/cost. Six useful receipt rows reused original native evidence without
another tool execution. C13 stays closed at **38 profiles using 15 programs**;
its native text-capture and finite successor limitations remain in the
[C13 runbook](snmp-next-tools.md). Synthetic grants do not claim personal acceptance.

**C12 is accepted in [PR #66](https://github.com/0xsl0th/recon-cockpit/pull/66).**
The reviewed candidate merged as `7faf974f5e0bbc917ef5d8b6ee70164478524ef4` after
all five final CI jobs passed; the [post-merge run](https://github.com/0xsl0th/recon-cockpit/actions/runs/37713341040)
also passed. Preserve **16,138 portable and 40 native tests**,
6/6 ordinary and 2/2 robustness completions, six inconclusive negative cases,
zero unnecessary refusals, 28/28 blocked destinations, 140/140 boundary fields and
83 unchanged accepted-bundle replays with eleven inherited receipt links. The 574
source bindings reconciled with two AST-identical comment corrections recorded.
C12 remains closed with **37 profiles using 14 programs**. Its finite authentication
grammar and curl capture limitations remain documented in the
[C12 runbook](http-options-tools.md); the earlier C9 stall remains unexplained.

**C11 is accepted in [PR #65](https://github.com/0xsl0th/recon-cockpit/pull/65).**
Reviewed head `40197b6` merged as `82dd85a` on 8 October at 01:03:14 UTC;
reviewed and merged trees match `840c25b76d25469556320bb7b16000a5f5e33099`.
Fresh authority/runtime and parser/evidence reviews found no blockers; all 566
validated source hashes, 97 reports, 112 artifacts and ten inherited receipts
reconciled. All five [final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37709477319)
and all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37710962147)
passed. Preserve **15,464 portable and 61 native tests**, **3/3 ordinary and 2/2
robustness completions**, zero unnecessary refusals, nine inconclusive cases,
28/28 blocked destinations, 140/140 boundary fields and 78 unchanged accepted-bundle
replays. C11 remains closed with **36 profiles using 14 programs**. Dig's native
capture limitations and the unexplained earlier C9 stall remain recorded.
Private merge receipt: `.secure-agent/pr65-merge-review.json`.

**C10 is accepted in [PR #64](https://github.com/0xsl0th/recon-cockpit/pull/64).**
Reviewed head `964d600` merged as `dea8c7a` on 8 October at 00:25:00 UTC;
reviewed and merged trees match `5ba1c32671aa72821f0ef97983ec36618f0b13b2`.
Fresh authority/runtime and parser/evidence reviews found no blockers; 362 focused
tests passed. All 557 source hashes, 92 reports, 107 artifacts and nine inherited receipt
links reconciled.
All five [final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37706257697)
and all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37707653540)
passed. Preserve 14,814 portable and 62 native tests, 5/5 ordinary and 1/1 separate
robustness completions, zero unnecessary refusals, 28/28 blocked destinations,
140/140 boundary fields and 72 unchanged accepted replays. The initial historical
snapshot-test selection failure and correction remain recorded; no production or
selected native-test file changed. C9's earlier stall cause remains unresolved.
C10 stays closed with **35 profiles using 14 programs**. Private merge receipt:
`.secure-agent/pr64-merge-review.json`.

**C9 is accepted in [PR #63](https://github.com/0xsl0th/recon-cockpit/pull/63).**
Reviewed head `f91d9d3` merged as `e06e1a4` on 7 October at 23:42:45 UTC;
reviewed and merged trees match `d909db662eee3c31945550994ee3d7819af11cf4`.
Fresh authority/runtime and parser/evidence reviews found no blockers; 351 focused
tests passed. All 548 validated source hashes, 83 reports, 98 referenced artifacts
and eight inherited receipt links matched. All five
[final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37702693909)
and all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37703801916)
passed. Preserve 14,231 portable and 65 native confirmation tests, 2/2 ordinary
and 3/3 separate robustness completions, zero unnecessary refusals, 22/22 blocked
destinations, 110/110 boundary fields and 67 accepted-bundle replays.
The initial legacy OpenSSL stall failure remains unexplained; successful unchanged
reproduction and confirmation do not establish resolution. C9 stays closed with
**34 profiles using 14 programs**. Private receipt: `.secure-agent/pr63-merge-review.json`.

Each batch records useful completion and unnecessary refusals as well as blocked
unauthorized attempts, request counts, elapsed time and zero provider cost. A normal
case blocked by confinement fails G2. Review the next remaining capability gap after
each batch; do not grow dictionaries, workflows or benchmark scope to fill time.

## Completion gates for every required capability

1. **G1 — explicit authority.** Versioned strict parameters, fixed reviewed
   invocation, executable/data pins, effects and limits; policy denial plus all
   approval/audit/admission gates tested. No arbitrary argv, plugins, shell,
   uncontrolled configuration, environment or target selection.
2. **G2 — actual useful execution.** The real executable (or named native adapter)
   completes an independently invoked normal case in the disconnected owned lab.
   Known negative/absent results have distinct semantics. Missing prerequisites,
   skipped execution, a descriptor or a mock cannot satisfy this gate.
3. **G3 — structured results.** Bounded stdout and stderr feed a confined parser;
   finite validated fields represent the useful result. Malformed, partial,
   oversized and hostile output cannot invent findings or expand scope. A
   validated tool report is labelled as such wherever the client cannot establish
   the underlying fact; it must not be promoted to a verified finding.
4. **G4 — evidence.** Save private raw artifacts and runtime/action/policy bindings;
   independent read-only replay agrees with normalized results, tampering is
   rejected, and dry runs never claim execution. Published docs contain accurate
   limitations, not private transcripts or credentials.
5. **G5 — enforcement and cleanup.** Verify real network/file/process restrictions,
   approval/permit replay refusal, deadlines, cancellation, output/resource limits
   and lab closure. Preserve existing accepted profiles and their regression tests.
6. **G6 — reviewed handoff.** Record exact source, tests, actual execution receipts,
   result and request counts, elapsed time and limitations; obtain independent
   review, pass applicable checks, and merge under the operator's instruction.
   The roadmap/checkpoint then identifies the next unchecked tool row.

The milestone completes only when **every required row B0–B8 satisfies G1–G6**
and no required row remains unverified, blocked or review-pending. This is bounded
core tool coverage, not professional deployment acceptance. Broader dictionaries,
targets, authentication and intrusive capabilities need their own subsequent scope.

Per-tool verification records legitimate completion, unnecessary refusals,
unauthorized execution attempts/results, protocol request counts, output bounds,
cleanup and descriptive elapsed time. Normal work blocked by the boundary fails
G2. Provider calls and actual cost must remain zero. These checks continue now;
**deeper workflow composition and comparative/paired benchmarking wait until the
coverage milestone is complete**. Existing accepted comparisons remain closed.

## Gate reconciliation — accepted B0–B8

The accepted runbooks and [verification record](verification.md) retain each
batch's source, actual executions, negative cases and private receipts. Earlier
accepted evidence was preserved; the final PR #45 review independently replayed
all 24 saved B1–B8 bundles without changing bytes, modes or mtimes.

| Gate | Closure evidence and limits |
| --- | --- |
| G1 | Each registered capability has a fixed versioned action, parameter validation and authority profile. B8 review additionally recomputed 35 policy-denial cases through admission and native launch consumption. Interactive host commands remain outside this claim. |
| G2 | Every required capability has actual useful disconnected owned-lab execution in its accepted batch. B8 completed both legitimate reporting tasks, with zero unnecessary refusals; its spoof case is counted separately. No mock or skipped run substitutes for execution. |
| G3 | Confined parsers produce bounded structured observations with explicit semantics. Kerbrute's `tool_report_only`/`authentication_verified: false` fields mean a faithful client report, not verified principal existence/absence. SMB ambiguities remain inconclusive; complete unmatched Nmap scans remain explicitly unidentified by the finite probes. No accepted observation grants follow-up authority. |
| G4 | Private raw artifacts and action/policy/runtime bindings support independent replay. All 24 final saved bundles replayed unchanged. Hashes establish local consistency, not protection against a malicious host owner. |
| G5 | Each batch passed applicable actual Linux confinement, request/output/resource bounds, gate refusal and cleanup checks. B8 added UDP/task-limit witnesses and blocked all six clean-trial forbidden-destination probes. Earlier accepted profiles remain regression anchors. |
| G6 | B0's accepted baseline and PRs #38–#45 have independent reviews, passing checks and operator-authorized merges. PR #45's reviewed head `9edec213` and merge `47d70a2` have identical trees. No required row remains review-pending. |

This closure concerns the documented bounded capabilities. It makes no claim of
semantic immunity to every malicious service response, arbitrary executable-mode
coverage, real-model acceptance or external engagement readiness. The catalog
follow-on is a usability change and does not reopen these accepted contracts.

## Product scope after core coverage

Professional use ultimately includes discovery, enumeration, validation,
explicitly enabled exploitation, post-access work, cleanup and reporting. The
checklist covers the core enumeration portion. Remaining categories include
broader authenticated web/API testing, database/SNMP assessment, Windows/AD
credentials and sessions, vulnerability-specific validation, exploitation,
post-access actions and external engagement routing. They are visible product
gaps, not capabilities established by this milestone.

Additional executable candidates such as recursive crawlers, vulnerability
scanners, database clients and exploitation frameworks require a later named
selection and capability review; a tool-name quota is not permission to expose
all of their functions. Existing interactive NetExec, ssh and feroxbuster modes
also remain distinct later integration work where they exceed the checklist.

Model credentials, paid calls, provider funding and live-model evaluation remain
deferred until much later. Real service credentials, external targets and
intrusive/authenticated activity retain their explicit authorization boundaries.
Owned synthetic fixtures are development evidence, not permission to assess a
third party. Keep the local proposal PDF unchanged until its planned revision;
competition submission and publication remain separate decisions.

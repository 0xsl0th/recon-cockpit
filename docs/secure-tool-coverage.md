# Secure-tool coverage milestone

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

Priority 3 follows the accepted initial GUI. Accepted main has **25 bounded profiles
from 13 external programs** after C1 in PR #55. Installed binaries and interactive
commands do not satisfy secure coverage. The following rows distinguish existing
integration from a candidate secure profile.

| Order | Capability gap and present support | Completion criteria | Status |
| --- | --- | --- | --- |
| C1 | Redis server metadata; redis-cli, no interactive menu integration | One RESP2 INFO server, four selected typed fields, no authentication/key access/writes/cluster follow-up; actual useful execution, error/hostile/bounded-output cases, replay and G1–G6. | [x] Accepted in PR #55. |
| C1 | SNMP system metadata; snmpget, no interactive menu integration | One v2c TCP GetRequest of three fixed system OIDs with public synthetic community; complete typed values/noSuchObject, no walks/writes/UDP/custom community; actual useful execution, adversarial cases, replay and G1–G6. | [x] Accepted in PR #55. |
| C2 — current | PostgreSQL pre-authentication TLS; existing secure OpenSSL runtime, no interactive database integration | One fixed SSLRequest followed by fixture-CA/name-verified TLS 1.3 and clean close without application data; structured handshake-only evidence, refusal/untrusted/malformed/stalled/injected cases, replay and G1–G6. No startup/login/SQL/readiness claim. | Candidate; actual execution, review and merge pending. |
| C2 — current | MySQL pre-authentication TLS; same existing OpenSSL runtime, no interactive database integration | Read one bounded initial greeting, send fixed SSLRequest, verify TLS 1.3 and close without application data; hostile greeting version remains inert, no account/auth-plugin/login/SQL operation; honest fragmented-greeting limitation, replay and G1–G6. | Candidate; actual execution, review and merge pending. |
| C3 — next | HTTP application fingerprinting; WhatWeb installed, no interactive or secure integration | Review a finite allowlisted plugin set, runtime dependencies and one-origin request bounds first; then actual useful owned execution, structured untrusted observations, hostile/redirect cases, evidence and G1–G6. Missing prerequisites or unbounded defaults must fail closed. | Planned; no execution capability claimed. |
| Later | Broader Windows/AD, authenticated SSH/LDAP/SMB, SQL readiness/queries and real SNMP deployments | Separate credential/session and engagement-scope design with relevant authorization, plus exact operation contracts and G1–G6. Existing interactive suggestions do not satisfy this row. | Deferred boundary work. |
| Later | Additional web discovery/scanning engines | Evaluate incremental coverage beyond accepted ffuf/HTTP profiles before selecting a finite operation and corpus; no arbitrary plugins/templates/crawling. | Optional; deeper composition and comparison deferred. |

C1 is closed: its Redis/SNMP metadata remains `untrusted_service_report`, and
TCP SNMP does not establish UDP coverage. C2 reuses the existing single-action
authority, OpenSSL runtime, strict TLS parser and evidence infrastructure. It adds
two profiles, bringing the candidate to **27 profiles from the same 13 programs**,
pending acceptance. The selected database wire protocol is a contract binding;
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

# Secure-tool coverage milestone

Current priority, selected by the operator on 1 October 2026: broaden independently
usable secure tools before composing deeper workflows or running comparative
benchmarks. This milestone stays open across successive implementation batches.
Finishing one batch selects the next coverage gap, not a workflow project.
Completed offline R5 and accepted local R6 remain closed.

[PR #38](https://github.com/0xsl0th/recon-cockpit/pull/38) merged as `5436dd6`: B1
DNS/TLS is accepted. [PR #39](https://github.com/0xsl0th/recon-cockpit/pull/39) contains
the locally verified B2 SSH/LDAP batch, followed by
B3 anonymous SMB share metadata. Main has 8 secure capabilities backed by 5 external
programs; B2 adds two locally verified capabilities/programs, pending review/merge.
It is not yet counted as accepted main coverage.

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
| dig | New integration candidate; no current menu command | None | Fixed nonrecursive DNS record query; current batch. |
| OpenSSL | New integration candidate; no current menu command | None | Structured verified TLS handshake metadata; current batch. |
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
| B2 — current | SSH host keys with ssh-keyscan | [ ] Verified locally; review/merge pending | One fixed key type and endpoint; validate bounded key/fingerprint output; no login or trust-on-first-use claim. |
| B2 — current | LDAP RootDSE with ldapsearch | [ ] Verified locally; review/merge pending | Anonymous base query with fixed attributes; structured entries; referrals, arbitrary DNs and user enumeration disabled. |
| B3 | SMB share metadata with smbclient | [ ] Planned | Anonymous finite listing against owned SMB; no credential discovery, file retrieval, writes or remote execution. |
| B4 | RPC program metadata with rpcinfo | [ ] Planned | Bounded read-only query to owned rpcbind; results never authorize connections to advertised endpoints. |
| B4 | NFS export metadata with showmount | [ ] Planned | Bounded export listing against owned mount service; no mounts or reads from exports. |
| B5 | Anonymous FTP listing with curl | [ ] Planned | Fixed passive control/data bounds and one finite listing; no uploads/downloads or unapproved passive destinations. |
| B5 | SMTP advertised capabilities | [ ] Planned | Reviewed Nmap script closure or a narrow native adapter, selected when this batch starts; bounded banner/EHLO/QUIT, no message or account probing. |
| B6 | Docker API metadata with curl | [ ] Planned | Fixed read-only health/version endpoints; bounded structured JSON; no container lifecycle, filesystem or command endpoints. |
| B6 | WinRM endpoint metadata with curl | [ ] Planned | One fixed unauthenticated endpoint response; report status/authentication schemes; no login, SOAP operations or shell. |
| B7 | Nmap service identification | [ ] Planned, closure review required | Finite reviewed service probes and any implicit NSE/version behavior must be explicitly pinned and constrained; preserve the old TCP-only profile. No generic `-sV` switch without that review. |
| B8 | Kerberos principal enumeration with kerbrute | [ ] Planned, owned KDC prerequisite | Fixed short synthetic principal list, bounded requests, structured exists/unknown results, no passwords, spraying, ticket extraction or real directory. |

Batch order follows missing protocol families and existing interactive precedents,
then runtime/fixture complexity. At each batch handoff, compare the remaining
unchecked rows and prioritize the next tool gap. Change the order with a recorded
reason if prerequisites or findings warrant it. Do not silently delete, waive or
move a required row to deferred work to claim milestone completion. Keep each PR
small enough for an independent review; stop a tool on unsupported prerequisites
without falling back to the host runner. A blocked tool does not complete its row.

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
   oversized and hostile output cannot invent findings or expand scope.
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

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
[PR #56](https://github.com/0xsl0th/recon-cockpit/pull/56), bringing main to **27 profiles
using the same 13 programs**. Local validation
passed 10,776 portable and 28 native Linux tests; both ordinary TLS tasks completed
with zero unnecessary refusals, and all 24 forbidden-destination witnesses blocked.
Each database recipe stops after a verified fixture TLS handshake
and clean close, without credentials, login or SQL.

The current C3 [WhatWeb candidate](whatweb-tools.md) adds one passive HTTP
fingerprint profile, bringing this branch to **28 profiles using 14 programs**.
Its recipe permits one fixed GET with five exact plugins and no redirects,
credentials or follow-up. Ruby supports the WhatWeb runtime and is not separately
counted as an assessment program. All 11,109 portable and 39 selected native tests
passed. Independent trials completed 2/2 ordinary and 2/2 robustness tasks with zero unnecessary
refusals, blocked 8/8 forbidden destinations and replayed 36 accepted bundles
unchanged. Final review, hosted checks and merge remain acceptance gates; this
candidate is not yet counted as accepted main coverage.

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
principal, so these reports do not verify existence or absence. SMB's ambiguous
empty/denied/malformed replies remain inconclusive. Nmap's unidentified result
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

The B0–B8 [coverage checklist](secure-tool-coverage.md) is closed under those
accepted limits. The original catalog was accepted in PR #46 at `0d5cbdc`;
its recipes retain their accepted behavior. The separately versioned
[Nmap service → ffuf → headers workflow](service-web-assessment.md) and
[configurable owned-lab slice](configurable-owned-lab.md) remain distinct from
the current C3 candidate. Further composition and comparative benchmarking
remain later work. Model
credentials, paid calls and live-model evaluation stay deferred until much later.

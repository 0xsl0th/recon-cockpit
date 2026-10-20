# S3.7: combined finite compatibility and routing acceptance

PR [#98](https://github.com/0xsl0th/recon-cockpit/pull/98) accepted S3.6b at
`c71b599643b713139ea28390063b7730837ac203`. Its tree
`6a4384431669ebc604c0b5b6878dcdee67892577` is identical to reviewed
`05719b3176ee637125f45c5ed11c0de14f6dc09f` and the five passing CI checkouts.
S3.6 is closed. Stage 3 has nine accepted logical increments and one remaining;
the thirteen-PR estimate includes twelve accepted PRs, #87–#98, and this S3.7
slice. S3.7 remains open until its evidence, independent review and required
checks are complete and accepted.

This contract is pinned before implementing the additional inspection path or
running the combined evidence validation. The accompanying
`stage3-combined-acceptance-gates.json` names every reused native test identity,
selected run and current saved bundle. Counts are checks on those inventories,
not substitutes for exact identity or evidence. No additional native case is
invented merely to mark a new milestone.

## Required combined outcomes

The governing [Stage 3 contract](stage3-compatibility-routing.md) requires the
finite HTTP/SSH/DNS routing and selected TLS name/trust subset together. Here
“together” means one complete, reviewed acceptance map and evidence packet for
the already declared profiles. Each original action still needs its own
authority. The routed HTTP/SSH owner and the DNS/HTTP/TLS owner remain separate;
this slice adds no combined owner, topology, automatic planner or new grant.

| Requirement | Evidence that must agree |
| --- | --- |
| S37-01 — preserve the catalog | All 52 pre-S3.6 profiles and their parameter/recipe semantics remain intact. Record the three S3.6b profiles as accepted: 55 profiles, zero candidates, 17 external programs. A name/TLS description still has no prebuilt live binding or executable catalog recipe. |
| S37-02 — useful HTTP and SSH | The complete routed nginx/Apache A/B corpus, both baseline action orders and the earlier v1/v2 coverage retain their expected native observations. Required ordinary and hostile cases in the selected passing runs have useful completion and zero unnecessary refusals. |
| S37-03 — correct negatives | Native transport/response negatives and aggregate-budget stops retain their exact classification and preceding useful work. Intentional default-approval refusals are separate outcomes; a missing metric is not silently converted to zero. |
| S37-04 — routed destinations and budgets | Distinct owned service namespaces, controlled links, denied other-service/excluded endpoints, irreversible shared allowances and restart/split-action enforcement remain proven by the exact routing gates. |
| S37-05 — names and trust | The complete A/B DNS/HTTP/TLS corpus retains eligible binding, generation/expiry checks, Host/SNI/certificate-name/trust agreement, changed/excluded/ambiguous/undeclared-name refusal and no redirect/referral follow-up. |
| S37-06 — authority and custody | Exact action/approval/audit/admission binding, sealed source/runtime custody, role and socket restrictions, bounded parsing and physical process ownership retain their native enforcement gates. |
| S37-07 — lifetime and cleanup | Cancellation, deadline clipping, owner close, stale/foreign grants, parser cleanup and closed sockets/processes retain their exact gates and physical evidence. The two N15 composites additionally gain a bounded saved-evidence CLI path. |
| S37-08 — unchanged replay | Reinspect the 234 selected current standard bundles and two N15 composites through Python and CLI: 472 inspections. Retain the separately pinned 120 legacy inspections of 60 original v1/v2 bundles. Every original byte, mode and modification time stays unchanged. |
| S37-09 — source and runtime continuity | Reused execution, authority, parser, native-test/helper, sealed-source and installed-runtime bytes must match the accepted evidence. The explicit metadata/documentation exceptions below cannot alter those contracts. |
| S37-10 — prerequisites and limits | Document the supported Linux execution/inspection prerequisites, fixed runtime identity and fail-closed unsupported behavior. Keep remaining compatibility gaps visible. |
| S37-11 — failure provenance | Preserve the original failed B16 DNS attempt and reverse-order Apache/A SSH identification attempt, plus their reviews and diagnostic/follow-up receipts. Neither later passes nor diagnostic observations establish an unexplained cause or fix. |
| S37-12 — final review and checks | Independently review the combined map, outcome derivation, immutable replay and metadata changes. Complete the local portable suite and all five Linux/macOS CI jobs at the final reviewed head, without failures, errors or skips. |

## Evidence reuse and new validation

The accepted S3.6b audit is `final-validation-05719b3.json`, SHA-256
`4bb875a10c358607952b0fe9e43f5f43ebc03462e32daee0105a4772c4d78c02`.
It verifies **651 distinct native identities**: 327 name/TLS gates plus 248
routing and 76 accepted-profile/witness regressions. The retained routing group
uses the single predeclared complete 88-case follow-up; its original 87/88
failed attempt remains a separate, mandatory provenance input. Diagnostics
contribute no native cases, useful completions or acceptance inspections.

Reuse requires exact source/runtime continuity, the accepted source/merge/tree
relationship, exact collected/completed identities, passing selected receipts
and unchanged referenced artifacts. Inspect the original executable modules,
native tests/helpers, fixtures, parser closure and installed files; do not infer
continuity merely from a green CI badge or matching totals. Existing native runs
need no repetition solely because the milestone or catalog label changes.
An execution-affecting change requires a separately reviewed affected-gate plan
before execution; it cannot inherit this reuse decision.

The implementation may add this contract, its exact inventory, a separate
read-only inspection module/CLI and its portable tests, and update explicit
roadmap/catalog/status documentation. The only changed existing product module
is `tool_catalog.py`, which is absent from the sealed launcher/name-TLS source
closure. Only the exact portable test files listed in the inventory may change
their current catalog acceptance-label/count assertions; their historical
52-profile projections and pinned hashes remain unchanged.
Do not change `tool_adapters.py`, the stable name/TLS family discriminator,
native tests/helpers, execution modules, source-closure inventories or version-1
saved-report wording. In particular, the historical word “candidate” in a v1
report remains part of its canonical immutable output; current catalog status
is recorded separately.

| Selected cohort | Standard bundles | Composite bundles | Fresh Python/CLI inspections |
| --- | ---: | ---: | ---: |
| Name/TLS core corpus | 52 | 2 N15 | 108 |
| Routing v3 matrix | 132 | 0 | 264 |
| Earlier routing v1/v2 from the selected retained group | 50 | 0 | 100 |
| **Current total** | **234** | **2** | **472** |

The 52 standard name/TLS bundles already have 104 Python/CLI replay checks in
their native tests. The 182 current routing bundles already have 364. The two
N15 composites have production-validator Python replay, but no CLI equivalent.
This slice records fresh, durable inspections for all 236 current identities and
closes that precise CLI gap. Do not add prior repeated inspections to the new
472 total. The 60 original legacy bundles form a separate retained cohort with
120 inspections and 516 unchanged files; reuse those receipts only while their
inspection closure and original bundle snapshots remain identical.

Pytest `*current` symlink aliases are not additional bundles. The nine routing
default-approval reports intentionally have `case_passed=false` and
`classification=incomplete`; their exact native test identities require refusal.
The acceptance map must identify them explicitly, check no action executed and
retain their original reports. Unexpected incomplete ordinary work fails the
combined check. Preserve null/not-applicable metrics as recorded.

## Additional inspection boundary

The new inspection path accepts saved data only. It may use the unchanged
isolated production parsers, but creates no fixture daemon, native client,
network topology, assessment owner, approval grant or provider call. It never
restores authority from a saved binding or ledger.

An N15 composite is a private regular file, at most 1 MiB, decoded with the
existing bounded name/TLS decoder and checked by the unchanged production
`validate_probe_evidence` function. Its three recorded owners and the actual
closed-owner/foreign-grant observations must validate together. The new wrapper
must reproduce the historical test inspector's report without importing test
helpers or treating their assertions as validation. It must reject malformed,
oversized, symlinked or changed input and preserve bytes, mode and modification
time. Output is a consistency result, not authentication of an unsigned bundle
against rewriting by its host owner.

Freeze exact input identities and snapshots before replay. Apply a 45-second
outer allowance to each fresh Python and CLI inspection, matching the existing
CLI allowance; N15's read-only composite inspection uses the same cap. The old
Python API replay ran inline and had no separate 45-second outer wrapper.
Existing production
parser deadlines and resource caps are unchanged. Run at most two inspection
workers, retain every outcome and do not silently retry failures. The combined
summary must account for all selected identities exactly once and preserve the
original reports alongside any separately named acceptance classification.

## Supported environment and remaining gaps

Native execution remains limited to the reviewed Linux x86-64 runtime and
disconnected A/B configurations in the accepted HTTP, SSH, routing and name/TLS
contracts. Required facilities include the documented user/network/mount/PID
namespace and bubblewrap boundary, seccomp notification, pidfds and process
start identities, descriptor custody, sealed runtime/source files and the fixed
installed client/daemon/parser dependency manifests. Missing or changed
prerequisites produce an unsupported/refused result; this slice installs no
packages, starts no host service and adds no fallback to the host network.
Saved inspection uses the existing Linux isolated-parser requirements where
applicable. Portable CI on macOS establishes portable behavior only.

The topology, endpoints, logical name, trust material, client argv, request
grammars, process roles and all action/owner/time/traffic/parser limits remain
unchanged. The other accepted tool families retain their finite fixture scope.
There is no attached lab/VPN/physical/engagement network, external route,
credentials, generated keys, recursive lookup, alias/redirect/referral chasing,
authenticated operation, paid/live model, broader service/version claim or
professional-v1 release acceptance. Stage 4 engagement, credential and session
custody, Stage 5 workflows, and later release gates follow the product roadmap
after Stage 3 is accepted.

## Validation status

The contract and exact inventory were committed at `adecfb3` before
implementation. The catalog now records accepted S3.6b status; 525 focused
catalog and dependent portable tests pass, with all 52 prior list entries and
complete descriptions/recipes byte-identical. The saved-composite wrapper and
CLI pass 54 portable custody, mutation, bounds and entrypoint checks.

Inspect a private saved N15 composite with
`python scripts/name_tls_composite_inspect.py /path/to/n15-composite.json`,
or call `name_tls_composite_evidence.inspect_composite(path)` from Python.
Neither entrypoint has an execution or approval mode. Ordinary name/TLS and
routing bundles keep their existing inspection commands and report schemas.

The combined validation at `931e693` passed **472 fresh inspections**:
236 exact current outcomes through Python and CLI. All source/runtime pins and
all 296 current/legacy input snapshots remained unchanged. The separately
retained legacy proof remains 120 inspections of 60 original bundles and 516
files; it is not added to the fresh 472 count. No native client, fixture daemon,
assessment owner, approval grant or provider was started by this replay.

Current outcomes are **102 completed, 92 expected negatives, 27 budget refusals
and 15 intentional approval refusals**. The 363 standard action rows contain
235 useful actions; the six embedded N15 DNS prerequisites are recorded
separately, without adding canonical cases. The nine routing approval-refusal
CLI calls correctly return 1 and reproduce their original false/incomplete
reports. Every other CLI call returns 0; each Python call returns its exact
expected report. Every inspection stayed within 45 seconds with at most two
workers, and no automatic retry occurred.

The measured native whole-case times below come from the selected original
evidence. They are not fresh replay timings, configured deadlines or comparative
benchmarks. The durable packet also retains per-case/action startup, teardown,
wire/reservation/refusal metrics and 193 separate cohort/outcome/field
distributions. Missing fields and explicit nulls remain missing/null. In
particular, all 52 standard name/TLS reports omit the `unnecessary_refusals`
metric, while 36 routing budget/default-refusal reports explicitly record null;
none is converted to zero. Nearest-rank percentiles are used.

| Cohort / outcome | Cases | Native whole-case ms (min–max) | p50 ms | p95 ms |
| --- | ---: | ---: | ---: | ---: |
| Name/TLS / completed | 16 | 9183–15499 | 12516 | 15499 |
| Name/TLS / expected negative | 30 | 843–13145 | 10502 | 13070 |
| Name/TLS / approval refusal | 6 | 808–10819 | 10722 | 10819 |
| N15 composite / expected negative | 2 | 31909–32270 | 31909 | 32270 |
| Routing v3 / completed | 56 | 9557–31084 | 11988 | 28855 |
| Routing v3 / expected negative | 60 | 10178–16646 | 11797 | 15436 |
| Routing v3 / budget refusal | 12 | 14327–18562 | 14980 | 18562 |
| Routing v3 / approval refusal | 4 | 1589–1717 | 1602 | 1717 |
| Current routing v1/v2 / completed | 30 | 10096–25773 | 11274 | 25685 |
| Current routing v1/v2 / budget refusal | 15 | 12826–15044 | 13381 | 15044 |
| Current routing v1/v2 / approval refusal | 5 | 1588–1675 | 1653 | 1675 |

N15 retains its separate original 200,000 ms whole-composite cap. No ordinary
case cap was raised. Original failures and diagnostics remain separately pinned
as required above; these selected outcomes do not relabel the failed attempts.

The replay receipt is
`.secure-agent/stage3-combined-acceptance-20261019/combined-replay-01/verification.json`,
SHA-256 `a06ae8bca63ef16b2cb52a6a5b936df6dd4989f6d3e3a4e02de3f1a6e016f28c`. Its `outcomes-and-metrics.json` and
per-entrypoint receipts retain exact reports, exit status, source/runtime/input
continuity and parser-process cleanup observations. Independent review checks
these against the original inputs rather than accepting aggregate counts alone.

The final reviewed head must also pass the complete **28,777-test portable
suite** locally and in all five Linux/macOS CI jobs, with no errors, failures or
skips. Those final-head receipts and reviews are retained in the same private
directory and linked from the PR. S3.7 and Stage 3 remain open pending acceptance
of the complete evidence and required checks; this validation does not begin
Stage 4 or establish professional-v1 release readiness.

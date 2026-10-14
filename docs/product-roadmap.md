# Product roadmap and remaining PR estimate

Current continuation (14 October 2026):
**T01–T04 meet G1–G6 and remain accepted and closed.**
[T04 PR #84](https://github.com/0xsl0th/recon-cockpit/pull/84) merged as `435a271`
after review of `40d98b6`, two independent reviews without blockers and 319 fresh
focused test passes. The reviewed and merged trees both match `9de7a974b3683d1abdfed9904b90932bb2be714c`.
All five [final PR checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/38577572315)
and all five [post-merge checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/38580423750)
passed. Its [accepted secure hierarchy runbook](web-hierarchy-tools.md) retains
26 native and 22,577 portable passes, the original frozen source pins and the
explicit native-retry/evidence-integrity limitations. T04 acceptance brings the
accepted baseline to **49 profiles across 16 programs**. Do not repeat its merge
or reopen earlier milestones.

**Current work is T05: one bounded SNMP interface-description page.**
The separate [T05 candidate](snmp-page-tools.md), open as
[PR #85](https://github.com/0xsl0th/recon-cockpit/pull/85), integrates `snmp_interface_page_v1`
through the existing secure execution and evidence path. One TCP GETBULK uses
one fixed ifDescr seed, zero non-repeaters and four maximum repetitions, with
public synthetic fixture data and no continuation. The catalog records
**50 registered profiles: 49 accepted and one T05 candidate, across 17 programs**.
Frozen native validation on `f6e515fe0292e7624a87ee3d0329abb7799e7374`
passed **51 tests**. Full portable validation on
`ae7e1b8fdb5309dd14e09850959b55e6c1eca6fe` passed **23,170 tests**, with 1,341
integration tests deselected and no failures, errors or skips. Each run preserved
all 735 recorded source files; only ten portable test files changed between
those revisions, leaving production code, policies and native tests identical.
Private proof belongs under `.secure-agent/snmp-page-20261014/`.
**G6 review and merge remain open; T05 is not accepted.** Review PR #85 and its
latest required checks before T06's separate fixed AAAA/PTR profiles;
do not replace either required outcome with optional signatures or tool quotas.

PRs #80/#81 (T02/T03), #82 (catalog/source review), #83 (T04 native diagnostic)
and proposal PR #31 remain closed. Proposal submission and its broader refresh
remain deferred to November. Model credentials, paid calls, live-model evaluation,
attached/external targets, deeper workflows and comparative benchmarking remain
deferred. The dated baseline and candidate wording below preserve historical
snapshots; this continuation supersedes their pre-merge status.

Historical pre-merge snapshot: **9 October 2026, after PR #79**, accepted main `5f4197f`.
The PR-count forecasts retain their explicitly dated PR #72 baseline below.
This is the consolidated product plan. The [implementation roadmap](roadmap.md)
retains milestone history; the [checkpoint](continue-here.md) records the next
authorized work. Estimates below describe future work, not accepted capability
or permission to start a deferred operation.

The owner agreed this plan and authorized continued coverage development.
[PR #73](https://github.com/0xsl0th/recon-cockpit/pull/73) merged reviewed head
`44b479b` after review and all five final CI jobs passed. All five
[post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37818772689)
also passed; reviewed and merged trees match. The private receipt is
`.secure-agent/pr73-merge-review.json`. The new
[finite coverage contract](professional-v1-coverage.md) maps **43 accepted
profiles across 16 programs** and fixes six required operator outcomes.
[PR #74](https://github.com/0xsl0th/recon-cockpit/pull/74) accepted C18/T01 DNS MX
after fresh review, 407 focused tests and all five final CI jobs passed. Reviewed
`043aa543` and merge `b1afbbab` have identical trees; G1–G6 are closed.
All five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37834481139)
also passed; receipt: `.secure-agent/pr74-merge-review.json`.
**T02–T06 remain open.** [PR #75](https://github.com/0xsl0th/recon-cockpit/pull/75)
accepted source feasibility after review and all five final/post-merge jobs passed.
[PR #76](https://github.com/0xsl0th/recon-cockpit/pull/76) accepted the native
diagnostic and its preserved retry-boundary failure after fixing a review
finding and passing all five final and post-merge jobs.
[PR #77](https://github.com/0xsl0th/recon-cockpit/pull/77) accepted the
[mediated diagnostic](tls-posture-mediation.md) after independent review and all
five final/post-merge checks. It retains 8/8 ordinary and 4/4 explicit-absence
observations while preventing the tested retry before peer delivery, 1/1.
[PR #78](https://github.com/0xsl0th/recon-cockpit/pull/78) accepted closed
diagnostic observations after review and five passing PR checks. A later macOS
cancellation failure is retained in the checkpoint and corrected by merged
[production PR #79](tls-posture-tools.md). Its four fixed-version profiles remain
candidates. PR #80 validates the T02 acceptance corpus with 65 native and 21,593
portable passes; G6 review/checks and authorized merge remain pending. Accepted
coverage stays 43 profiles / 16 programs. The separate T03 candidate in PR #81
follows in review order; T04–T06 and the dated PR-count forecast remain required.

## Product destination

Build an operator-supervised pentesting application for **internal networks with
web services**, initially on the supported Linux environment. Its eventual
lifecycle covers engagement scope, discovery, enumeration, validation,
explicitly authorized exploitation and post-access assessment, cleanup, findings,
reporting and retesting. A later model can propose steps; the authority layer,
operator approvals and enforced execution boundaries remain responsible for
what may run.

Two useful release targets keep the work measurable:

- **Professional v1:** an operator-assisted application for a declared subset of
  internal-network/web assessment tasks, with practical tools, engagement custody,
  a usable GUI, evidence-backed reports and verified cleanup. It can be useful
  without live models and without 40 programs. Its supported and unsupported
  engagement tasks must be explicit; it is not the whole eventual pentest lifecycle.
- **Broader product:** roughly 40 distinct external programs with selected secure
  modes, broader authenticated assessment, authorized intrusive/post-access work,
  mature workflows and later evaluated model assistance. A count alone cannot
  establish complete coverage or professional readiness.

The first target is the agreed intermediate release direction, not a replacement
for the owner's longer-term 40+ tool ambition. The finite coverage contract makes
the current tranche reviewable; compatibility, authenticated-operation and final
release criteria still need their later concrete contracts before completion.

## Verified position today

| Area | Implemented and accepted | Remaining product gap |
| --- | --- | --- |
| Execution authority | Typed actions, policy/scope checks, isolated approval/audit/admission services, consumed grants, confined launch, bounds and cleanup. | Revalidate these guarantees for broader target configurations, credentials, sessions and intrusive effects. Local consistency hashes do not establish protection from a malicious host owner. |
| Secure tools | **48 bounded profiles backed by 16 external programs**, plus repository-native capabilities represented in that profile count. Actual owned-lab execution and structured evidence exist for accepted operations. | Most profiles have fixed targets/requests and finite response grammars. They do not expose each program's full feature set or establish general real-server compatibility. |
| GUI | Accepted local Tk desktop, light/dark Swiss Industrial themes, scope import/export, separate dry run and owned execution, isolated exact-action review, cancellation and evidence inspection. | Execution currently exposes one four-action disconnected HTTP/SSH workflow. Broader tool selection, engagement/assets/findings/report views and operational usability are future work. Extend this GUI; its initial milestone is already closed. |
| Workflows | Accepted bounded discovery/HTTP/SSH and service/web workflows, with predecessor evidence, stops and saved decisions. | General multi-asset planning, durable engagement coordination and wider evidence-driven composition remain deferred. |
| Evidence and reporting | Private bounded raw artifacts, structured observations, action/policy/runtime bindings, reports and read-only replay. | Engagement-wide asset/finding models, deduplication, reviewed severity, remediation, client deliverables and retest history. |
| Model infrastructure | Prepared provider isolation, cost controls and model-capable integration validated with mocks/owned fixtures. | No live-model usefulness, cost or safety result is established. Credential setup, paid calls and live evaluation remain deferred until much later. |
| Packaging and support | Accepted local offline candidate and documented reproducible local execution. Portable CI spans Linux Python versions and macOS. | Professional installation, upgrade/migration, recovery and support acceptance. Portable macOS tests do not establish native macOS confinement or execution support. |

The 16 catalog programs are `curl`, `dig`, `ffuf`, `kerbrute`, `ldapsearch`,
`nmap`, `nuclei`, `openssl`, `redis-cli`, `rpcinfo`, `showmount`, `smbclient`,
`snmpget`, `snmpgetnext`, `ssh-keyscan` and `whatweb`. This uses the repository's
program-count convention: `snmpget` and `snmpgetnext` count separately. Grouping
them as one tool suite would produce a different total. Interactive host-runner
suggestions, supporting interpreters and installed binaries are not additional
accepted secure integrations.

The **offline R5**, **accepted local R6**, **B0–B8 core coverage**, **initial GUI**
and **C1–C18 accepted batches** stay closed. Deferred live-model criteria and
publication do not reopen their accepted local scopes. Proposal PR #31's
architecture correction is merged; the private PDFs, email draft and GUI mock
PNGs remain unchanged.
The owner chose to wait with the proposal until **November 2026**; refresh it with
verified progress before the **15 November 2026** deadline. Submission remains a
separate owner decision.

PR #72 accepted C17's fixed Git HEAD marker check after fresh independent reviews
and five passing PR checks; all five
[post-merge checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37816689999)
also passed. Its retained validation is 19,437 portable tests,
44 native checks, 4/4 ordinary plus 1/1 robustness completions, eight inconclusive
negative cases, zero unnecessary refusals, 26/26 blocked destination witnesses
and 195/195 boundary fields. Thirteen new and 120 accepted bundles replayed
unchanged. This is finite fixture evidence, not a repository-exposure or general
vulnerability-detection claim. See the [C17 runbook](nuclei-git-tools.md).

## Proposed professional-v1 sequence: 40–60 further PRs

These ranges are additive. They remain estimates from the accepted PR #72 baseline,
excluding the documentation-only PR #73 forecast and already completed work. Stages
describe deliverables; they do not lift the current offline-only restrictions.

| Stage | Deliverable and completion condition | Estimated PRs |
| --- | --- | ---: |
| 1. Freeze the release contract | The [coverage contract](professional-v1-coverage.md) maps accepted exact profiles and six required task gaps. Finish the supported environment, compatibility and later authenticated-operation/release criteria without treating synthetic coverage as professional acceptance. Every required task needs a named result, lab case and gate. | 2 |
| 2. Complete a practical coverage tranche | T01–T04 are accepted with G1–G6 closed, most recently T04 in PR #84. The [T05 SNMP interface-page candidate](snmp-page-tools.md) is integrated in PR #85 with 51 native and 23,170 portable passes; G6 review and merge remain open. Required T06 AAAA/PTR follows T05 acceptance. Reuse integrations and add only programs that contribute distinct coverage. Each row requires useful execution, structured results, evidence, enforcement and review. T05 registers snmpbulkget as a seventeenth program pending acceptance; the historical 4–6-program assumption was never a quota. | 8–12 |
| 3. Realistic lab and controlled target routing | Exercise varied real services in an owned isolated multi-host lab; add explicit target binding, DNS/redirect/referral handling, exclusions, network/rate budgets and compatibility cases. Separately approve any attached lab or engagement network. Demonstrate useful execution and denied out-of-scope traffic under the new boundary. | 6–8 |
| 4. Engagement, credential and session custody | Engagement identity, rules of engagement, approved effects/windows, revocation and crash-safe custody. First build with synthetic credentials; later introduce separately authorized real credentials and selected read-only authenticated operations. Secrets must not leak into planners, artifacts or logs. | 4–6 |
| 5. Workflows, findings, reports and retests | After the required coverage tranche closes, add deterministic cross-tool decisions, provenance-linked asset/finding records, deduplication, analyst disposition, remediation and report/retest history. Preserve fresh action authority; saved work does not restore grants. | 8–12 |
| 6. Extend the existing GUI | Expose supported catalog operations through shared services; add engagement/assets/findings/report views, clear progress and cancellation, useful errors and accessibility/usability work. Preserve the separate exact-action reviewer and both existing themes. | 5–7 |
| 7. Professional-v1 release gate | Installation and dependency diagnostics, pinned runtime maintenance, data migration/export/retention, recovery, representative service compatibility, adversarial review, operator acceptance and documented support limits. Publish only after the separate release decision. | 7–13 |
| **Professional-v1 total** | **Operator-assisted Linux release for its declared engagement subset. Live models and the full 40-program breadth are not prerequisites.** | **40–60** |

### Finite coverage gate before deeper workflows

The [finite checklist](professional-v1-coverage.md#six-required-tasks-in-priority-order)
fixes six required operator outcomes: **T01 MX, T02 TLS version posture,
T03 SSH policy assessment, T04 controlled web hierarchy discovery, T05 one SNMP
interface-description page and T06 AAAA/PTR metadata**. T01 is accepted in
PR #74; T02/T03 are accepted in PRs #80/#81 and T04 in PR #84. T05 is the
current candidate and T06 remains required. It maps all 49 accepted profiles separately and
records supported limits, meaningful positive/absent and
negative cases, evidence and G1–G6 for each new task. Candidate engines remain
subject to short feasibility reviews; engine selection cannot silently remove or
weaken the required outcome. B0–B8 and C1–C18 remain closed.

Close Stage 2 only when all six tasks are accepted, no row is blocked or
review-pending, normal tasks complete without unnecessary refusals, unauthorized
test actions do not execute, and evidence replay/cleanup pass. More realistic
target routing and service compatibility stay in Stage 3; the checklist is not
professional release acceptance. Record any required scope change for the owner
instead of moving a difficult row to optional work. Moving beyond this coverage
gate into deeper composition or comparative benchmarking remains a later decision.

## Broader product: 40–70 PRs beyond professional v1

These are additional to the 40–60 above, giving **80–130 total further PRs from
the PR #72 accepted baseline**. They are not another 80–130 on top of v1.

| Expansion | Deliverable and boundary | Additional PRs |
| --- | --- | ---: |
| Reach roughly 40 distinct programs | Integrate the remaining programs selected for actual engagement gaps, with bounded secure modes, realistic lab support and the same six gates. Reuse existing interactive precedents where practical. No credit for another mode of an already counted executable. | 24–40 |
| Broader authenticated, intrusive and post-access lifecycle | Broader Windows/AD, SSH, database and web/API sessions; separately approved vulnerability validation/exploitation, session handling, impact controls, cleanup and retest. This budget covers workflows, effects and custody beyond the adapters counted in the previous row. | 10–20 |
| Late bounded live-model integration and evaluation | Reuse the existing disabled integration. Approve data release, provider/model, credential source and spending ceiling, then run a small Nmap → HTTP → evidence pilot and adversarial variants. Compare against deterministic and appropriate operator/tool baselines before expanding autonomy. Offline operation remains a fallback. | 3–5 |
| Scale and advanced operations | Larger engagement/resource scheduling, long-run recovery, performance/reliability work and expanded security/operator acceptance within the supported Linux product. | 3–5 |
| **Additional expansion** | **Broader professional lifecycle and evaluated model assistance, subject to its separate approvals.** | **40–70** |
| **Total from PR #72** | **Professional v1 plus broader expansion.** | **80–130** |

Against the accepted 16-program baseline, the literal 40-program target leaves
**24 programs**. Accepted T02/T03 reuse existing implementations, and accepted
T04 reuses ffuf. The catalog already registers a separate seventeenth program. If
T05's snmpbulkget candidate is accepted, Stage 2 adds one program and **23 programs**
remain for expansion. The historical 4–6-program assumption was not a quota. The expansion's 24–40-PR allowance covers
the remaining gap rather than charging for all 24 twice; retain the Stage 2
8–12-PR estimate subject to native feasibility findings. This assumes many additions
can reuse a reviewed runtime and be delivered in one or two cohesive PRs. A new
runtime, difficult protocol, credential/session model or additional supported
platform can require more. Program selection is not yet a reviewed 40-name list.

Native Windows/macOS execution, cloud/mobile/wireless assessment, SaaS or remote
multi-tenant operation, distributed/multi-agent orchestration, arbitrary plugin
marketplaces and unlimited exploitation-framework modes are **outside these
ranges**. They remain optional separate scope. Buying a tool or installing a
binary cannot replace integration and acceptance work.

## Estimate assumptions, metrics and authorization

These are engineering planning ranges, not statistical confidence intervals,
calendar forecasts or guarantees. They assume one coherent reviewed capability
or subsystem slice per PR, reuse of the existing authority/evidence services, a
single primary Linux platform and no major architecture replacement. Normal
fixes are expected within a slice; substantial redesign or serious security
findings require re-estimation. Do not derive completion percentage from PR or
test counts. Re-estimate after Stage 1 and each 5–10 merged implementation PRs.

The largest uncertainties are real-service compatibility beyond finite fixtures,
new runtime confinement, credential/session custody, product usability and the
intrusive-operation boundary. These changes are materially larger than adding
another fixed HTTP matcher. A reasonable working budget is around **50 PRs for
v1** and **100–110 total for the broader product**, with the ranges retained.

Every stage measures legitimate task completion, unnecessary refusals, blocked
unauthorized actions, evidence integrity, cleanup, request/resource bounds and
latency. Model cost remains zero while models are disabled. Later paired
evaluation adds finding accuracy/false positives, overhead against the chosen
baseline, actual provider usage and cost. Blocking everything fails acceptance;
a plausible report without evidence also fails. Do not infer live-model prompt
injection resistance from the present deterministic hostile-output fixtures.

Planning these stages authorizes no new target, credential or spend. Decisions
needed later are:

- Review of any changes to the finite task matrix, concrete later release and
  authenticated-operation contracts, and moving past the coverage gate into deeper
  composition or comparative benchmarking.
- Explicit lab/engagement target ownership, scope, effects and routing permission
  before any external or attached-network execution.
- Credential/session-custody review and authorization before real credential use;
  separate approval for intrusive or post-access effects.
- Much later, a concrete model pilot configuration, data-release rules, measurable
  success thresholds and hard spending ceiling before any paid call.
- Separate release/publication and competition-submission decisions.

**Accepted C18/T01** adds one fixed nonrecursive TCP DNS MX question and at
most four typed preference/exchange rows, with useful null-MX/NODATA/NXDOMAIN
results and no returned-host follow-up. It reuses `dig`; see the
[C18 runbook](dns-mx-tools.md). Its merge adds one accepted profile and no program.

**Historical pre-merge snapshot (before PRs #80/#81): T02 remains open; the [mediated diagnostic](tls-posture-mediation.md)
preserves usefulness and blocks the tested plaintext retry before peer delivery.**
Frozen source `4d92d1d` produced 8/8 ordinary observations across TLS
1.0/1.1/1.2/1.3 and 4/4 explicit received rejections, with zero unnecessary
refusals in that finite corpus. The HRR case achieved **1/1 prevention**: the
client emitted two ClientHellos and 552 bytes; the mediator forwarded only 270
bytes (the first ClientHello and compatibility CCS), withholding the complete
282-byte second record. The independent peer observed one ClientHello.
All thirteen trials closed, passed the new Unix-socket boundary witnesses, and
made zero provider calls with zero cost. The prior PR #76 **0/1 prevention
failure** remains unchanged historical evidence; the new trial does not relabel it.

The gate validates plaintext framing and bounds encrypted record shapes; it does
not decrypt traffic or prove general encrypted application-data prevention.
PR #77 accepted this diagnostic boundary and PR #78 accepted
[closed diagnostic observation/replay](tls-posture-observations.md). The current
[production integration](tls-posture-tools.md) connects four candidate profiles
to policy, per-action approval, consumed permits and both evidence inspectors.
PR #80 validates the hostile-usefulness, ambiguity/pressure and full accepted-bundle
regression corpus with 65 native and 21,593 portable passes. G6 review/checks and
authorized merge remain pending.
Diagnostic receipts do not close those product gates. Accepted coverage remains
**43 profiles / 16 programs**; existing TLS profiles and limits stay unchanged.
Deeper workflows, credentials and paid/live models stay deferred.

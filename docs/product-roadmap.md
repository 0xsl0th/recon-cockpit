# Product roadmap and remaining PR estimate

Status snapshot: **8 October 2026, after PR #76**, accepted main `ca793cd`.
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
finding and passing all five final and post-merge jobs. The new
[mediated diagnostic](tls-posture-mediation.md), awaiting review, preserves 8/8
ordinary and 4/4 explicit-absence observations while preventing the tested retry
before peer delivery, 1/1. Product authority/evidence integration and its remaining
corpus are next; no T02 profile or additional program is accepted.

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
| Secure tools | **43 bounded profiles backed by 16 external programs**, plus repository-native capabilities represented in that profile count. Actual owned-lab execution and structured evidence exist for accepted operations. | Most profiles have fixed targets/requests and finite response grammars. They do not expose each program's full feature set or establish general real-server compatibility. |
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
publication do not reopen their accepted local scopes. Proposal PR #31, the
private PDFs, email draft and GUI mock PNGs remain separate and unchanged.
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
| 2. Complete a practical coverage tranche | C18/T01 DNS MX is accepted; T02 mediation proves useful observations and tested retry prevention, with product authority/evidence integration still open and T03–T06 still required. Reuse integrations and add only programs that contribute distinct coverage. Each required row passes actual useful execution, structured results, evidence, enforcement and review. Three additional programs are now plausible; the historical 4–6 assumption was never a quota. | 8–12 |
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
PR #74; T02–T06 remain open. It maps all 43 accepted profiles separately and
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

Today the literal 40-program target leaves **24 programs**. If the OpenSSL
substitution succeeds and the three remaining new-program candidates are accepted,
Stage 2 adds three and **21 programs** remain for expansion. The historical
4–6-program assumption was not a quota. The expansion's 24–40-PR allowance covers
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

**T02 remains open: the [mediated diagnostic](tls-posture-mediation.md) now
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
Next review the mediator and integrate four separately versioned profiles through
policy, fresh per-action approval, consumed permits, admission and both evidence
inspectors. Complete the full hostile-usefulness, ambiguity/pressure,
enforcement, cancellation and regression corpus before G1–G6 acceptance.
Diagnostic receipts do not close those product gates. Accepted coverage remains
**43 profiles / 16 programs**; existing TLS profiles and limits stay unchanged.
Deeper workflows, credentials and paid/live models stay deferred.

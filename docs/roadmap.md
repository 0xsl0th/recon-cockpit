# Roadmap — secure AI pentesting workflows

**Planning baseline: 15 September 2026.** This is a development plan, not a list
of implemented capabilities. Start the next session with
[continue-here.md](continue-here.md).

**Current milestone — broader secure-tool coverage (1 October 2026).**
Work through the [prioritized coverage checklist](secure-tool-coverage.md) in
successive small implementation batches. Each tool must execute usefully through
the secure path in the disconnected owned lab, return validated structured results,
retain independently replayable evidence and pass its enforcement checks.
Interactive command support, mocks and adapter descriptors do not count as secure
execution support. After every batch, select the next unchecked tool-coverage gap.

**Deeper workflow composition and comparative benchmarking are deferred until this
coverage milestone is complete.** Per-tool correctness, useful completion,
unnecessary refusal, bounds, descriptive latency and cleanup remain required now.
The preceding suggestion to compose Nmap, ffuf and headers after PR #37 is
superseded by the operator's broader coverage priority.

The inventory baseline is PR #37, merged as `ba0d6f8`: 10 interactive executable
families versus 6 secure capabilities backed by 3 external programs. PR #38 adds
accepted DNS/TLS coverage, bringing main to 8 capabilities backed by 5 external
programs. B2 adds SSH key collection and anonymous LDAP RootDSE next. See the
[inventory and completion gates](secure-tool-coverage.md) for exact distinctions,
product gaps and deferred modes. Roughly 40 tools remains the longer-term product
direction, not a claim that 40 integrations exist or a reason to duplicate tools.

| Priority | Required batch | Completion criterion beyond common gates G1–G6 |
| --- | --- | --- |
| B0 — accepted | TCP/Nmap, HTTP/headers, curl HTTPS and finite ffuf | Preserve the existing bounded owned execution and evidence; PRs #36/#37 stay closed. |
| B1 — accepted in PR #38 | dig DNS and OpenSSL TLS | Fixed nonrecursive A query and verified TLS handshake; structured useful output, negative cases, actual confinement and replay. |
| B2 — current | ssh-keyscan and ldapsearch RootDSE | Fixed key collection and anonymous base-scope metadata; no login or referrals. |
| B3 | smbclient | Anonymous bounded share metadata; no file operations. |
| B4 | rpcinfo and showmount | Bounded RPC/export observations without following endpoints or mounting. |
| B5 | curl FTP and SMTP capability query | Fixed finite listing and banner/EHLO/QUIT; no file transfer, mail or authentication. |
| B6 | curl Docker/WinRM metadata | Fixed read-only endpoint observations; no container or remote-session operations. |
| B7 | Nmap service identification | Reviewed, pinned probe/NSE runtime closure; never silently enable broad `-sV`. |
| B8 | kerbrute synthetic principal enumeration | Owned KDC, fixed finite users and request cap; no passwords, spraying or ticket extraction. |

The [full checklist](secure-tool-coverage.md#prioritized-coverage-checklist) is the
source of row-level status. Completion requires every required row B0–B8 to meet
G1–G6, including actual useful execution, evidence replay, enforced limits,
independent review and an authorized merge. Do not close the milestone after B1,
count skipped/mocked checks as executed, or silently defer required rows to finish.
Reprioritize unchecked rows after each batch with a recorded reason.

The [bounded model pilot](web-model-pilot.md) remains available but disabled.
Credential setup, paid calls, provider funding and live-model evaluation stay
deferred until much later; do not ask for a key during tool development. Completed
offline R5 and the accepted local R6 candidate remain closed. Broader authenticated,
intrusive and external-target product capabilities retain separate authorization.

Continue focused tool coverage through October. Refresh the proposal with verified
results in early November, targeting submission around 9 November after operator
review. Proposal PR #31 remains separate and unmerged; its local PDF is unchanged.
GUI/API, publication and competition submission remain separate later decisions.

The R5 offline baseline is `1605606`, the authorized merge of PR #26
([offline planning evaluation](planning-evaluation.md)). PRs #16–#26 remain
merged and closed. Both profiles pass 18 trials with matching semantic
fingerprints and no paid calls. These results establish offline integration,
not real-model acceptance. [PR #27](https://github.com/0xsl0th/recon-cockpit/pull/27)
adds the [local evidence packet and demo runbook](offline-release-evidence.md)
as R6 preparation and is merged as `dd4bbe4`, with all five final and post-merge
checks passing. The actual approval-required terminal rehearsal completed on
30 September: three approved actions, seeded case a validated, no paid calls.
The operator confirmed entering all three phrases and found it straightforward.
After reviewing the linked report and rehearsal, the operator separately chose
“Accept the local offline candidate”. The evidence packet/rehearsal review is
accepted; publication remains pending and requires a separate instruction.
Live calls remain disabled; development and verification use owned/mock fixtures.

### Earlier implementation checkpoints

**Implementation update — 17 September 2026:** R1 and the smallest R2 HTTP
assessment, private evidence and report slice are reviewed and merged into
`main` through [PR #6](https://github.com/0xsl0th/recon-cockpit/pull/6) (`07af513`)
and [PR #7](https://github.com/0xsl0th/recon-cockpit/pull/7) (`f85aaa9`).
Verification passed 1,849 portable tests
and 78 real Linux integrations, without failures, errors or skips in the selected
suites. All ten refreshed R2 branch/PR checks passed before merge; the merge
preserved the reviewed files. Current state is in [continue-here.md](continue-here.md).
See [http-assessment.md](http-assessment.md),
[offline-authority.md](offline-authority.md) and [verification.md](verification.md).
**R3 update — 22 September 2026:** the smallest owned single-port discovery
slice is reviewed and merged into `main` through
[PR #8](https://github.com/0xsl0th/recon-cockpit/pull/8), merge `b1c7b67`.
One isolated TCP connection gates the existing two-GET workflow; local verification
passed **1,977 portable tests and 96 real Linux integrations**, and all ten
premerge branch/PR checks passed. See [discovery-assessment.md](discovery-assessment.md)
and the continuation checkpoint. **R4 update — 23 September 2026:** the first
versioned card and deterministic engine are reviewed and merged into `main`
through [PR #9](https://github.com/0xsl0th/recon-cockpit/pull/9), merge `8673dc0`.
All ten premerge checks passed; the post-merge cancellation-test correction was
reviewed and merged in [PR #10](https://github.com/0xsl0th/recon-cockpit/pull/10),
merge `2b3527e`. All five subsequent main checks passed.
The [persistent owned lab foundation](owned-lab.md) is reviewed and merged in
[PR #11](https://github.com/0xsl0th/recon-cockpit/pull/11): 2,226 portable and 126
Linux tests passed, plus all five PR CI jobs. The [repeatable evaluation runner](evaluation.md)
now implements the 18-trial synthetic baseline, independent saved-evidence grading
and resource/cleanup/isolation aggregates, reviewed and merged into main through
[PR #12](https://github.com/0xsl0th/recon-cockpit/pull/12), merge `ff5f76a`.
Verification passed 2,300 portable and 132 Linux tests, plus the final 18/18 CLI
baseline. All five final PR CI jobs passed. The first R5a implementation is the
[owned TLS provider foundation](provider-foundation.md): disconnected fixture
transport, synthetic credentials, explicit status-only data release and bounded
per-attempt accounting. R5a is complete and merged in PR #13; its publication
and verification state are recorded in the continuation checkpoint.
**R5b complete — 29 September 2026:** the [durable provider cost ledger](provider-cost-ledger.md)
adds explicit USD estimates, reservations, actual usage/billing reconciliation and
atomic account/engagement/session/agent/action caps, merged in PR #14 (`3a0cb67`).
The [controlled provider call](controlled-provider-call.md), merged in PR #15
(`1369166`), integrates one fixed synthetic ACK request with those controls and
the R5a isolation machinery. R5a is merged in PR #13 (`0a9697f`). The new call
remains disabled by default and separate from assessment planning. All provider
verification used owned/mock fixtures and synthetic credentials; real planning,
further authority separation and live evaluation remain unfinished R5 work.
See [workflow-assessment.md](workflow-assessment.md) for the
decision trace and evidence contract. Broader discovery remains future work.
The baseline below is historical.

## Product direction

Build an AI-assisted pentesting platform that turns evidence into proposed next
steps, runs approved capabilities inside enforced boundaries, and produces
reviewable findings. The longer-term lifecycle includes discovery, enumeration,
validation, explicitly enabled exploitation, post-access assessment, cleanup and
reporting. Each stage needs its own permissions and tool contracts.

An **engine** is a specialist workflow with evidence requirements, capability
choices and stop conditions. A **tool adapter** implements one bounded capability.
A **planner** chooses steps. None owns policy, grants, audit authority or
permission to widen an engagement.

The competition contribution is control of autonomous agents, demonstrated by
useful pentesting. The official [Challenge 4](https://www.palermo.edu/ingenieria/concurso-ciberseguridad/)
supports that framing. Keep the Spanish [proposal](competition-proposal.md)
consistent with implemented limits and measured results.

## Baseline before R1/R2 — historical

PRs #2–#5 are merged. PR #5's reviewed code is `0477f25`; its merge on `main` is
`bf3a359`. The final run passed 1,383 portable and 51 Linux integration tests;
all ten hosted branch/PR checks passed. See [verification.md](verification.md).

| Existing capability | Gap that determines the next work |
| --- | --- |
| `AuthoritySession`, isolated coordinator and bound fixture executor | R1 adds an offline-provider relay. Host authority/UI/broker/audit/launcher still share one process. |
| `OfflineOpenAIProvider`, isolated parser and offline broker | R1 connects these to the authority path; the earlier `SessionRunner` mode remains. No live transport or credentials. |
| Strict actions and policy | Only `http_probe` is executable in secure mode; the action model is HTTP-specific. |
| Fixtures and a separate routed HTTP backend | Authority executors are fixture-only; routed sessions and real VPN validation are absent. |
| Audit and bounded feedback | No secure engagement evidence store, finding lifecycle or report provenance. |
| Legacy cockpit and Nmap workflows | Useful precedents; the host runner is not an agent-safe tool boundary. |

## Original milestone order — historical

The original sequence built one complete path through the provider and authority
boundaries before expanding the workflow library. Those bounded milestones are
now closed as recorded below. The current tool-first sequence above governs new
development; credential setup, paid calls and live evaluation remain deferred
until much later.

| Priority | Build | Why now | Exit evidence |
| --- | --- | --- | --- |
| R1 — implemented | Offline provider through the isolated coordinator and authority | Closes the split between existing boundaries without new targets or spending. | Combined three-step synthetic session and adversarial variants pass through the Linux boundaries. |
| R2 — smallest slice implemented | One HTTP assessment, minimal capability/evidence contracts and report | Makes the foundation useful and reveals the abstractions tools actually need. | Two-GET owned workflow, private execution/observation artifacts, draft reports and read-only crash inspection. |
| R3 — accepted bounded scope merged | One isolated single-port TCP adapter | Adds a second typed capability without broadening old HTTP backends. | Owned TCP evidence gates HTTP; 1,977 portable and 96 Linux tests passed. Broader discovery remains future work. |
| R4 — accepted first card/engine merged | Versioned workflow cards and one specialist engine | Turns references into tested branching, validation and stopping rules. | Existing six owned cases retain their outcomes with durable explanations of proposals, executions and stops. |
| R5 — offline scope complete; live work deferred | Isolated live-provider broker and further authority separation | Useful actions and a reproducible baseline provide a basis for model evaluation. | Offline integration/evaluation merged; real-model validation remains gated on explicit approval. |
| R6 — local offline candidate accepted; publication deferred | Evaluation corpus, operator review, packaging and demonstration | Makes utility, enforcement and limits independently reviewable. | Reproducible release, evidence-backed report and rehearsed final demo. |

Tests and adversarial fixtures accompany every slice; R6 consolidates them.

## Milestone completion order

The agreed offline R5 scope is complete and the local R6 candidate is accepted
under the disclosed offline fallback. Live work and publication remain deferred.
Use the original requirements below
alongside the accepted bounded contracts; do not retroactively expand completed
scope. Offline completion does not claim real-model acceptance or erase the
original live criterion.

1. **Preserve the accepted R1–R4 baseline:** the authority path, owned HTTP and
   TCP workflow, versioned card/engine, persistent lab and 18-trial evaluation
   are merged. Keep their documented limits visible. A general capability
   registry and broader finding workflows were not
   automatic blockers for R5. The newly authorized bundled-adapter contract is
   separate follow-on work. Address an earlier contract only when a concrete
   dependency or regression requires it, within the current milestone's scope.
2. **R5a complete — PR #13:** preserve the isolated owned TLS provider boundary,
   synthetic credentials, explicit data release and bounded attempt accounting.
3. **R5b complete — PRs #14 and #15:** preserve the durable monetary ledger,
   hierarchical spending limits and first tightly controlled provider-call path.
   Their agreed verification is offline with owned/mock fixtures. Live execution
   remains disabled by default; its later activation does not reopen R5b.
4. **Bounded R5 integration merged through PR #25:** preserve the accepted
   approval/authorization/launch/audit interfaces and owned assessment-planning
   path on R5a/R5b. The merged offline evaluation in PR #26 checks that combined
   path against the preserved baseline, including persisted accounting and
   launch preconditions. Keep its trust limits explicit; the fixed ACK diagnostic
   does not establish assessment planning, and a GUI is not a dependency.
5. **R5 live acceptance is gated:** real-model comparison still requires a later
   explicit operator instruction and reviewed data/model/credential/spend settings.
   This priority correction does not authorize paid or external provider calls,
   real credentials, external targets or VPN testing. Keep that criterion visibly
   pending while live work is prohibited; do not mark R5 complete using fixtures.
6. **R6 after the preceding acceptance gates:** consolidate the corpus, repeat
   functional/adversarial comparisons, obtain actual operator review, package a
   reproducible release and rehearse the evidence-backed demonstration. Existing
   baseline grading is a foundation, not completion of R6. If live validation
   remains unavailable, use the original explicitly disclosed offline fallback;
   it does not silently satisfy the live acceptance criterion. The current
   [evidence packet and runbook](offline-release-evidence.md) provide that local
   fallback. The operator has now accepted the local candidate after review and
   rehearsal; the separate decision is recorded in the checkpoint. Publication
   remains pending, and the original live acceptance criterion stays deferred.

### Bounded R5 integration and offline evaluation

The first merged implementation is the [confined audit writer](isolated-audit.md): an
explicit Linux option transfers audit persistence to a restricted worker and
requires a durable acknowledgement before the existing launch gate proceeds.
[Isolated terminal approval](isolated-approvals.md) is now merged in PR #18:
review, unpredictable challenges and single-use grant state reside in one fixed
worker. [Isolated launch admission](isolated-launch-admission.md) is merged in
PR #19: an independent worker owns fixed policy/profile checks, execution
reservations and one-use permits. The [confined fixture launcher](isolated-fixture-launcher.md)
(PR #20) and [persistent-lab integration](isolated-owned-lab-launcher.md) (PR #21)
are now merged. The launcher owns admission-client custody, executor supervision,
and persistent lab management/namespace pins, preserving card v2 and all six cases.

With merged [independent durable-intent verification](launch-audit-witness.md),
the isolated writer sends a direct witness after fsync, and the launcher checks it
before admission or execution. [PR #22](https://github.com/0xsl0th/recon-cockpit/pull/22)
completes the durability portion of precondition integration. The merged
[direct approval gate](launch-approval-witness.md) in [PR #23](https://github.com/0xsl0th/recon-cockpit/pull/23)
requires proof of a consumed grant from the approval worker, retains its original
expiry and rechecks freshness after admission. It closes reliance on a host
consent claim in the opt-in path; the fixed worker and terminal remain trusted.

The merged [bounded offline planning slice](bounded-assessment-planning.md) on
`feature/bounded-assessment-planning`, published as `bb9e42c` in
[PR #24](https://github.com/0xsl0th/recon-cockpit/pull/24), connects the existing workflow/evidence
eligibility gate, explicit planning data release, isolated parser/coordinator and
simulation monetary reservations/settlement to both independent launch checks.
It uses finite owned mock responses and leaves the fixed ACK and R5a TLS contracts
unchanged. Full verification passed 3,382 portable and 430 Linux tests, with zero
selected failures/errors/skips; independent review has no remaining findings.
The operator authorized review and merge of #24; final head `9ccc910` passed
review and all five hosted jobs, and merged as `4f9545c`. Keep this mock slice
closed. The [owned TLS slice](owned-tls-assessment-planning.md), PR #25, merged as
`636a067` after final head `c7f7791` passed review and all five checks. It sends the
same approved descriptor through the disconnected fixture, preserves settlement
before proposal release and verifies cleanup and transport failures. The current
[offline evaluation](planning-evaluation.md) compares this combined path with the
preserved deterministic baseline using a separate versioned grader and shared
batch simulation ledger. Mock responses do not complete
live-model acceptance; paid calls remain disabled during ordinary development.
The offline R5 scope is complete; full R5 still has its deferred live integration
and acceptance gate. R6's packet and runbook are merged in PR #27 and the
operator accepted the local candidate after the terminal rehearsal. Publication
is a separate pending decision. Optional GUI/session APIs and broader tools
remain deferred. The current follow-on authorization covers the reviewed
adapter/Nmap implementation described above; keep live calls disabled.

- Preserve the merged narrowly scoped approval/launch and audit interfaces.
  Record any necessary ownership change before extending the planning path.
  Keep the new reviewed adapter profile separate from accepted milestone
  contracts; it does not authorize broader targets or data release.
- Preserve fresh approval, independent authorization, cost reservations,
  audit acknowledgement before launch and independent executor validation.
  Moving functions into subprocesses alone does not establish a new boundary.
- Verify denial, expiry, replay, cancellation, audit failure and cleanup with
  owned/mock fixtures and the affected Linux isolation checks. Preserve the
  existing R1–R4 assessment outcomes and R5a/R5b financial/provider invariants.
- Preserve the merged offline evaluation and accepted local R6 packet/runbook.
  Keep real-model acceptance and publication visibly pending
  until each occurs; development and verification remain offline.

### Additional ideas deferred until milestone completion

The recently proposed separate budgeted-assessment initiative, general read-only
session view/timeline API, dashboard based on the GUI reference, and interactive
GUI controls are not the next work items. Revisit them after the original
milestones are complete, where they naturally fit, using the established
architecture and safety model. Necessary accounting or evidence work already
required by an original milestone stays in that milestone; do not relabel an
optional UI/API project as a prerequisite. Keep broader tools, multiple agents
and other stretch goals behind the same original completion priorities.

## R1: implemented integration and acceptance criteria

**Objective:** one offline planning path using the new authority boundary and
existing owned HTTP fixtures. Keep the current modes as regression references.

### Work sequence

1. Write a short architecture decision identifying who triggers planning, how
   proposals reach the coordinator, channel ownership, session identity, shared
   deadline, authority budgets and provider budgets. Settle topology before IPC
   changes.
2. Define the smallest bounded provider dialogue. The current coordinator has
   only stdin/stdout/stderr and proposal-only authority frames. A provider lane
   requires deliberate bootstrap/protocol work, not a generic RPC interface,
   inherited broker object or configurable Python plugin.
3. Construct planning observations and canonical provider requests from trusted
   execution records and fixed configuration. Coordinator-supplied claims cannot
   redefine observations, provider configuration, budgets or system rules.
4. Feed synthetic proposals through the isolated coordinator and existing
   sequenced authority checks. Every action still requires policy, any required
   fresh approval, reservations, audit and an independently validating executor.
5. Add a labeled combined offline CLI/demo, regressions and verification record.

### Acceptance criteria

- One three-step synthetic session uses an authority-owned session ID and
  deadline; provider usage and tool usage have separate bounded counters.
- Each planning exchange validates the canonical request, reserves resources
  and audits before offline transport handoff. No credentials or external
  connection become available.
- Every proposal enters the authority channel; there is no legacy host-runner
  or direct-executor shortcut.
- Replay, wrong-session messages, forged observations/approval fields, malformed
  dialogue, denied follow-ups and exhausted budgets produce no unauthorized
  additional exchange or launch.
- Cancellation, expiry and audit failure prevent subsequent work and reap
  children. Restarting a planner cannot replenish counters. A new operator-created
  session remains a separate documented case; persistent engagement quotas come
  later.
- Linux canaries preserve the existing broker/parser and coordinator/executor
  isolation claims, including absent host credentials, terminal and authority
  handles where required.
- Portable and affected real Linux suites pass. Report synthetic provider
  behavior separately from real OS isolation and human approval evidence.

### Starting points

Under `recon_cockpit/secure_agent/`, inspect `cli.py`, `control_plane.py`,
`coordinator_worker.py`, `coordinator_ipc.py`, `coordinator_isolation.py`,
`openai_provider.py`, `openai_broker.py`, `broker_ipc.py` and
`openai_isolation.py`. Read [control-plane.md](control-plane.md) and
[offline-openai-broker.md](offline-openai-broker.md).

**Outside R1:** new pentesting tool capabilities, live API calls, credentials, external targets,
VPN testing, generic knowledge ingestion, GUI and multiple agents.

## R2: implemented owned HTTP assessment

The fixed workflow discovers `/assessment/<case>/diagnostics.json` from an actual
successful response, then permits only that same-case follow-up. Both GETs use
`127.0.0.1:8080` inside owned fixtures and the R1 coordinator, offline parser,
authority and independently checked executor. Defaults are two planning steps
and 2,048 reserved output bytes. No live model or external target is involved.

A versioned descriptor covers this one capability. Private records bind host
execution IDs, action/policy digests, decoded artifacts and parsed observations.
JSON/Markdown reports distinguish validated seeded exposure, not demonstrated
at the endpoint, and inconclusive evidence. Findings remain pending operator
review. Read-only inspection recomputes observations and flags missing or
inconsistent records; it does not restore execution or approvals.

Six fixture cases cover exposure, absence, malformed documents, timeout, excess
output and hostile discovery. The current parser uses probe success/EOF and no
reported truncation; it does not establish comprehensive HTTP framing integrity
or authenticate server content. Local digests detect inconsistency, not a
compromised host owner's modifications. See [the R2 design](http-assessment.md)
for evidence ordering, storage bounds and remaining limits.

General capability registration, broader finding/review workflows, richer UI and
remote assessments remain future work. R3 has delivered the second tool's
smallest isolated runtime and owned lab contract. Continue the current R5 work
without making those broader extensions prerequisites.

## R3–R4: extend the assessment with discovery and workflow cards

### Start with HTTP, then generalize only what the second tool needs

R2 now covers the fixed HTTP path: inspect an approved endpoint, select a
bounded follow-up, validate a seeded condition, and produce a finding draft,
“not demonstrated,” or an inconclusive result. Extend this small workflow as
discovery exposes concrete requirements for another capability.

Generalize R2's versioned descriptor into a registry of reviewed built-in capabilities. An entry
declares typed parameters, destination requirements, effect/approval classification
interpreted by operator policy, resource ceilings, isolated runtime, parser and
result schema. Agents select
capability IDs and bounded parameters; trusted code selects executable,
arguments and storage paths.

This broader registry direction is not implemented by the accepted bounded
R3/R4 slices. It remains a future extension unless a concrete dependency of the
current R5 work requires a minimal change; it does not reopen those slices.

A new adapter needs its own runtime/dependency review, network model and
adversarial tests. The existing host runner must never become a fallback.
Check candidate tool behavior against its primary documentation during
implementation; this roadmap does not certify a particular tool/version.

### Evidence and findings

Keep three concepts distinct:

- **Execution record:** trusted session/action IDs, effective configuration,
  status, timestamps, resource use and artifact references.
- **Observation:** a bounded parsed claim from untrusted output, with source,
  target, parser version, truncation status and evidence reference. Successful
  exit does not prove a vulnerability or authenticate target content.
- **Finding:** hypothesis, supporting/contradicting observations, validation
  state, scope, impact rationale, remediation and reviewer state. Missing proof
  is not a negative result; unsupported model assertions remain hypotheses.

Use private, size-bounded artifacts, host-generated IDs, bounded parsers and safe
rendering. Define retention, redaction and which evidence may enter model
context. Do not copy raw output into trusted approval prompts or audit fields.
Agents receive selected views, not write access to case storage.

A digest identifies content; it does not prevent host-owner tampering. Keep that
limit visible. After a crash, preserve evidence and flag started-without-finished
actions for reconciliation. Never restore old approval grants, monotonic
deadlines or apparently unused budgets. Development resumption and assessment
resumption are different operations.

### First additional tool

Use a fixed **TCP-connect discovery profile**, with Nmap as the initial adapter
candidate, in an owned lab network. Bound ports, targets, rate, runtime and
output; isolate XML parsing. Begin without arbitrary options, user scripts,
raw-socket privileges or credentials. If its runtime cannot meet the boundary,
use a minimal bounded TCP discovery implementation until it can.

A multi-service lab requires an explicit lab-only executor contract. Do not
silently broaden existing fixture restrictions or route to the host. Reachable
allowed/forbidden witnesses must prove both connectivity and enforced scope.

### First engine and workflow cards

The first engine receives approved lab scope, discovers a service, selects HTTP
enumeration from evidence, validates one seeded non-destructive condition and
produces a finding draft with a Markdown/JSON report. Failure or insufficient
evidence produces an inspectable inconclusive stop.

Start with normal and stalled/misleading-response variants. A card records
ID/version, objective, preconditions, evidence dependencies, allowed capabilities,
parameter bounds, success/failure predicates, retries, stop conditions,
effects/cleanup, report fields, provenance and test fixtures.

Cards generate proposals, not permissions. Later attack graphs connect cards
through evidence-dependent transitions. Discovering another host, identity or
credential does not authorize its use. Every engine shares the same authority
and evidence contracts.

The first slice now uses one repository-authored card for the existing singleton
topology. It imports no external instructions and adds no capability registry.
The first card/engine slice is merged. The persistent owned lab foundation keeps
one seeded service alive across fresh executors, binds identity and counters to
evidence, and destroys the instance at session end. See [its contract](owned-lab.md)
and [verification](verification.md). The [repeated evaluation runner](evaluation.md)
now measures this fixed baseline. Preserve these accepted implementations as
regression references while completing R6 and any later authorized live work.
Persistent lab operation does not establish live-model performance.

## R5: live AI and further privilege separation

**Status: agreed offline scope complete; model integration prepared, live evaluation pending.** R5a
(PR #13), R5b (PRs #14/#15), bounded audit/approval/admission/launcher separation
and owned assessment planning through PR #25, and the offline comparison in
PR #26 are accepted. Keep those contracts closed. PR #27 is R6 packaging and
the runbook. No necessary offline R5 blocker remains.

The original live criterion below remains pending. The separate ACK diagnostic
stays unchanged. The new [web-model integration](web-model-pilot.md) supplies a
live-capable assessment path, validated only with owned TLS fixtures. Execution
remains disabled by default. Its proposed pilot requires reviewed data, endpoint,
credentials, egress, usage/pricing and spending settings before any paid call.
Owned fixture results do not establish model performance or live acceptance.

The current constraint remains **live calls disabled**. Build transport and
credential handling against controlled endpoints and synthetic secrets first.
Real use needs explicit operator choices for permitted data, model, credential
source and spending ceiling. Account for input/output consumption, bounded
bytes, cancellation and retries. Output-token limits alone are not a monetary
budget; reserve cost conservatively and reject unaffordable work before sending.

The credential/network broker needs its own constrained process, fixed
destinations and verified TLS behavior. Credentials must not enter planners,
tools, artifacts or logs. Redaction alone is not a data-release policy. Returned
model content remains untrusted.

Further separate approval issuance, authorization, launching and audit with an
explicit statement of which authority leaves each process. Prioritize credential
isolation, then narrowly scoped approval/launch and audit interfaces before
expanding credentialed or intrusive tools. Moving functions into subprocesses
or hashing messages does not establish independent authorization. Audit must
acknowledge intent before launch; independent storage cannot prove the truth
of a compromised producer's claims.

Run identical seeded assessments with deterministic and real planning. Measure
repeated-run completion, finding accuracy, unnecessary actions, scope violations,
injection effects, time and cost. Refusing everything is not useful assessment;
a convincing report without evidence is not success.

## Competition scope and schedule

Confirmed on 22 September: Enrique Folte is the sole human participant and
project contact, with Codex assisting development under his review. No other
members or institutional affiliation are declared. These are target windows,
not completed-capability claims. R1/R2, the smallest R3 slice and the first R4
card/engine slice are merged. The windows below preserve the original schedule;
they do not override the current R6 offline priority or reopen accepted scope.

| Target window | Outcome |
| --- | --- |
| September–October 2026 | R1–R4 bounded implementations, persistent lab and 18-trial baseline merged; offline R5 complete, live work deferred. Continue R6 under the disclosed offline fallback. |
| Through 8 November | Finalize proposal and measured baseline; build repeatable owned evaluation where ready. Tool breadth is not a submission prerequisite. |
| 9–15 November | Human review and project submission; aim for 9 November for margin. |
| 16 November–10 January 2027 | Complete R3/R4 and the lab assessment corpus. |
| 11 January–28 February | R5 controls and explicitly approved live-model evaluation. |
| 1 March–25 April | R6 repeated evaluation, operator review and documentation. |
| 26 April–13 May | Freeze capabilities, reproduce release and rehearse. |
| 14–20 May | Delivery buffer; no unvalidated expansion. |

**Minimum final target:** one real-agent lab assessment using discovery and HTTP
validation, traceable reporting, enforced scope/approvals/budgets and an
adversarial comparison. If live evaluation is unavailable, disclose the reduced
offline demonstration; do not claim validated autonomous performance.

**Later/stretch:** broader web/API, Linux and Windows/AD engines, credentialed
validation, controlled exploitation/post-access workflows, multiple agents,
remote audit, richer UI and optional PivotTrail/reporting integrations.
Real VPN testing remains deferred until the product is ready and the operator
provides scope; it is not a dependency of the initial lab demonstration.

Multi-agent work follows a validated single agent. Use shared engagement budgets,
scoped evidence views, delegation limits and concurrency tests. Delegating never
resets scope or grants.

If time slips, cut engine count, target breadth and interface polish first.
Keep one complete workflow, evidence quality and enforcement. Do not regain
time by using host execution, widening permissions or relabeling mock evidence.

## Knowledge sources

The user confirmed these exact references on 15 September 2026. They are
knowledge sources and potential lab resources, not installed integrations.

| Source | Intended role |
| --- | --- |
| [Enrique Folte](https://enriquefolte.com/) | Primary personal workflow/manual source; decision routing, pattern cards and reporting. |
| [PentestMonkey](https://pentestmonkey.net/) | Tools and technique references. |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | Payload and web-testing reference. |
| [GTFOBins](https://gtfobins.org/) | Unix executable behaviors relevant to privilege boundaries. |
| [LOLBAS](https://lolbas-project.github.io/) | Windows binaries, scripts and libraries relevant to security testing. |
| [HackTricks](https://book.hacktricks.wiki/en/index.html) | Broad technique and methodology reference. |
| [Hack The Box](https://www.hackthebox.com/) | Training and candidate lab scenarios, subject to access and applicable scope. |

The personal manual provides useful starting structures:
[Engagement Cockpit](https://enriquefolte.com/manual/_Engagement_Mode/Engagement_Cockpit),
[Decision Trees](https://enriquefolte.com/manual/_Engagement_Mode/Decision_Trees),
[Symptom Index](https://enriquefolte.com/manual/_Engagement_Mode/Symptom_Index),
[Attack Pattern Cards](https://enriquefolte.com/manual/_Engagement_Mode/Attack_Patterns)
and [Reporting & Evidence](https://enriquefolte.com/manual/_Engagement_Mode/Reporting_SysReptor).
Their translation into the contracts above is our design proposal.

Requested categories: reverse shells/payloads, Linux privilege escalation,
Windows privilege escalation, Active Directory, web application pentesting,
enumeration, post-exploitation and CTF/lab reference. Coverage in the knowledge
catalog does not enable execution. Payloads, callbacks, privilege changes and
post-access actions each need explicit capabilities, effect policies, cleanup
and their own lab verification before admission.

For adopted cards, record source URL/author, retrieval date, revision or content
digest, attribution/license status, reviewer, relevant tool versions and fixtures.
Summarize and reference; do not bulk-copy third-party collections or execute
retrieved prose. Preserve source → card → execution → observation → finding links.
HackTricks' book URL was verified through its official repository because direct
page retrieval was unavailable during this planning pass.

## Open decisions

- Enrique Folte is the confirmed sole human participant and contact; affiliation
  is unspecified. Review submission details before sending.
- R1 channel topology is settled in [offline-authority.md](offline-authority.md).
- R2's seeded diagnostic condition and R3's singleton owned topology are fixed in [http-assessment.md](http-assessment.md) and [discovery-assessment.md](discovery-assessment.md). Card v2 uses the [persistent lab foundation](owned-lab.md); the [evaluation runner](evaluation.md) measures repeated synthetic outcomes. Preserve the completed offline R5 and accepted local R6 baseline; the new model integration is separate work and live acceptance remains pending.
- Later choose real-model/data/credential/spend settings.

Reference identities and team composition are resolved. This plan does
not authorize registration, messages, paid calls or target assessments.

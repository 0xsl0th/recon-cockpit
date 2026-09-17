# Roadmap — secure AI pentesting workflows

**Planning baseline: 15 September 2026.** This is a development plan, not a list
of implemented capabilities. Start the next session with
[continue-here.md](continue-here.md).

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
R3's smallest isolated discovery adapter is next. The baseline below is historical.

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

## Recommended order and why

**Build one complete path before multiplying engines.** Compose the existing
provider and authority boundaries, produce one useful HTTP assessment with
evidence, add discovery, then grow the workflow library and live planning.

| Priority | Build | Why now | Exit evidence |
| --- | --- | --- | --- |
| R1 — implemented | Offline provider through the isolated coordinator and authority | Closes the split between existing boundaries without new targets or spending. | Combined three-step synthetic session and adversarial variants pass through the Linux boundaries. |
| R2 — smallest slice implemented | One HTTP assessment, minimal capability/evidence contracts and report | Makes the foundation useful and reveals the abstractions tools actually need. | Two-GET owned workflow, private execution/observation artifacts, draft reports and read-only crash inspection. |
| R3 — next | One isolated discovery adapter | Adds a second tool and tests the capability contract. | Discover an owned service and select HTTP work from evidence. |
| R4 | Versioned workflow cards and one specialist engine | Turns references into tested branching, validation and stopping rules. | Complete scoped lab assessment reaches a supported finding or an honest inconclusive result. |
| R5 | Isolated live-provider broker and further authority separation | We now have useful actions and a reproducible baseline against which to evaluate a model. | Approved real-model runs with verified credential/egress/data/spend controls. |
| R6 | Evaluation corpus, operator review, packaging and demonstration | Makes utility, enforcement and limits independently reviewable. | Reproducible release, evidence-backed report and rehearsed final demo. |

Tests and adversarial fixtures accompany every slice; R6 consolidates them.

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
remote assessments remain future work. R3 should first settle the second tool's
smallest isolated runtime and owned lab contract, then extend the proven path.

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

## R5: live AI and further privilege separation

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

Assumption: one primary developer with intermittent assistant access; team
capacity is unconfirmed. These are target windows. R1 and the smallest R2 slice
were implemented by 16 September; use the remaining early windows for review,
publication and R3 design rather than treating later capabilities as completed.

| Target window | Outcome |
| --- | --- |
| 16–30 September 2026 | R1/R2 review and merges completed on 17 September; design isolated discovery. |
| 1–18 October | Begin R3 and extend HTTP/evidence contracts only where the second adapter requires it. |
| 19 October–8 November | R3 discovery prototype if ready; finalize proposal, team and measured baseline. Tool breadth is not a submission prerequisite. |
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

- Confirm Enrique Folte's submission role, affiliation if applicable, and any
  additional team members.
- R1 channel topology is settled in [offline-authority.md](offline-authority.md).
- R2's seeded diagnostic metadata condition is fixed in [http-assessment.md](http-assessment.md); choose the smallest owned discovery topology for R3.
- Later choose real-model/data/credential/spend settings.

Reference identities are resolved. Team details do not block scoped development. This plan does
not authorize registration, messages, paid calls or target assessments.

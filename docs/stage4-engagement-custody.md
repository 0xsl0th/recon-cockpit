# Stage 4: engagement, credential and session custody

**Stage 3 is accepted; S4.1 is a contract-only slice pending review.**
[PR #99](https://github.com/0xsl0th/recon-cockpit/pull/99) merged as
`4ef9b9827d887df827eab3d52991ec3b35a0ea12`, with tree
`321f50c2f53f3ecda88242f703ce32a46404d878`, identical to reviewed
`96c44085b806731d6b54cb484e5fb9438d99a4c4`. The final local portable suite and
all five pre-merge CI jobs passed 28,777 tests each; the combined evidence
retains 651 reused native identities, 472 fresh inspections and 120 separate
legacy inspections. These establish the accepted Stage 3 scope, not Stage 4
custody. All Stage 4 requirements and cases start pending. The contract PR's
review and checks must pass before S4.1 is accepted.

The [product roadmap](product-roadmap.md) requires engagement identity, rules of
engagement, approved effects and windows, revocation and crash-safe custody.
Development starts with synthetic credentials. Separately authorized real
credentials and selected read-only authenticated operations remain required
later work; deferring their authorization leaves that gate and Stage 4 open.
This contract does not authorize credential acquisition, a live model/provider,
attached targets, a network connection or a native diagnostic.

## Four logical increments, within the existing 4–6 PR estimate

| Increment | Bounded work | Completion boundary |
| --- | --- | --- |
| S4.1 — contract and inventory | Pin these requirements, authority/data-flow/state rules, finite cases, prerequisites and exclusions. | Reviewed documentation and exact machine inventory only; no execution, custody or recovery claim. |
| S4.2 — engagement and session authority | Build strict non-secret engagement records and durable state, then bind the declared supported session/action path to current rules, windows, revocation and recovery. | Useful allowed work and real denied-dispatch/cleanup evidence for the declared path; opening a store alone proves no enforcement. |
| S4.3 — synthetic credential custody | Build the isolated custody boundary, then validate the selected finite authenticated read-only outcome against an owned service with synthetic credentials. | Useful and negative native observations, secret-free released evidence, physical custody/denial/cleanup and immutable replay. No real credentials. |
| S4.4 — authorized real use and combined acceptance | After a distinct operator authorization, validate the same selected read-only operation with a real credential under explicitly reviewed ownership/scope/effects/windows/routing; combine all Stage 4 evidence. | Every required row complete, original failures preserved, independent review and required checks. No blanket network, authenticated-operation or release acceptance. |

Two splits are permitted without changing outcomes: S4.2 may separate durable
record preparation from authority integration; S4.3 may separate custody
preparation from operation integration. Thus four logical increments can use
four to six PRs. Further necessary splits require an explicit estimate update.
Do not replace the real-use gate with another synthetic success or silently make
it optional. Missing authorization is a visible pending gate, not permission to
run it. Intrusive/post-access operations remain outside this stage.

## Existing foundations and explicit gaps

`Policy` already checks exact action targets, tools, ports, methods and bounds.
`ApprovalStore` issues expiring, single-use action/policy grants; the isolated
review protocol exposes review/consume, not durable engagement management.
`SessionRunner` creates a fresh session and immutable monotonic deadline. It is
single-use and intentionally does not restore grants or budgets from a saved
session. These are constraints to retain, not evidence of engagement revocation.

`CostLedger` offers private SQLite transaction, one-time dispatch and uncertain
outcome patterns. Its account/engagement/session labels govern provider costs;
they do not authorize tool execution. Reuse reviewed durability patterns without
turning an accounting scope into a grant or enabling a provider.

The isolated audit/admission/approval boundaries and provider synthetic-secret
worker are relevant precedents. Their existing proof applies only to their
current contracts. New engagement state, credential release and authenticated
operations need their own exact runtime, authority, custody and native evidence.
No existing catalog profile acquires authentication through this document.

Legacy `recon_cockpit.models.Credential.secret`, `case.py` JSON/Markdown storage,
and `cli.py` stored-credential selection are outside this secure boundary.
Their presence, a private case directory, a saved password or redacted terminal
line does not establish secure custody. Preserve legacy behavior separately:
there is no automatic import, migration, credential discovery or execution bridge
from cases/notes/CLI into Stage 4. Future explicit migration would need a distinct
contract and authorization. No real legacy credential is read during this work.

## Required outcomes

| ID | Requirement |
| --- | --- |
| S4-01 | Stable engagement identity with immutable, versioned rules-of-engagement revisions and explicit supported scope. Identity references cannot confer authority. |
| S4-02 | Exact declared inclusions, exclusions, operation/effect permissions and persistent aggregate limits; intersect these with existing profile/policy constraints. Splitting actions or reopening a process cannot replenish consumed allowance. |
| S4-03 | Fresh exact-action review, audit and admission bind the engagement/revision, revocation generation, policy, action, credential reference where applicable, and actual live session/owner. Both approval views show the non-secret commitments. |
| S4-04 | Approved UTC windows and bounded monotonic execution deadlines have explicit edge/clock-change semantics. No new work after expiry, including after approval or durable writes. |
| S4-05 | Revocation and dispatch admission have one durable serialization order. Stale/foreign references fail; already-dispatched work is classified honestly and cancellation/cleanup follows. |
| S4-06 | Durable transitions and crash recovery never resurrect grants, repeat uncertain sends, reset usage or claim an unobserved completion. Storage/audit failure fails closed. |
| S4-07 | Synthetic-first credentials remain inside a minimal reviewed custody/operation boundary; secret-bearing data never enters planners, arguments, environments, public logs or released evidence. |
| S4-08 | Actual process/descriptor/session lifetime and cancellation are bounded and observable. Recovery creates fresh authority; no saved network/login session is resumed. |
| S4-09 | One declared authenticated read-only outcome completes usefully; supported authentication denials and malformed/unsupported responses are distinguished without expanding requests or claiming access that was not observed. |
| S4-10 | Non-secret evidence supports exact identity/state/result consistency, immutable Python/CLI inspection and tamper refusal; it restores no authority and states the limits of replay. |
| S4-11 | Preserve accepted profile behavior and the secure/legacy boundary, plus all original failures, excluded diagnostics and finite-scope limitations. |
| S4-12 | Complete the exact finite inventory, separately authorized real-use gate, meaningful metrics, independent reviews and required checks before Stage 4 acceptance. |

The JSON inventory maps every requirement to increments, gates and named cases.
Each requirement's increments are the union of its named cases' owning increments,
including the final combined acceptance case; they do not duplicate case counts.
Its cases are obligations, not claims that tests or native executions exist.
Later pinned implementation inventories must map every applicable case to exact
collected test identities and retained evidence. Splitting a test, parameterizing
it or reusing a case across requirements does not add canonical outcomes.

## Authority and durable state contract

Engagement configuration is trusted operator input, never planner output. The
first implementation can be an offline, non-secret record/inspection slice.
Before writing it, pin the exact closed schema and finite size/count limits,
canonicalization, storage/journal/version rules, supported scope representation,
state transitions and event/error vocabulary in an S4.2 implementation contract.
An offline record validator returns data; it does not create a live owner or a
credential-release capability. Neither an imported document nor a valid digest
changes current policy or grants.

The record must separate: stable engagement ID; immutable ROE revision/digest;
explicit endpoints/selections and exclusions; allowed effect/profile identifiers;
approved UTC start/end; persistent usage; monotone revocation generation; and
observed lifecycle/uncertainty. Session/owner/credential handles are opaque
references. A trusted live service resolves them to actual identities and checks
current state. Guessing or copying a handle grants nothing. Do not accept a
caller-provided snapshot as current authority.

The authorized effect set initially contains only the exact operations selected
by a later reviewed integration contract. There is no wildcard method, arbitrary
URL, general shell, generic plugin, response-directed follow-up or automatic
planner extension. Applicable permission is the intersection of engagement ROE,
profile/policy, fresh action approval, current window/state and launch admission.
Absence or disagreement denies before credential release or dispatch. Metadata
alone cannot prove target ownership; explicit operator authorization remains a
precondition for later real use.

Revocation and a one-time **dispatch admission** must serialize in the same
trusted durable authority domain. If revocation commits first, dispatch cannot
be admitted and no credential/request is released. If dispatch commits first,
the operation is in flight or possibly sent: revocation prevents later admissions
and requests cancellation and bounded cleanup. It cannot retract bytes already
sent. The contract does not equate database commit with an atomic network write.
Retain the order, actual observed progress and uncertainty instead of reporting
all concurrent work as never sent. A stronger credential-release/write handoff
requires its exact protocol and physical witnesses in the implementation pin.

Persistent limits are separate from grants. At admission, reserve the full
bounded allowance irreversibly for the operation. No response-reported refund,
process restart, new child or replay can restore it. If a future reservation model
releases definitely unadmitted work, its exact proof/transition must be reviewed
before use; the initial integration cannot infer that release from missing logs.
S4-E07 includes concurrent distinct approved actions competing for the last
shared allowance: at most the bounded winner may dispatch. S4-E08 includes
simultaneous consumption of the same grant/dispatch identity: at most one
admission may commit and dispatch. These are mandatory variants with actual
transaction and dispatch witnesses, not sequential replay substitutes.

Approved windows use explicit UTC instants with start inclusive and end exclusive.
At admission, use a trusted clock observation and derive a monotonic deadline no
later than the end window and existing session/action cap. Wall-clock rollback
cannot extend that deadline; a forward clock reaching the end denies new work.
Every authority/credential-release boundary rechecks the current window and
original deadline. Recovery cannot reuse a pre-crash monotonic timestamp. It must
recheck UTC/state and require fresh session/action authority. Bound and pin clock
uncertainty/failure handling before implementation; unknown time fails closed.

Durable state must distinguish prepared/unadmitted work, admitted/possibly-sent
work, completed observed work, cancellation and unresolved interrupted work.
A crash before dispatch admission supplies no send claim. A crash after admission
preserves its consumed allowance and uncertainty even if no response was saved.
Reopening does not repeat the operation, issue a replacement grant, restore an
approval store or claim a zero-byte delivery. Completion becomes trusted only
with the required persisted observation; incomplete completion writes require
reconciliation. No automated recovery resends or continues an authenticated
connection. Storage and audit failure stop future authority; they do not undo an
already performed effect. Concurrent writers and revoke/dispatch races require
actual transaction-boundary tests, not only sequential model assertions.

Durability assumes the operator-owned host, filesystem and storage implementation
honor their documented guarantees. Generation monotonicity is enforced within
that trusted store; it does not detect a malicious host owner's coherent rollback
of the database, clock and evidence. An imported older snapshot must never be an
authority-restoration interface. Protection against hostile-host rollback would
require a separately reviewed trust mechanism and is not claimed here.

## Selected candidate: one authenticated service-status read

The S4.3 candidate is **one HTTPS GET `/api/status`** at one explicitly declared
owned service, using one synthetic bearer credential supplied through the custody
boundary. Its useful result is a strict public service identifier plus one of
`ready` or `degraded`. The result claims only that this exact authenticated
read-only operation returned the permitted status; it is not general account,
permission, application-security or service-version assessment.

This candidate is deliberately not a registered or accepted catalog capability.
The exact client/daemon implementation is not selected by this document. Review
whether a minimal isolated worker or an existing bounded client can meet the
contract before choosing one. Do not activate the provider pilot or repurpose its
provider/model settings. A local status-service fixture is not a live model.

The later S4.3 implementation contract must freeze, **before execution**:

- Exact client/server/parser images, source/dependency hashes, supported platform,
  UID/GID/capabilities, namespaces, mount/file/device allowlists, system calls,
  process/thread/exec ceilings and descriptor custody/readiness/cleanup evidence.
- The one numeric endpoint, logical Host/SNI, certificate name, pinned public trust
  and address family/route restrictions. No ambient DNS/trust/host-network fallback.
- One connection attempt, one TLS handshake and one GET, with no automatic retry,
  redirect/referral/alias following, token refresh, cookies, pagination, second
  request, login session, credential probing or authenticated state-changing method.
- Exact request template and credential encoding/length limits; allowed header
  set, framing, TLS version/algorithms, client/server byte ceilings, timeouts,
  output/parser/storage limits and aggregate engagement/session budgets. No missing
  cap inherits an unbounded default. A required engine behavior exceeding a pin
  triggers contract review, not an implicit permission increase.
- Exact finite success schema and public identifier/status values; HTTP 401/403
  authentication/authorization refusal; malformed/unsupported/oversized/partial
  response classifications; owner progress required before counting each case.
- Exact credential input descriptor/source and one-operation lease checks,
  non-secret proof format, release/parsing placement and all applicable case IDs.

Real-credential S4.4 validation uses this already reviewed finite operation only
after a separate authorization identifies credential provenance/reference,
service/target ownership, scope, effects, approved window, trust/routing and
cleanup/revocation expectations. The actual secret and credential-file contents
must never enter the contract, Git, a PR, review message or evidence bundle.
There is no authorization to search credential files or attach to a network while
preparing this gate. Missing any required authorization leaves it pending.

## Secret-free release and evidence limits

Use only a finite, pinned set of deliberately public synthetic sentinel values
during development and testing. A credential's appearance cannot establish that
it is synthetic; the synthetic mode accepts only its pinned fixture values and
source. Negative tests use synthetic stand-ins for unauthorized material and
refuse unauthorized sources before opening or reading them. No legacy
case credential, ambient environment variable, home-directory search, keychain,
agent socket or default credential path is a source. The real-use source, much
later, must be explicitly chosen by the operator and transferred through the
reviewed private descriptor boundary only after current authority checks.

Keep the secret, credential-bearing request and potentially reflective raw
response inside the minimal trusted custody/operation/parser boundary. Release
only a strict non-secret result/error schema, public action/ROE/runtime digests,
opaque credential references, bounded accounting and lifecycle observations.
Do not retain raw credential-bearing request/response bytes or hashes derived
from the credential or complete secret-bearing request. Public request-template
commitments omit the secret value; an opaque handle binds to a live custodian
lease, not a publicly guessable secret digest. Credential paths are not evidence.

Tests must include literal, JSON-escaped and base64-looking secret reflection,
unknown response fields, diagnostic exceptions, malformed/partial output and
retained artifacts. A finite reflection check is not a universal redactor. The
primary boundary is a closed result/error grammar and controlled output paths;
unknown content is rejected without echoing fragments. No claim of perfect
memory zeroization, complete covert-channel removal or immunity to a malicious
host owner is made. Python/runtime copies, swap/core-dump policy and host/kernel
trust must be stated honestly in the implementation custody review.

Secret-free replay verifies permitted observations, current evidence structure
and recorded authority/custody/accounting consistency. It cannot independently
reconstruct a discarded secret-bearing wire exchange, validate an actual secret,
contact the service or restore a live session/grant. Physical synthetic native
proof supplies the separate evidence that the real operation reached the owned
authentication boundary. Later real-use receipts state their observation limits.
Unsigned local hashes establish consistency, not protection against coherent
rewriting by the host owner.

## Finite validation and completion

The exact case inventory is `stage4-engagement-custody-gates.json`: **55
canonical obligations**, partitioned into S4.1's 4 contract cases, S4.2's 26
engagement/lifetime cases, S4.3's 19 custody/operation cases and S4.4's 6 real-use
and final-acceptance cases. These are not executed-test counts. Each case names
its increment, requirements, gates, stimulus, expected outcome and required
proof. For S4.2 and S4.3, each implementation contract must freeze the corresponding
schemas, runtime/native limits, exact test identities and source/fixture pins
before the relevant work. Case counts alone close no gate; startup refusal cannot
stand in for a useful response, authentication negative or live revocation proof.

Retain separate denominators for useful ordinary status reads, supported degraded
status, correct authentication denials, invalid/unsupported input, intentional
authority/window/revocation refusal and crash uncertainty. Record requests,
connections, irreversible reservations, actual delivery where knowable, duration,
stop reason and cleanup. Unknown remains unknown; zero requires evidence.
Provider calls and cost stay zero. No comparative-performance or live-model
resistance claim follows from these deterministic cases.

Every affected entrypoint must retain fresh authority and consistent Python/CLI
inspection. Preserve accepted profile schemas/recipes, historical contract bytes,
reports and previous evidence. Prior Stage 3 gates establish only their unchanged
claims: they cannot prove new engagement revocation, secret custody or crash
recovery. Changes to shared authority/runtime code need a pinned affected-gate
plan and fresh relevant physical validation. Keep all failed attempts and their
explanations or unresolved causes beside the passing selections; diagnostics
contribute no acceptance cases.

S4.1 changes only these two new documents and current status pointers in
`product-roadmap.md`, `roadmap.md`, `continue-here.md`, `secure-tool-catalog.md`,
`secure-tool-coverage.md`, `stage3-combined-acceptance.md`,
`stage3-compatibility-routing.md` and `stage3-name-tls-preflight.md`.
The JSON inventory lists these exact eight existing paths. Do not edit byte-pinned
historical contracts, production code, runtime inventories or tests in that PR.
Review exact requirement/case coverage and the JSON inventory, then complete the
repository's required checks. This documentation gate proves no new native or
credential behavior. Stage 4 closes only after S4.2–S4.4 and all whole-stage
requirements have accepted evidence, independent review and required checks.
Stage 5 workflows, Stage 6 GUI expansion and Stage 7 professional-v1 release
remain separate roadmap work.

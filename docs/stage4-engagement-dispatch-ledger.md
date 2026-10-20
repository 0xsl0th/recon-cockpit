# S4.2b — durable dispatch accounting

Implementation contract, fixed before code after independent review. Acceptance
remains pending. This contract authorizes the bounded offline implementation; it
authorizes no native execution, network contact or credential access. PR101/S4.2a is accepted
at merge `43869cb182cc440487ee2f292db0fba2ca731892` after corrected validation
and review. Its source review baseline is `fe2e40e649b81df9f28114f6d1c40093b64c5912`, tree
`4896f2567cac6ca25c4023c6c28a05d651b669de`.

## Decision and scope

The accepted S4.1 contract permits further necessary splits with an explicit
estimate update. This increment separates S4.2b durable dispatch accounting from
S4.2c isolated live enforcement. It changes the current Stage4 forecast from
5–6 to **6–7 PRs**, professional-v1 from48–65 to **49–66**, and the broader
product from88–135 to **89–136**. The original4–6/47–65/87–135 and intermediate
5–6/48–65/88–135 estimates remain historical. S4.3 retains its optional split;
no outcome is added or removed. The new range is not described as inside4–6.

This is a real persistence increment: current ROE, terminal revoke, lifetime
reserved usage, immutable session declarations, unique reservations and reported
completion commit in one bounded SQLite transaction domain. It proves database
ordering, durable accounting, replay and lost-acknowledgment behavior. It creates
no grant, admission permit, owner process, worker, socket, session execution,
native request or credential lease. A committed reservation is a **record**, not
proof that an action was reviewed, admitted by a live boundary, sent or observed.

All18 S4-G3 physical cases remain open. The other8 S4.2 obligations retain their
exact parent meanings; supplied-clock and reported-observation checks are partial
preparation where physical context is missing. All26 parent IDs are mapped in
the adjacent inventory. S4.2 as a whole, S4.3, S4.4 and Stage4 remain open.

The technical reason for this split is explicit: S4.2a fixes a metadata-only
three-table schema, while current approval/audit/launcher witnesses lack
engagement bindings and current configurable output limits do not meter all
accepted/delivered application payload. These are separate storage, authority
and physical-effect boundaries. A full vertical slice is feasible; this split
lets each boundary receive a concrete review without claiming that one replaces
the others. S4.2c is the next integration increment, not another planning slice.

## Preserved preparation and fresh v2 store

Keep every accepted S4.2a module, API, CLI, schema and test unchanged. Reuse its
pure ROE validator and ROE digest. Create a **fresh**, explicit operator-owned
v2 store with a fresh UUID4 in a new private directory. The database basename
remains `records.sqlite3`, so existing inspection refuses store-directory inputs
before opening a second database descriptor. No v1 migration, export import,
restoration, reactivation, reset, deletion or grant/session rehydration exists.
Opening v1 through this API and opening v2 through the old API both refuse.

The operator supplies a new nonsecret ROE; copying data into a new declaration is
not import of old identity, usage, approvals or authority. Existing recorded
engagements are not automatically promoted to live status. The new store still
uses status `recorded` or terminal `revoked`; neither means execution is enabled.

All existing ROE forms remain valid record data. The single declared plan is
`http-prefix-v1`. Registering a session additionally requires HTTP not excluded,
both `configurable_nmap_service_v1` and `configurable_http_headers_v1` present,
and `scope.http.path == '/'`. The SSH profile may also be declared and SSH may
be excluded or not; this plan never selects SSH. HTTP exclusion, either missing
prerequisite profile, and any other HTTP path refuse session registration.
This avoids silently permitting Nmap's compiled `GET /` when only a different
follow-up path was declared. This increment executes neither operation.

The fixed actions are exactly `configurable_contract.action(scope,1)` and
`action(scope,2)`: existing field sets, UUID5 action identities, parameters and
rationale remain unchanged. A new pure policy builder uses the existing Policy
schema: policy_version `engagement-http-prefix-v1`; only the HTTP target/port;
the two named tools; GET; max_timeout_seconds5; max_output_bytes8192;
max_targets1; require_approval true; approval_ttl_seconds60. No engagement
extension fields are inserted into Action or Policy. Session records bind this
derived policy digest; supplied approval/audit identities remain declarations.

## Fixed reservation rows and limits

| Slot | Required predecessor | Actions | Connections | Request bytes | Response bytes | Output cap | Native tool timeout |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| http_identify | new session | 1 | 3 | 4096 | 4096 | 8192 | 5 seconds |
| http_headers | eligible reported identify completion in this session | 1 | 1 | 256 | 2048 | 2048 | 1 second |

The immutable reservation cost is exactly `actions,connections,request_bytes,
response_bytes,runtime_ms`. Runtime cost is `min(30000, current ROE
max_action_ms)`; other cost fields come only from the fixed slot row. Callers
cannot submit costs or lower them using observed delivery. Output is an
unchanged separate tool/session cap, not a replacement for response bytes.
A full prefix reserves2 actions,4 connections,4352 request bytes,6144 response
bytes and at most60000 runtime milliseconds. The session has exactly2 possible
slots, at most60 seconds and at most10240 output bytes. The outer30-second
per-action allowance includes preparation/review/cleanup; it does not widen the
existing5-second Nmap or1-second GET tool timeouts. Smaller ROE limits narrow
the plan and may make the complete prefix unavailable.

These are accounting rows for the next integration. S4.2c must physically meter
admitted connections and accepted/delivered application payload, explicitly
distinguishing them from TCP packets/retransmissions/unread kernel bytes. It must
prove these caps before using them. Reusing the trusted synthetic endpoint as
the meter is a viable alternative to adding a proxy; no topology is selected here.

Five lifetime usage counters match the cost fields. At reservation commit, add
the entire fixed cost atomically and irreversibly. Each counter must remain at
or below the corresponding current ROE cap. `runtime_ms` is charged against
max_engagement_ms, while max_action_ms bounds one slot. Revision never resets
usage. Raising a cap is an explicit new ROE declaration within the existing
global maxima, not a refund; lowering a cap below already-consumed usage is
allowed record data but prevents every further positive reservation until a
later explicit revision permits it. Completion, failure, cancellation, missing
evidence, reopened handles and exact retries never subtract usage.

Additional inclusive bounds are: ROE4096 bytes; request8192; receipt4096;
session row4096; reservation row8192; completion row4096; export2097152;
report8192; JSON depth12; revisions64; sessions64; reservations64;
completions64; events257; database8388608 (2048 pages of4096);
rollback journal16777216. Event257 is65 create/revise/revoke events plus64
session,64 reservation and64 completion events. Independent row/event/file
bounds all apply; no successful operation may create an unexportable state.
The implementation must test the attainable combined maxima rather than assume
that independently bounded fields fit. All public operations share an original
2000ms work deadline, including locking, nested validation, SQLite progress,
commit, readback and successful cleanup. Emergency closure/rollback remains
necessary after work expiry and cannot produce success.
The new codec has its own2MiB size bound, but all new public operations bind the
accepted engagement_contract._operation_deadline/_using_deadline helpers around
nested v1 validate_roe/roe_digest calls. A separate deadline ContextVar is not
allowed: it would grant reused validators a fresh2-second phase. Existing
PID-scoped deadline semantics and constructor cleanup remain unchanged.
Raw byte/depth cutoffs are distinct from attainable valid schema maxima. Tests
must not invent oversized fields or fractional reservation costs merely to make
a valid export equal2MiB or a valid database equal8MiB. Prove applicable raw
cutoffs, attainable combined row maxima, and fixed-cost cap boundaries separately.

## Canonical data and schemas

Use exact closed objects, ASCII canonical JSON, sorted keys, compact separators,
ensure_ascii true, allow_nan false, no newline and detached return values.
Reject booleans as integers, floating/nonfinite numbers, duplicate/unknown keys,
invalid UTF-8, lone surrogates in keys or values, excessive depth and trailing
JSON. UUIDs are lowercase RFC4122 UUID4 except derived existing Action UUID5s.
Hashes are lowercase64-character SHA256. Integer fields are nonnegative unless
their named lower bound is1; all integers are at most2**63-1.

The inventory contains the exact closed schemas. A normalized mutation request
has `schema_version:'2', engagement_id,event_id,operation,expected_revision,
expected_generation,body`. Operations are create/revise/revoke/session/reserve/
complete. Create and complete have null expected revision/generation; all other
operations require the exact current values. Bodies are operation-specific and
no arbitrary extension or SQL is accepted. An exact retry binds the complete
normalized original request, including original CAS, owner, clock and references.

Create/revise body is the validated v1 ROE; revoke body is null. Session body
contains session_id,owner_id,clock,original_deadline_ns. Policy and deadline
fields are derived. Reserve body contains dispatch_id,session_id,owner_id,slot,
approval,audit,clock. Approval is exactly broker_id,consume_sequence1..32,
witness_sha256. Audit is exactly writer_id,audit_sequence1..1024,event_sha256.
These are nonsecret supplied declarations; accepting them does not verify a
review, durable audit, actual process or live channel. S4.2c must replace that
assumption with its separately pinned independent witness/custody chain.

Complete body contains dispatch_id,session_id,owner_id,outcome,observation,clock.
Outcome is one of reported_success,reported_failure,cancelled,unresolved.
Observation is null or exactly evidence_sha256,connections,request_bytes,
response_bytes; reported_success requires a nonnull observation with positive
connection/request/response counts, all within the reservation. Other outcomes
permit null or bounded partial counts including zero. No reported count refunds
the reservation or proves actual delivery. The evidence hash is a commitment to
operator-declared nonsecret evidence, not to credentials or secret wire bytes.
For identify, reported_success specifically declares identification of the
declared HTTP service prerequisite, not merely positive byte counts. S4.2b cannot
verify that declaration. Before S4.2c records it, the trusted integration must
independently validate actual parser/native evidence and the existing predecessor
predicate; an arbitrary caller-declared hash/count is insufficient authority.

The request domain is `b'recon-engagement-dispatch-request-v2\x00'`; the state
domain is `b'recon-engagement-dispatch-state-v2\x00'`, where each escape denotes
one zero byte. ROE hashing preserves the accepted v1 domain. State hashes cover
the exact post-event state object, not the recursive event history.

All mutation return values are exactly `schema_version:'2',kind:'data_only',
disposition,receipt`, with disposition recorded or already_recorded. Receipt is
exactly schema_version,engagement_id,event_id,sequence,operation,revision,
generation,status,session_id,dispatch_id,state_sha256,usage; optional identities
are null. It describes the historical post-event state. No field is named permit,
grant, authorized, send_allowed or execution_success. Data-only is not an
authentication claim and cannot be converted to a live capability by replay.
The constructor is the explicit exception: create returns an owned open store
handle, and event_receipt exposes its initial immutable receipt. The CLI closes
that handle and wraps the initial receipt as a recorded data-only result.

## Clock model: supplied data, not clock authority

A clock observation is exactly `utc_ns,mono_before_ns,mono_after_ns`, all bounded
integer nanoseconds. UTC is within2000-01-01 inclusive to2100-01-01 exclusive.
Monotonic values are0..2**63-1, ordered before<=after, with bracket width at
most50000000ns. The declared sampling procedure for later integration is
monotonic-before, UTC, monotonic-after. This increment only validates supplied
data; it performs no trusted clock sampling or physical release decision.
The bracket limits sampling delay, not external UTC accuracy. The operator-owned
host's UTC source is trusted; no NTP synchronization, absolute accuracy, remote
clock attestation or malicious-host clock defense is claimed.

For start S/end E and sample(B,U,A), conservative admission requires U>=S and
U+(A-B)<E. Its window-derived monotonic end is B+(E-U). Session registration
requires A<original_deadline_ns<=A+60000000000 and stores the immutable session
deadline min(original_deadline_ns, B+(E-U)). Addition overflow refuses.

Each later session observation requires B>=the preceding observation's A.
Compare UTC delta with the possible monotonic elapsed interval
[B-previous.A, A-previous.B]. Allow at most50000000ns discrepancy on either side;
outside it is clock_changed. This explicitly detects excessive rollback/forward
discontinuity. Forward observation at/after the end is window_closed even if
other values look plausible. Unknown/malformed clock data refuses. A tolerated
clock variation never extends an existing deadline.

Metadata also retains utc_high_water_ns, initially null. Every committed session,
reservation or completion sets it to max(previous value, supplied UTC), even a
completion whose clock status is uncertain. It never decreases on revision,
revoke, reopen or exact retry. A fresh session or reservation refuses when its
UTC+50000000ns is below that durable high-water. This catches excessive rollback
across sessions/handles without reusing monotonic values across processes.
An uncertain completion with a far-future well-shaped UTC may conservatively
block later reservations; it cannot replenish or grant authority. Correcting that
data does not have a reset API. A coherent hostile-host rollback of the whole
database is still outside this trusted-storage model.

Identify's action-ready time is session registration A; headers' is the preceding
identify completion A. Its immutable action deadline is the minimum of session
deadline, ready-time+charged runtime_ms*1000000, and the reservation sample's
conservative window end. Reservation requires A strictly before this deadline.
No review, commit, parser, completion or worker phase can start a fresh action
clock. The future physical workflow must use these original bounds at every
authority/release point and supervise cleanup; this model does not prove it.

Persisted monotonic values are historical evidence only. A reopened store has a
fresh process-owned owner reference and cannot continue an old session. Recovery
uses a new session and a fresh observation; it never treats serialized monotonic
values as current authority. No clock is inferred from filesystem timestamps.

Completion may retain already-reported progress after a revision, revocation,
deadline or window end. It consumes no new allowance. Its derived clock_status
is valid/window_closed/deadline_elapsed/nonmonotonic/clock_changed, determined by
the same comparison rules against the reservation's historical ROE window and
the latest clock-bearing event in that session, not a later revised ROE window.
Malformed clock shape still refuses. Priority is: nonmonotonic; window_closed
(before start or at/after the conservative exclusive end); clock_changed
(durable high-water rollback or excessive UTC/monotonic discrepancy);
deadline_elapsed; valid. Conditions are evaluated against pre-event state;
only afterward is high-water advanced. Its derived
continuation_eligible is true only for a reported_success identify completion
with current same revision/generation, recorded status and valid clock before
the immutable action/session deadlines. Otherwise it is false. Neither this
flag nor a reported_success record claims physical success or authorizes work.
New header reservation independently rechecks current rules, time and allowances.

## Process ownership, transactions and retry

Each successful create/open generates a fresh UUID4 owner_id in process memory,
records its creator PID, and exposes the ID through a read-only owner_reference
property. No API accepts a replacement current owner. Public session/reserve/
complete methods insert that current owner into the normalized request. Fresh
reserve/complete require the same current owner and registered session; a new
handle, even in the same process, cannot resume another handle's session.
Inherited post-fork handles refuse before lock/SQLite/close operations. Opaque
IDs describe custody intent; they do not authenticate a running worker.

Every mutation uses one BEGIN IMMEDIATE transaction. Validate the complete
before-state, exact event retry, expected revision/generation where applicable,
terminal/capacity/owner/phase/window/uniqueness predicates, new rows and usage,
then append its immutable event and update metadata. Validate the resulting
export before COMMIT. Refresh SQLite busy_timeout from the remaining original
budget immediately before BEGIN and COMMIT. Check original deadlines and held
file/directory identities before and after commit and cleanup. A commit failure
or late return is uncertain; never synthesize a successful receipt.

Create starts revision1,generation0,recorded,sequence1 and zero usage. Revise
increments revision and generation and invalidates old sessions; it preserves
all previous usage/records. Revoke increments generation and terminally marks
revoked. Registration adds one immutable session row, no usage. Reservation adds
one immutable reservation, full usage and one event. Complete adds at most one
completion row/event, no usage, even if current rules have changed/revoked; it
must refer to an existing reservation owned by this handle's session.

The identify slot may be reserved once per session. Headers require an eligible
identify completion in that same session and may be reserved once. A second
slot, session or handle never replenishes engagement counters. Uniqueness covers
dispatch_id, (session_id,slot), (approval.broker_id,consume_sequence) and
(audit.writer_id,audit_sequence). Concurrent last-allowance, same-dispatch,
same-approval and revoke/reserve tests use actual distinct processes and SQLite
transactions; retained order is database order, not a claim about dispatch.

Exact event retry returns the original immutable receipt as already_recorded,
before current terminal/CAS checks, with no new transition. Changed normalized
request under the same event ID conflicts. A dedicated retry(request) operation
is read-only: it may return only an already-existing identical event and otherwise
refuses. Thus it can recover a lost acknowledgment after reopen without changing
owner, restoring a session or creating another reservation. event_receipt(id)
is likewise historical lookup. Never retry automatically with a fresh event ID.

A precommit crash leaves no committed reservation/charge. A postcommit crash
retains the full charge and reservation even without an acknowledgment or
completion. An uncompleted reservation remains explicitly unresolved concerning
delivery; reopen does not invent zero bytes, run work, close native processes or
reconstruct grants. Existing completion bytes are reported evidence only. No
automatic reconciliation manufactures success, and no missing-log refund exists.

## SQLite, files and export

The adjacent inventory pins every DDL statement and implicit index. There are
six application tables: revisions,metadata,sessions,reservations,completions,
events. All except metadata are append-only under ten exact UPDATE/DELETE
rejection triggers. Foreign keys, typed integer/string bounds and the named
uniqueness constraints are mandatory. Verify exact sqlite_schema inventory/SQL,
user_version2, integrity/foreign keys, canonical rows, full replay and current
metadata equality on open and each transaction. No views, virtual tables,
unexpected indexes/triggers, extensions, user SQL or ATTACH.

Use page_size4096/max_page_count2048, DELETE journal, synchronousEXTRA,
fullfsyncON, foreign_keysON,trusted_schemaOFF,temp_storeMEMORY and busy_timeout
at most250ms clipped to remaining work time; query_onlyON for read-only opens.
SQLite limits are LENGTH2097152, SQL_LENGTH32768,COLUMN32,EXPR_DEPTH32,
ATTACHED0,VARIABLE_NUMBER64,TRIGGER_DEPTH8. At most4000 progress callbacks
of1000 instructions share the original operation budget; constructor configuration
and validation do not reset it. Constructor failure after opening a handle closes
all owned resources, including a final original-deadline failure.

Keep the accepted held-parent/private-directory custody model: owned0700 parent
and store, held no-follow directory descriptors and identity rechecks; regular
owned0600 single-link database and journal; no foreign directory entries except
the exact database and rollback journal. Open read-write only with mode=rw;
read-only with mode=ro/query_only, never immutable=1 or create-on-open. A valid
hot journal is recovered only by the trusted read-write path. Read-only refuses
before SQLite can recover. Do not open/close an extra descriptor for a live DB:
that can release process-wide POSIX SQLite locks. Preserve the meaningful real
external-writer witness across rejected DB inspection.

Exports are bounded canonical v2 snapshots with exactly schema_version,kind,
engagement_id,state,revisions,sessions,reservations,completions,events. kind is
engagement_dispatch_ledger. Sorted row arrays follow their event insertion order;
revisions/events are contiguous. Replay every normalized request, recompute all
derived action/policy/cost/clock/eligibility fields and digests, compare all rows
and metadata, and enforce capacities, exact historical row counts/references and
all uniqueness constraints. Each reservation is checked against the ROE and
usage current at its own event; honest totals exceeding a later narrowed cap do
not invalidate history. Internal consistency is not authenticity,
clock freshness or current authority; a coherent hostile-host rewrite/rollback
is outside this operator-owned storage trust model.

Inspection imports no SQLite/store/runtime module, creates no authority and only
reads a private regular export through held FDs, bounded reads, validation and
unchanged identity/byte checks. It refuses all inputs inside a directory with
reserved records.sqlite3 before opening any input. Output refuses that basename
and store parents, uses exclusive0600 creation, bounded writes/readback/fsync,
and never silently overwrites/removes a partial file. report_export validates
the caller raw_sha256 against canonical validated snapshot bytes. Python/CLI
reports match exactly and retain only finite counts/digests and explicit
data-only/unknown-physical-status statements. No universal redaction or host
rollback/zeroization claim is made.

## Public API and errors

The JSON inventory is authoritative for exact signatures/schemas. New modules
are engagement_dispatch_contract, engagement_dispatch_store and
engagement_dispatch_inspection; a separate scripts/engagement_dispatch_records.py
CLI. The existing modules remain unchanged. The contract exposes strict codec,
digest, fixed-plan, clock and replay validators; no runtime functions. Bounded
validators may read monotonic time and PID solely for their original work budget;
they never implicitly sample UTC or create an engagement-clock observation.

Store exposes create/open, owner_reference, append_revision, revoke,
record_session, reserve, complete, retry, event_receipt, snapshot, close and
context-manager entry/exit. CLI exposes only create/revise/revoke/show/receipt/
export/inspect; no reserve/complete/session or execution subcommand. Session
declarations and reservations are useful to a trusted same-handle Python caller
and later broker integration, not reusable capabilities from a one-shot CLI.

DispatchLedgerError exposes .code from the exact finite inventory. Public CLI
error is exactly schema_version:'2',error:CODE; no path/input/exception/SQLite
detail. Success exits0; supported refusal including malformed command line or
closed output exits2. Complete output is bounded; a broken pipe is not success.
No user-controlled callback, callable, class, SQL, operation name outside the
finite set, ambient credential discovery or legacy import exists.

## Validation and acceptance

The fixed inventory has80 exact portable function nodes:24 contract,
36 store,16 inspection/CLI and4 preservation. No count-only substitutions or
silent skips. Concurrency and commit-boundary crash tests use actual SQLite
connections and spawned Python processes. Narrow fault injection supplements
real transactions, never replaces them. Callback/deadline tests preserve failed
attempts and distinguish pure supplied-clock proof from real timing enforcement.

Before acceptance require independent schema/storage/evidence review, exact
focused cases, full portable suite, five existing CI jobs at reviewed head or
exact-tree merge, and a source/native closure preservation receipt. No native
client/daemon, network target, provider call or credential read is authorized by
this slice. Previously accepted native evidence is preserved as unchanged proof,
not relabeled as new execution or a closed S4.2 physical obligation.

Before S4.2c code, pin exact fresh witness/display protocols, source/runtime
closure and HTTP-only native projection, physical connection/payload metering,
actual clock sampling/release/cancellation bounds, process/FD custody and the
exact all26 parent case mapping. Both real concurrent physical variants, window
edges, revoke ordering and partial-delivery/crash cleanup remain mandatory.
S4.3 synthetic credential custody and S4.4 separately authorized real use remain
later; S4-G5 stays mandatory pending without explicit authorization.

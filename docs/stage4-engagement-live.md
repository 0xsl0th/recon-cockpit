# S4.2c — isolated live engagement enforcement

This contract and its adjacent machine inventory must be independently reviewed,
mutually consistent and committed before implementation or owned native validation
begins. Authorization to implement does not mark any acceptance gate complete.
Nothing here authorizes contact with an external target or access to credentials.

## Scope and preserved authority

PR102/S4.2b is accepted at merge
`d8e1a6fd12a3b7f3759aa8d790ce02a50b2340b1`, tree
`1cb1d5e8450b33bb9d73ed00f54b88ca52061a7c`. S4.2c is the previously selected
integration increment. It closes the live enforcement portion of S4.2; it is not
another preparation split. The current forecasts remain Stage4 6–7 PRs,
professional-v1 49–66, broader product 89–136. S4.3 credential custody, S4.4
real-use authorization and Stage4 as a whole remain open after this increment.

The one plan is the accepted `http-prefix-v1`: native HTTP identification and
then the fixed HTTP header request, against an explicitly owned synthetic
endpoint. The existing Action and Policy schemas, deterministic action IDs,
action parameters, native arguments, v1/v2 record stores, fixed reservation costs
and accepted parsers retain their meanings. No new tool, catalog entry, arbitrary
command, target resolver, credential reference, credential source or HTTP method
is introduced. The live integration accepts only a current ROE permitting both
HTTP profiles, HTTP not excluded, and `scope.http.path == '/'`. SSH declarations
may remain record data but never create a selected operation or runtime mount.

All 1,101 accepted baseline files are pinned by path, Git mode, blob and SHA256.
Only the eight named current-status documents may change; byte-pinned historical
contracts, every accepted execution/approval/audit/parser module, and all accepted
tests remain unchanged. New production/test paths are an exact allowlist in the
inventory. New modules may call the pinned pure validators and the deliberately
identified private seams; they may not monkeypatch accepted modules in production.

Acceptance requires the exact 26 S4.2 parent obligations, including all 18
physical S4-G3 obligations. Their original proof text, gate IDs and mandatory
variants are preserved verbatim in the inventory. An accounting receipt is not
a live witness. A portable transition test does not substitute for an actual
isolated review, durable write, process, connection, payload or cleanup witness.

## Fixed scope, costs and process lifetime

One broker owns one freshly opened v2 handle and supports at most two live
sessions. Each session has the exact two slots below. A broker cannot adopt an
old handle owner, restore a former session, reload grants or resume an unresolved
dispatch. A restarted broker opens a fresh handle and may register fresh sessions
against remaining current allowance; old admissions remain consumed.

| Slot | Predecessor | Actions | Connections | Request payload | Response payload | Client output | Native timeout |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `http_identify` | Fresh session | 1 | 3 | 4096 B | 4096 B | 8192 B | 5 s |
| `http_headers` | Actual eligible identify completion in this session | 1 | 1 | 256 B | 2048 B | 2048 B | 1 s |

The ledger always charges the full accepted row, including runtime cost
`min(30000, current_roe.max_action_ms)`. Observed partial delivery never refunds
or lowers a cost. A complete prefix reserves two actions, four connections,
4352 request bytes, 6144 response bytes and at most 60000 runtime milliseconds.
The original session deadline is at most 60 seconds; the original action deadline
is at most 30 seconds and also clipped by the session and ROE window. Total
session output is at most 10240 bytes. The broker lifetime is at most 120 seconds.
A smaller accepted ROE cap narrows these limits; it does not select an alternative
plan or a cheaper caller-supplied reservation.

The broker allows two inherited submitter channels to exercise concurrent calls.
They do not grant authority and cannot supply a successful review response,
clock sample, reservation cost, parsed success, native argv, runtime path or GO
packet. The channels have independent strict sequences and at most one pending
request each. Session/action identity is checked independently of channel identity.
A caller can submit the same real reference through both channels; at most one
actual consume, reservation and release can succeed.

## Authority and process partition

The trusted host orchestration creates a private owned namespace/process tree,
opens intentional channels and pins actual process identities. It supplies no
planner-selected runtime, executable or file. A private broker opens the explicit
operator-owned store under its own fresh handle identity. Only that broker has
the SQLite connection, database directory capability and the direct approval and
audit witness readers. The host retains no database descriptor on its behalf.
Concurrent explicit v2 CLI revocation/revision remains possible and is detected;
the integration does not assume all mutation travels through broker RPC.

Each session has an isolated reviewer, launcher and endpoint. The reviewer uses
either the terminal or graphical implementation chosen at session creation and
fixed in the envelope. The launcher independently validates policy, actual
runtime custody, action and the release envelope through an isolated admission
worker. The trusted host constructs and observes the fixed children; only the
launcher holds their request/release endpoints. During preparation a waiting
client and its admission worker may coexist through guarded GO. The admission worker redeems its real
one-use permit after GO, then is actually reaped before client release/native
exec. During active native execution only the client or parser child is present. The exact graph bound counts this overlap.
The endpoint is the synthetic service and the application-payload meter; it is
not a forwarding proxy. The client is either the exact native Nmap image or the
fixed GET worker. It has no database, approval/audit witness, endpoint ARM channel,
broker control FD or authority key. The parser has no network, database, reviewer,
launcher-release or endpoint capability.

Only inherited role-specific UNIX SEQPACKET channels carry authority messages.
Channel identity is pinned by actual descriptor identity and custody; role comes
from the inherited endpoint, never a caller-controlled JSON field. Unexpected
FDs, rights, truncation, ancillary data, credentials, duplicate packets, changed
sequence, wrong endpoint and channel EOF fail closed. Peer credentials on a
socketpair created before exec are not represented as proof of the later worker
PID. Actual payload identity uses pidfd, PID/start ticks, namespace readback and
sealed executable/source observations. No fallback to a less isolated mode exists.

The root trusted desktop remains in the graphical threat model, as with accepted
graphical approval. This does not defend against an operator, root or compositor
rewriting the entire trusted execution/evidence environment. It does defend the
finite planner/worker boundary and makes its observed process/file custody clear.

## Immutable review envelope

Canonical JSON follows the accepted closed-schema rules: ASCII encoding, sorted
keys, compact separators, no newline, no duplicate/unknown keys, floats,
nonfinite numbers, boolean-as-integer, lone surrogates or trailing JSON. All
nanoseconds are bounded integers. UUID4/hash formats match the accepted v2
contract; existing Action UUID5s remain unchanged. Return detached values.

The prepared object is exactly `schema_version, envelope, action, policy`.
`schema_version` is `1`; Action and Policy are the complete unchanged objects.
The envelope is exactly:

- `schema_version:'1', profile:'engagement-http-prefix-live-v1'`;
- `engagement_id, revision, generation, roe_sha256, scope_sha256`;
- `broker_id, ledger_owner_id, session_id, dispatch_id, reviewer_id, review_mode`;
- `slot, action_sha256, policy_sha256, runtime_sha256`;
- `window_start_utc_ns, window_end_utc_ns, clock_anchor`;
- `session_deadline_ns, broker_deadline_ns, action_ready_ns, action_deadline_ns`;
- `cost, output_limit, native_timeout_ns`.

`broker_id`, `reviewer_id`, session and dispatch identities are freshly generated
by their trusted owning components. `ledger_owner_id` is the actual new handle
owner. The broker derives every other field from validated current state,
accepted policy/actions, a pinned runtime manifest and its actual clocks. The
cost is the exact v2 reservation row. No input API accepts a fabricated envelope
as authority. `envelope_sha256` is SHA256 of the domain
`b'recon-engagement-live-envelope-v1\x00'` plus its canonical bytes. The escape
represents one zero byte. The full envelope, not merely a displayed digest, is
bound to every review/consume, started audit event, reservation crosslink,
admission request, GO, endpoint ARM, completion and evidence record.

Both actual views display the complete canonical Action (with the fixed rationale
omitted from the human-facing view), full canonical envelope, policy version and
digest, engagement/revision/generation/owner/session/dispatch, literal target,
method/path/port, fixed caps and remaining original time. Both views also derive
readable UTC start/end ISO text from the validated integer window alongside its
exact ns values; the countdown is labeled “Action time remaining” when action-clipped. The omission is a display
rule only: the complete original Action and its digest remain bound. No free-form
rationale or planner wording is rendered as an instruction or review decision.

Each view requires a fresh random challenge and explicit affirmative interaction.
Terminal review flushes pending input before its fresh prompt; graphical review
drains stale events, uses a fresh phrase and explicit button, and never treats
Enter alone as approval. The graphical worker exposes no Tk remote `send`
interpreter. Denial, EOF, changed envelope, closed view or deadline consumes no
new ledger reservation. Test PTY/GUI interactions are explicitly scripted owned
validation, not evidence of a person's judgment or permission for real targets.

The approval worker uses the existing in-memory ApprovalStore semantics plus an
immutable per-reference envelope binding held solely inside that worker. It does
not restore this map. A consume attempt burns the reference and its envelope
entry before mismatch/expiry checks, including wrong action/policy/envelope.
The consume request is checked against the original displayed prepared object.
consume_sequence counts every actual consume attempt, including failed burns;
successful direct witnesses may have gaps. The broker requires strict increase
and the exact expected request/reference, not an invented contiguous-success
sequence.
Only a successful actual consume emits the direct broker witness. Its sequence,
worker identity, exact consumed reference digest, full envelope commitment,
action/policy digests and original expiry are retained. An RPC reply or a copied
old witness is insufficient without the current inherited witness endpoint and
fresh role sequence. The new profile has its own explicit maximum witness age
of 10 seconds, clipped by original grant/action/window expiry; unchanged legacy
five-second validators remain unchanged. Both approval and audit freshness are
rechecked at guarded GO. No refresh or reconsume is attempted on expiry. No affirmative planner RPC or unattended allow mode exists.

## Durable audit and admission

Reuse the unchanged confined append writer, canonical producer-event encoder,
durable JSONL append/fsync and direct one-way witness. A new engagement adapter
clips every write/witness exchange to the current original phase deadline; it
must not inherit the accepted host adapter's renewable five-second wait. The
writer cannot acquire a store handle or issue a grant. The broker validates the
actual writer bootstrap/custody and the complete successful witness, including
writer identity, sequence, durable flag, exact original action/policy/session and
full engagement-envelope producer-event digest.

The started producer event contains exactly the accepted started-event fields
plus `engagement_live`, whose value is the full immutable envelope. It has
`event_type:'execution_started', execution_status:'started'`, the exact backend
and `decision:'approval_required'`. The machine inventory fixes the complete
field set. The witness `event_digest` hashes `audit_protocol.event_bytes` of this
complete producer event. It does not hash only the old projected claims. Durable
JSONL adds event_schema_version/event_id/timestamp/source; those wrapper bytes
are retained and validated separately, never mistaken for producer-event bytes.

The broker requires actual successful approval consume and this exact durable
started audit witness before invoking unchanged `DispatchLedger.reserve`.
The ledger approval declaration sets its field named broker_id to the actual
approval witness reviewer_id, not the live broker_id, and uses that actual consume
sequence; the audit declaration uses that actual writer/sequence/full
producer-event digest. Reservation success must be `recorded`, not
`already_recorded`. A stored receipt alone cannot repeat a physical release.
Missing audit, unavailable witness, stale grant, revision/generation mismatch,
window/deadline refusal or insufficient allowance yields no new release.

The legacy audit witness packet contains a finite floating-point monotonic
`issued_at`. Preserve its exact original bytes as bounded base64, verify the
legacy closed packet grammar and actual endpoint, and hash those raw bytes. The
new integer-only envelope rule does not normalize, round or rewrite this legacy
packet. The new approval witness uses integer nanoseconds. The distinct new
10-second freshness check applies to the actual decoded legacy instant without
changing the accepted writer or its bytes.

The successful reserve commit is durable dispatch admission and irreversible
full-cost consumption. It does not assert that a client was sent or a request was
received. All later failure paths retain the reservation, even when zero payload
was delivered. A lost reply cannot be retried into authority.

## Guarded release, revocation and concurrent winners

After reservation, the broker enters the pinned trusted private
`DispatchLedger._transaction(write=True, deadline=...)` seam. This opens the same
SQLite BEGIN IMMEDIATE writer transaction used by explicit revoke/revision and
fully validates current replayed state. No public callback or new store API is
added. Inside this transaction the trusted broker checks current engagement,
status, revision/generation, actual handle owner/session, exact reservation and
fixed action/policy/runtime/envelope, original deadlines, current trusted clock,
actual approval/audit witness bindings, and unique local not-yet-sent GO state.
The prepared envelope never changes. A separate effective lease deadline is the
minimum of its frozen action deadline, the actual v2 reservation deadline, current
conservative window end, original session/broker deadlines and both witness
freshness/grant expiries. Fresh reservation clock conversion can narrow the
reviewed deadline; it must never extend it or require equality between unstable
clock-conversion results. GO and ARM carry this narrowed value and crosslink the
original unchanged envelope and actual reservation.

The only external effect inside that guarded transaction is one bounded
nonblocking SEQPACKET send of the exact GO to the inherited launcher endpoint.
There is no retry after EAGAIN, short send, uncertain return or timeout. Mark the
attempt locally before sending. Do not wait for launcher/endpoint/client/GUI or
native completion while holding the writer lock. The accepted after-state
validation, custody checks and transaction cleanup remain active and within the
same original operation deadline. No persistent new GO row or schema migration
is introduced.

This orders a committed revoke/revision versus the fresh guarded check and GO:
a revoke committed before the guard forbids release; a revoke waiting behind a
successful GO cannot be presented as if it had prevented that already-admitted
work. It does **not** make a database commit atomic with network I/O, retract
bytes, or prove that no TCP byte can appear after revocation. GO followed by a
failed postcheck/commit/reply is `possibly_sent`/unresolved, cancels and reaps;
its admission stays charged. No automatic reissue, refund, replay or recovery of
that action is available.

All role preparation and isolated admission preparation happen before
successful approval consume. The waiting identify client is a confined Python
wrapper with sealed fixed native image/argv, not an already-running Nmap ELF.
No ptrace or new trace authority is introduced. On GO the launcher rechecks its
current window/deadline, redeems the exact one-use admission permit and releases the
wrapper to exec the fixed native image. The endpoint remains unarmed while the
parent observes the actual pinned PID's native ELF/maps/task/FD identity. Only
then does it ARM the endpoint, which may admit/read/respond. Native Nmap may
connect/send into the listener backlog after GO and before endpoint ARM; this is
not presented as packet-level no-send. Failure or a too-fast exit before required
image observation fails closed without timeout extension.

The GET client remains the fixed confined Python image. Its actual wrapper/source
identity is verified before release; the launcher sends ARM, requires its bounded
matching acknowledgment, then releases that GET worker. Neither the ARM wait nor
native execution occurs inside the database guard. Both operation-specific paths
bind the same exact GO, current role identities and effective lease deadline.
The endpoint has a direct broker liveness/cancel channel as well as the narrower
launcher ARM channel. It gives CANCEL/EOF priority over ARM and all reads/writes;
cancelled state is terminal and a delayed ARM cannot resurrect it. The client
inherits no channel that could authorize or cancel another role.

The simultaneous last-allowance witness uses actual distinct reviewed actions:
session A first completes real identification, then A.headers and B.identify
race against exactly one remaining action allowance. Both reach the actual
transaction path; exactly one commit/release/effect can win. The duplicate-dispatch
witness first obtains one actual reviewed grant, performs its one successful
consume and exact durable started audit, then sends the same real direct-witness
pointers/dispatch identity simultaneously through both broker ingress channels.
Both calls must reach the actual broker boundary; exactly one reservation, GO
and physical effect can win. The finite owned helper may call the private real
approval/audit/broker interfaces, but may not issue a fake grant or forge a witness.
Two public execute calls alone are insufficient for this race because the second
may stop at the already-burned reviewer before reaching the broker. Actual repeated
reviewer consume and sequential broker replay are separate proofs.

## Actual clock checks and bounded external-state watch

The broker samples monotonic-before, UTC, monotonic-after itself using integer
nanoseconds. The accepted at-most-50 ms bracket, conservative inclusive start /
exclusive end conversion, persisted UTC high-water and change/rollback checks
are unchanged. The bracket bounds sampling delay, not absolute UTC accuracy.
Trusted host UTC remains an explicit assumption; no NTP or hostile-host clock
attestation is claimed. Old persisted monotonic data never restores live time.

Reviewers, launcher and endpoint independently check their original monotonic
stop and current UTC at each effect boundary. The endpoint checks before each
accept, request read and response write; the launcher checks before ARM/release.
A globally visible UTC forward jump is not deferred until the broker's next
store poll. Unknown/backward/discontinuous clock observations fail closed under
the accepted tolerance; no successful late cleanup can extend a deadline.
Physical fault cases use fixed sealed test clocks and synchronized stimuli in
all relevant trusted roles. They do not change the operating system clock or
claim that one worker-local injected clock represents every other role's clock.

The broker gives revocation/expiry/cancel work strict priority before accepting
another queued request or continuing another synchronous phase of an existing
request, including between reserve and guarded GO. State-watch scheduling is at most 100 ms; at most one
already-running bounded operation can precede it. Every synchronous broker
phase is at most 2 s and clipped to original action/session/broker deadlines.
The next full validated store read is itself at most 2 s. Consequently explicit
external durable revoke/revision is detected or the broker fails closed within
4100 ms, followed by at most 2000 ms owned cleanup: at most 6100 ms total. Earlier
original deadlines override this maximum. A failed/blocked read cancels rather
than interpreting an unverified cache as current authorization. This is not a
claim of immediate revocation, 100 ms enforcement, or zero in-flight bytes.
UI/native/child completion is asynchronous to broker watch/control service; no
30 s UI wait, 5 s audit exchange or queued request may starve the watch. The physical
worst-case gate measures actual observation and reaping, not only a mocked timer.

## Metering, completion and uncertain state

The owned endpoint meters admitted connections, accepted request payload bytes
and actual response payload bytes delivered by successful sends. It checks fixed
per-slot remaining capacity and deadlines before every accept/read/write,
reserves positive remaining write capacity before attempting output, counts only
actual return counts and treats partial/EAGAIN/failure conservatively. No read
requests more than the remaining request budget. No write attempts more than the
remaining response budget. An exhausted cap closes/refuses without probing one
extra byte. Kernel queued/unread bytes, TCP headers and retransmissions are not
claimed as accepted/delivered application bytes.

The exact private HTTP request/response grammar and native probe inventory are
fixed separately in the machine inventory. Identification requires actual native
exit/output, independent parser result and endpoint request/response agreement.
The headers step requires this exact same-session predecessor and actual fixed
GET/header evidence. Positive counts alone are insufficient. Only after these
checks may the broker call unchanged `complete(..., outcome='reported_success')`.
The v2 name remains a data schema; the new live evidence supplies its provenance.
Failure/cancel/unresolved records carry exact bounded actual partial observations
or null where unavailable; missing data is never synthesized as zero or success.

Completion after revision/revocation/expiry may record already-admitted progress
under the unchanged v2 rules. It does not continue execution or unlock another
step. Broker death, lost post-admission acknowledgment or unobserved cleanup
leaves an unresolved consumed reservation. A recovery view distinguishes durable
admission, observed GO, observed client effects, last acknowledgment and final
cleanup. It may expose historical data and fresh sessions, never restore a
pending grant, old owner, old session, earlier release or uncharged retry.

## Inspection and evidence boundary

A live bundle has a closed exact regular-file inventory totaling at most 16 MiB.
When actually observed, it retains initial and final validated v2 exports (at most
2 MiB each) with their real seal/source status. Unavailable exports remain explicitly
unavailable; a post-cleanup read-only recovery export is separately labeled and
never substituted for a missing broker snapshot. It also retains the actual
bounded durable audit JSONL (at most 1 MiB), ordered role/protocol/meter transcripts
(at most 2 MiB), at most four actual client raw-output pairs with each pair bounded
by its original slot output cap, sealed source/runtime/native manifests, actual
clock/process/namespace/custody observations and cleanup receipts. The machine
inventory fixes individual filenames, schemas and all remaining byte bounds.
No arbitrary path, imported state or executable file is accepted by inspection.

`write_live_bundle(directory, *, manifest, members, deadline=None)` performs
exclusive private directory/file creation only after all live authority cleanup.
It has its own original 15 s data-only packaging budget, clipped by an optional
caller outer absolute deadline. It preserves a partial output directory on
failure, never overwrites/deletes/retries it, and never promotes an unsuccessful
live operation to success. This phase is explicitly separate from the expired
action/session authority clocks. A runner reserves its packaging budget in its
outer bound and reports packaging failure separately.

The Python inspector and CLI independently validate the complete envelope,
reconstruct ledger history, verify full audit-producer crosslinks and reparse the
retained native outputs through the same isolated parser-only boundary. This is
explicit permission for bounded parser-only processes; it creates no broker,
reviewer, client, endpoint, SQLite handle, target connection or live authority.
Each bundle permits at most four parser runs, at most 2 s each. Total inspection
including held-FD readback, all checks, parser cleanup and successful output is
at most 15 s. Each nested accepted v2 validation retains its own at-most-2 s budget
clipped to that outer deadline; setting a shared context to 15 s must not widen
an accepted operation. Report output is at most 8192 bytes.

Saved data is consistency evidence, not authentication against a host coherently
rewriting every unsigned artifact. All claims distinguish actual process/clock/
request observations, supplied declarations, direct runtime witnesses and
inferences. Missing values remain null/absent under their exact schema, with
explicit populations/denominators for metrics. Diagnostic/test instrumentation
is identified and excluded from ordinary useful-operation claims. A complete
negative gate can pass while the attempted operation correctly has no success.
A production-run manifest has `case_id:null` and its report has `case_passed:null`,
never a fabricated test identity. Here production_run means ordinary production
code operating only against the owned synthetic endpoint, never an external
assessment. An owned-gate manifest binds one exact frozen case/variant and its
independently evaluated proof predicate; caller-supplied expected outcomes are
not authority for case_passed. The inspector API is `inspect_live_bundle(path, *, deadline=None)`.
Its CLI accepts only the saved directory and `--help`: exit 0 for complete valid
useful or expected-negative gate evidence, exit 1 for valid incomplete evidence,
exit 2 for invalid input/unavailable inspection. Production operation outcome is
reported separately from whether its evidence is complete.

## Public and internal integration APIs

The root-owned `engagement_live_session.EngagementSession` is the trusted host
orchestrator. Its public interface is:

- `start(store_directory, audit_path, *, review_mode, control) -> EngagementSession`;
- `open_session(*, ingress=0) -> session_binding`, choosing the unused preallocated
  slot with that ingress index, and refusing a third or reopened session;
- `prepare(session_id, slot, *, ingress=0) -> prepared`, deriving the exact action
  in the broker and completing actual role/admission preparation;
- `review(prepared, *, control) -> approval_reference | None`, through the actual
  configured view, never a Boolean or textual approve RPC;
- `execute(prepared, reference, *, ingress=0, control) -> live_result`, consuming
  the real grant, durably emitting its exact started event, and submitting only
  the matching direct-witness references to the broker;
- `cancel(session_id)`, `revoke(*, expected_revision, expected_generation,event_id)`,
  `snapshot() -> bounded status`, and `close() -> cleanup_receipt`.

`control` is the original execution/cancellation object, with a fixed earlier
absolute deadline. Child scopes clip it; they never replace its cancellation
identity or grant a new clock. A concurrent caller may use ingress 0 and ingress 1
for the same prepared dispatch/reference. Each channel serializes its own one
pending request; concurrency across the two is real. Cancellation, signal and
EOF are separate terminal controls, not delayed behind a blocking execute call.

Only `open_session` starts a persistent session clock. Broker READY allocates two
fresh UUID4 session IDs in advance but does not claim those sessions have started
or write their session records. The root preallocates the exact descriptor graph,
reviewer IDs and two slot indices before starting the broker. The broker then
returns its own fresh broker ID, actual v2 owner ID, two allocated session IDs,
full validated ROE/scope/policy and their digests. The worker business READY
contains no parent observation; the host builder adds its independently obtained
pidfd/source/process compound readiness to the public broker_ready object. A
worker-provided readiness Boolean cannot manufacture that parent proof. Root starts the other workers
later using their already-bound descriptor peers, the broker-created IDs and
these exact returned values. All inherited roles validate the full supplied
scope/window against the digest; a scope hash alone is insufficient for firewall,
parser, effect or display setup. No descriptor is added to the broker after its
initial bootstrap. An explicit current revision change cancels the existing
broker's sessions; it requires a fresh broker to select a different ROE/scope.

The host `EngagementBroker` builder accepts only the fixed runtime manifest,
explicit private store directory, original control and the preallocated private
channel/role bundle. Its methods are `start`, `open_session`, `prepare`,
`dispatch`, `cancel`, `revoke`, `snapshot`, `close`; its dispatch parameters are
`prepared_sha256, reference_sha256, consume_sequence, audit_sequence`, all checked
against the exact authoritative pending object and actual direct witnesses.
PREPARE may return one pending acknowledgment while asynchronous role setup
finishes; its final reply remains clipped to the same original action clock,
while broker watches continue. A known DISPATCH refusal after charging returns
its live_result with the consumed receipt/actual uncertainty, not a generic RPC
error that discards that state.
These reference arguments are pointers to independently required observations,
not supplied assertions of approval or audit. A fabricated success reply cannot
satisfy them. The host does not issue GO or invoke a store mutation on the
broker's behalf.

`EngagementApprovalService(policy, session_id, *, frontend, session_binding,
runtime_manifest, witness_slot, control)` receives the already allocated witness
writer slot and fixed reviewer ID; it does not allocate a replacement channel.
Its methods are `start`, `review(action,policy,envelope,*,control)`,
`consume(reference,action,policy,envelope,*,control)`, and `close`.
The private `witness_slot` includes the exact descriptor identity/role binding
created before broker startup; no caller can substitute an endpoint after READY.
A consume returns a closed result containing `accepted,consume_sequence,
reference_sha256,witness_sha256`; only accepted true has a witness digest. A
reference is an ephemeral opaque capability, never copied into the persistent
ledger. Approval RPC transcripts in released evidence use an explicitly labeled
projection containing the reference digest, not the original capability. They
are not falsely represented as raw unredacted request bytes.

`EngagementAuditService` reuses the accepted isolated writer, bootstrap and
producer grammar while providing `emit(event,*,control) -> receipt` under the
original clipped phase deadline and exact matching writer reply. It owns the
preallocated audit writer endpoint; its direct witness reader belongs only to
the broker. The reader returns the original legacy witness bytes as well as the
strictly validated complete producer-event binding. No approved event is accepted
from a generic file, host dictionary or projected old claims without this live
channel custody.

`EngagementLauncher.start(session_binding, role_bundle, control)` starts the
fixed isolated launcher with its preallocated peers and starts its one fixed host
supervisor. `prepare(prepared,control)` checks the actual preparation acknowledged
by the broker after isolated admission and host-observed child startup.
`progress(control)`, `cancel(reason)` and
`close()` expose observation/cleanup only. There is no public launch/release
method accepting a GO dictionary: release comes only from the inherited broker
peer. The launcher never reads SQLite or constructs a successful approval/audit
claim itself.

The native runtime seams are `inspect_runtime(control)`,
`snapshot_role(bundle, role, control)` and
`validate_readiness(role, value, bundle, *, expected_binding=None)`.
`prepare_endpoint(*, runtime, session_binding, broker_peer, arm_peer, control)`
returns the pinned endpoint owner and its bounded readiness, startup-only namespace
descriptors, progress and cleanup interfaces. The ARM peer transfers only at the
initial launcher bootstrap; the host retains no second writer.
`prepare_client(*, runtime, prepared, endpoint_identity, scope, control)` returns a
`WaitingClient` with `release`, `observe_native`, `collect` and `close`, enforcing
the operation-specific sequence. The parser API is
`parse(*, tool_id, raw, stderr, scope, truncated, control, runtime)`, returning
`(parsed, parser_receipt)`; it accepts no arbitrary parser or executable.
Those local client/parser APIs remain host-only. The live launcher must use
`_prepare_supervised_client(*, runtime, prepared, endpoint_identity, scope,
control, supervisor)` and `_parse_supervised_observed(*, tool_id, raw, stderr,
scope, truncated, control, runtime, prepared, supervisor)`. Its
`SupervisorChannel.start_child(*, child_slot, prepared, control)` returns a
`LauncherChild` owning the real preallocated request endpoint and cached actual
host READY; it has no fabricated process or pidfd interface.
`validate_live_context(value)` crosslinks actual role, client, meter and process
observations before a successful completion is recorded.

In host builder signatures, `session_binding` carries the complete validated
`session_opened` reply (its `binding`, ROE, scope, policy and session receipt).
Each builder extracts the immutable `binding` and includes the full validated
ROE/scope/policy in its fixed worker bootstrap. The pure `session_binding` schema
itself remains the exact closed binding object; this argument convention does
not add fields to that schema or accept an alternate scope.

The pure new contract module exposes `canonical`, `decode`, `validate_prepared`,
`validate_envelope`, `envelope_digest`, `prepared_digest`, `derive_prepared`,
`derive_effective_lease`, and `validate_live_result`. These are data validators;
calling one does not create authority. Their optional current-time input for
replay is an explicitly supplied retained phase observation. The live broker,
reviewer, launcher and endpoint obtain those inputs from their own trusted clock
sampler, never from ingress. The protocol module owns exact role operation shapes,
closed packet validation and bounded SEQPACKET I/O; no imported global registry,
mutable profile selector or arbitrary callback chooses a role.

The internal implementation symbols are fixed in the inventory's implementation_api
section. The shared exception is `LiveError(code)` with `.code` equal to one full
closed public code. `canonical(value, *, max_bytes=32768)` and
`decode(raw, *, max_bytes=32768)` return bytes and detached data respectively,
with explicit caps no greater than 2 MiB and depth 64; control frames also enforce
depth 12 and their smaller role bounds. Reused accepted validators remain inside
the same original 2 s deadline context. Pure contract code does not import runtime
builders or launch anything. Clock helpers accept retained observations for
replay; only the fixed live samplers obtain current clocks.

The broker host module owns `preallocate_role_bundle(review_mode)`. It creates
the exact two-slot broker/session channel graph and reviewer IDs once, before broker startup,
and returns a private `PreallocatedRoleBundle`. Its named worker-rights maps
match the runtime initial-rights table exactly. `take_worker_rights` and the
role bootstrap/RPC-pair takers transfer custody once; the receiving builder closes
them in a finally path even if transfer or startup fails. `close` closes only
still-owned descriptors, never a recycled number. The parent retains only the
fixed host peers and three separately reopened read-only evidence memfds.
It does not retain duplicate authority writers or add a new channel to an already
bootstrapped role after READY. It also creates six fixed child stdin pairs per
session before broker startup: client, admission and parser for each of the two
HTTP slots. Their request ends transfer once to the launcher at INITIAL. The host
retains each opposite end only until its fixed child is spawned, then closes it.
The launcher alone sends that child's committed INITIAL and later protocol
messages. Child INITIAL carries no rights. No role creates a later channel for
transfer into an already bootstrapped worker.

Protocol helpers are `encode_frame`, `decode_frame`, `send_packet`,
`receive_packet`, `send_once` and initial-only `send_initial`, with exact signatures
in the inventory. Ordinary sends wait only within the original control and make
one atomic attempt; they do not automatically repeat after an attempted send.
Guarded GO uses `send_once` without a readiness wait inside the writer lock. Only
`send_initial` may transfer the exact first descriptor set; an uncertain transfer
is terminal, never retried. Subsequent receives reject all ancillary data.

The exact schema objects and per-operation request/reply unions in the adjacent
inventory are authoritative for all required fields and types. Broker READY
contains the actual owner/engagement/current revision and generation (0..64),
validated full ROE/scope/policy, actual clock anchor, fixed broker deadline, two
allocated slot identities, initial sealed export reference and observed readiness.
OPEN_SESSION returns full immutable session_binding plus its actual recorded v2
session receipt. PREPARE returns the exact Prepared and compact hash references
to actual launcher/endpoint/client/admission preparation observations. Large role
observations live in the bounded transcript/process member, not duplicated past
the control packet cap. Snapshot replies are bounded current-status summaries;
they do not falsely claim to carry a 2 MiB full export.

All hashes have a fixed object: envelope/prepared use their named zero-byte
suffix domains; action/policy/ROE/scope preserve accepted digest functions;
ledger_state_sha256 and reservation_state_sha256 equal the exact accepted v2
receipt.state_sha256 domain hash, never the entire export hash; raw/file/witness
hashes cover their exact bytes. runtime_sha256 is SHA256 of canonical validated
execution-runtime bundle, with no added domain, excluding process/FD/clock and
diagnostic observations. A runtime.json wrapper file has its own manifest-member
SHA256 distinct from that execution-runtime digest. admission_permit_sha256 covers the exact canonical retained permit projection,
replacing its opaque reference with reference_sha256; it is not an unreplayable
hash of a hidden full-capability object. The private actual reference is still
compared and burned by the isolated admission worker. The new prepared domain is
`b'recon-engagement-live-prepared-v1\x00'`.

The admission worker has only its prepared/bootstrap input and private launcher
RPC, no DB or actual approval/audit reader. Its decision is an independent policy/
profile/budget preparation, never consent. Its lifetime is clipped by the same
original action/session/broker deadline (at most 30 s), with active issue/redeem
exchanges at most 2 s each and CPU 7 s. While waiting it prioritizes cancel/EOF; it
does not renew the permit. ISSUE returns a single fresh 256-bit opaque reference
bound to the prepared object and original expiry. REDEEM after GO burns it before
comparing the exact Prepared/GO/effective lease, and emits one bound successful
receipt or refusal. The launcher requires actual successful redemption and
actual worker reaping before client release. The accepted admission worker and
its legacy five-second permit lifetime remain byte-identical and are not reused
as if they supported this new profile.

## Descriptor and packet contract

The initial broker descriptor set is exact: stdio/control expected by its sealed
entry wrapper; two ingress SEQPACKET peers; two launcher-control peers; two
endpoint cancel/meter peers; two half-closed approval witness readers; one
half-closed audit witness reader; one distinct trusted bidirectional lifecycle-management peer;
the bounded sealed bootstrap/runtime descriptor; two preallocated export
memfds; and one preallocated transcript memfd. The store connection/directory descriptors are opened only by the broker
under the accepted custody rules. Each slot also has host↔reviewer RPC and
launcher↔endpoint ARM pairs outside the broker. Role supervisors use separate
bounded readiness output plus their actual pidfd/readback; they do not compete
with the broker for the same packet-reader endpoint. Unused peers are closed
promptly in every process. Children inherit only their exact role allowlist.

After terminal/graphical sealing, ordinary packets use socket.send or os.write,
not sendmsg, which the accepted reviewer restrictions deny. recvmsg is used only
to enforce framing and reject all ancillary data.

No SCM_RIGHTS transfer is accepted after any worker's initial bootstrap. No
channel accepts an unsolicited additional descriptor, even when the payload
would otherwise validate. The initial/final export memfds are distinct from the
DB, capped at 2 MiB and sealed WRITE/GROW/SHRINK/SEAL after canonical export. Their
bounded completion references contain bytes/SHA256/seals; the parent verifies
those actual seals and bytes before saving evidence. They cannot be reused to
restore a handle. Large export bytes are not hidden inside a control packet or
counted as though they fitted its bound. Before transfer the trusted host creates
O_RDWR memfds, reopens its own retained peers O_RDONLY through the pinned FD and
closes every host writable duplicate. Broker validates its O_RDWR descriptor;
the host validates its O_RDONLY same-device/inode peer. The third memfd is the
broker-only bounded transcript writer. The parent reads it as final only after
required seals; after confirmed broker reaping, unsealed bytes may be retained
only as explicitly partial evidence, never a final snapshot.

Every new control packet is exactly `schema_version:'1',channel_id,sequence,
operation,body`; sequences start at 1 independently in each direction. Packet
maximum is 32768 bytes, nesting depth 12. A channel admits at most 64 ordinary
request/reply pairs; the two ingress channels together admit at most 64 ordinary
requests. Two additional terminal cleanup frames per direction are reserved and
cannot authorize work. A reply body is exactly `request_sequence,status,code,
data`, where status is `ok`, `pending` or `refused`; ok/pending have code null,
refused has one fixed public code and data null. Data schemas are operation-specific.
A wrong role/operation/sequence or malformed framing is terminal to that channel
and its active session; an expected policy/window/budget refusal is a valid
refused reply without widening or silently retrying the action.

Ingress operations are exactly OPEN_SESSION(slot_index), PREPARE(session_id,slot),
DISPATCH(prepared_sha256,reference_sha256,consume_sequence,audit_sequence),
CANCEL(session_id), REVOKE(expected_revision,expected_generation,event_id),
SNAPSHOT(null), CLOSE(null). No input field accepts clocks, costs, decisions,
partial completion counts or arbitrary output. The separate trusted bootstrap/
lifecycle peer carries fixed initial role process/readiness observations and
STOP only in the host→broker direction; it never bypasses PREPARE, consume,
audit, reserve or guarded GO. Broker→host lifecycle messages are exactly
SESSION_STOP(session_id,reason,observed_at_ns,cleanup_deadline_ns) and
BROKER_STOP(reason,observed_at_ns,cleanup_deadline_ns). The absolute cleanup
deadline is no later than observed_at_ns+2000000000 and the original deadlines.

The trusted host has one dedicated lifecycle monitor thread polling broker
pidfd/channel and pending stop flags at most 100 ms apart. It performs only fixed
role cancellation/cleanup, not caller callbacks or authority decisions. The
host process allows main, this monitor, at most two API submitters and at most
two fixed child supervisors: six explicit orchestration threads, not isolated payload
RLIMIT_NPROC. Reviewer close sets its private stop flag and shuts down RPC before
waiting for any RPC lock, so a blocked 30 s review cannot delay cancel. Broker
revocation/death and lifecycle EOF close the active view, burn volatile grants
and reap the reviewer within the original 2 s cleanup bound, including monitoring
latency. Broker EOF/death reserves at most 1900 ms after the ≤100 ms detection poll.
Other role deadlines and direct EOF remain independent defenses. A stopped view
or late review reply never recreates a reference or authorizes another action.

Broker→launcher operations are PREPARE(prepared), GO(release), CANCEL(reason),
STOP(null). Launcher→broker operations are READY(readiness), PREPARED(receipt),
NATIVE_OBSERVED(receipt), RESULT(result), CLOSED(worker_stopped). A worker-stopped acknowledgment never
substitutes for the parent’s actual process reaping. Broker→endpoint
operations are PREPARE(prepared), CANCEL(reason), STOP(null); endpoint→broker
operations are READY(readiness), PREPARED(prepared_sha256,envelope_sha256,ready_at_ns),
METER(observation), CLOSED(worker_stopped). Endpoint PREPARE stores and validates
the immutable pending action before review; it neither arms nor accepts traffic.
Launcher→endpoint uses
ARM(release,slot), checked against that pending Prepared and followed by its exact
ACK or refusal. Reviewer RPC uses only
REVIEW(prepared), CONSUME(reference,prepared), CLOSE(null). It permits at most two
actual review challenges and 32 consume attempts per reviewer. It may send one
actual successful direct witness per consumed grant; failed consumes do not
fabricate a successful witness. Repeating the same reference never refreshes it.

A release object is exactly `schema_version:'1',broker_id,ledger_owner_id,
session_id,dispatch_id,envelope_sha256,prepared_sha256,reservation_event_id,
reservation_sequence,reservation_state_sha256,approval_witness_sha256,
audit_witness_sha256,guard_clock,effective_lease_deadline_ns,effect_stop_ns,
release_sequence`. The release sequence is 1 for that dispatch and cannot be
reissued. The original envelope remains accessible and byte-identical. The
narrowed lease is derived from the exact original, actual reservation, fresh
clock and actual witness expiries. `effect_stop_ns` is the earlier of that lease
and each original action/session/broker deadline minus the reserved 2 s cleanup
margin. If no positive work interval remains, refuse without release. Final
cleanup must finish by the earlier original deadlines, and within 2 s of stop;
expiry of the shorter witness lease may trigger cleanup before those deadlines.

The new approval witness is exactly `schema_version:'1',reviewer_id,broker_id,
ledger_owner_id,session_id,dispatch_id,consume_sequence,reference_sha256,
envelope_sha256,action_sha256,policy_sha256,issued_at_ns,expires_at_ns,accepted:true`.
It is at most 4096 bytes. Every field is checked against the actual prepared object,
reviewer bootstrap and receive-time clock. The original store's internal expiry
may be floating-point; the new worker narrows it to integer ns and to the original
context expiry, never rounding it upward to extend authority. Witness SHA256
commits to exact canonical bytes. Legacy audit witness raw packet maximum 2048
and its grammar remain unchanged; its base64 evidence encoding is separately
bounded. No new wrapper silently canonicalizes the legacy floating time.

Broker state per dispatch is finite: prepared, preparing, ready_for_review,
awaiting_witnesses, admitted, release_attempted, running, settling, settled, or
terminal_unresolved. All successful transitions retain their real observations;
the host cannot set this state. A reference/grant may be denied or burned before
admission without a new durable usage event. Only a fresh recorded reserve enters
admitted. Any attempted GO sets release_attempted before its send. No edge returns
to prepared/admitted after release_attempted. Terminal cancel/revision/revoke/EOF
prevents delayed packets from reviving any prior state.

The cumulative role transcript is at most 2 MiB and 4096 rows. Each of at most
two broker segments has 896 KiB and 1984 rows, including its 8 KiB/eight-row
terminal reserve. All host producers share the remaining 256 KiB and 128 rows;
at most 96 are supervision projections. The same host budget spans both broker
generations in a canonical bundle. Before any ordinary effect, the broker
checks capacity for its bounded current row and terminal state; it
fails closed if it cannot retain the corresponding observation. Watch rows are
compact exact phase/clock/state-sequence/hash observations, not repeated 2 MiB
exports. Packet and transcript capacities are independent; neither silently
widens to fit another limit. Full raw capability values are excluded from the
released transcript under the explicitly declared projection above. The final
transcript member contains at most two exact broker-memory byte segments from
strictly sequential broker instances and one host role-observer segment. Every
segment has its own source, broker identity, offset, byte length, SHA256, seal
status and completeness. The slices cover the file exactly and are validated
separately; a partial trailing line never merges into the next segment. The
combined member remains at most 2 MiB/4096 parsed rows. Host approval, root
observer and supervision producers all reserve their bounded current exchange
using one short-lock allocator, with reserved terminal tickets inside that same
budget. Host supervision reserves before enabling receive; host-originated
exchanges reserve before send, and child startup reserves before spawn.
Count ceilings do not guarantee that every maximum-width row fits;
byte exhaustion may refuse earlier. Unused current-exchange reservations may
be released, but retained records are never discarded. The final combined bound
is checked again during packaging without truncation or a success claim on
overflow. This is not an escrow for every future post-GO observation.

Host approval/admission RPC projections are explicitly role-observer records,
not invented broker observations. The projection hashes commit to saved projected
objects. An original wire hash/length, when actually observed, remains a separately
labeled opaque commitment; the inspector cannot reproduce hidden capability bytes
from their digests and never hashes the projection as if it were the original
packet. Direct witness, sequence, reference digest and complete action/envelope
bindings provide the specified consistency checks. Each segment's row sequence
starts at 1; concatenation is not falsely described as global chronological order.
Actual retained phase times and channel sequences determine causal checks. Closed
row kinds and request/reply projection unions are in the authority inventory.

Public live errors are closed codes with prefix `engagement_live_`: invalid_input,
limit_exceeded, timeout, cancelled, unavailable, unsupported_runtime,
invalid_runtime, invalid_role, invalid_channel, invalid_sequence, invalid_frame,
invalid_prepared, invalid_witness, stale_witness, approval_denied,
approval_unavailable, approval_unknown_or_replayed, audit_unavailable,
audit_not_durable, foreign_owner, session_unavailable, dispatch_replayed,
revision_changed, revoked, window_not_open, window_closed, clock_changed,
allowance_exhausted, prerequisite_missing, admission_unavailable,
release_unavailable, meter_refused, parser_unavailable, cleanup_incomplete,
evidence_invalid, evidence_incomplete, output_exists. No raw exception, SQL, path, reference or
OS diagnostic appears as a public error code. Bounded private diagnostics remain
separate and cannot convert a refusal into success.

## Resource inventory and validation

The adjacent inventory's exact resource, process graph, namespace construction,
FD phase sets, source/native file lists and syscall/readiness checks are part of
this contract. The broker has AS 256 MiB, FD 64, one task, CPU 120 s and lifetime 120 s;
its SQLite caps remain 8 MiB main / 16 MiB journal, 2 s per operation and 4000 progress
callbacks. The broker passes `min(now + 2 s, original remaining work deadline)` into
the private guarded transaction; it may not pass a 30 s live deadline as if that
were the accepted 2 s transaction allowance.

Nmap retains AS 256 MiB/CPU 5 s/FD 64/task 1/FSIZE 0/native 5 s/aggregate output 8192.
GET retains AS 256 MiB/CPU 5 s/FD 64/task 1/FSIZE 0/native 1 s/aggregate output 2048.
Parser has AS 128 MiB/CPU 2 s/FD 32/task 1/wall 2 s/output 4096. Endpoint has
AS 256 MiB/CPU 5 s/FD 64/task 1 and no writable filesystem. Admission has AS 256 MiB,
CPU 7 s/FD 64/task 1; original lifetime ≤30 s, active exchange ≤2 s. The launcher
has FD 64/NPROC 1/FSIZE 0 and exactly eleven initial steady descriptors; it stages
no child images and forbids process, namespace and socket creation. All child
staging occurs in the trusted host under the original finite snapshot bounds.
Graphical Tk's one
prewarmed notifier thread is explicitly counted; its task set cannot grow after
TSYNC sealing. No whole-process bound is inferred solely from RLIMIT_NPROC.

The owned graph has at most 12 payloads, 13 wrappers and one serialized setup
helper: 26 descendant processes and 28 descendant tasks. The trusted host's one
main thread, one lifecycle monitor, at most two API submitter threads and at most
two fixed child-supervisor threads are separate from that graph: six host threads
maximum, with no per-child thread. The external X server/test drivers are disclosed and
not included as isolated payloads. The eight persistent payloads are broker,
audit, two reviewers, two launchers and two endpoints; up to two waiting clients
and two admission workers may coexist before GO. Admission is reaped before
client exec/ARM; parser replaces a reaped client. Exact helper invocation counts
and bwrap/UID-map structure are in the inventory. A child never attempts to
nsenter a sibling user namespace. The trusted host enters the pinned endpoint's
user/net namespaces before constructing each launcher or networking client;
each payload receives its own user/mnt/pid namespaces. Parser and admission also
unshare net. Every namespace lease is acquired afresh from the held live endpoint
pin, checked before and after acquisition and closed during startup. Namespace
FDs never reach launcher or native payloads. Fixed `nsenter --no-fork` and the
shim's `execv(bwrap)` preserve the same wrapper PID/start identity.

The broker's named FD inventory peaks at 21 with bootstrap descriptor closed
before opening the store: 13 communication FDs, three evidence memfds, two held
store/parent directory FDs, SQLite main plus possible journal, and selector FD.
A bundle admits at most two sequential broker instances, never two simultaneous
brokers. The predecessor and every owned role must be actually reaped before the
successor starts. There are at most four actual client dispatches across both
instances. The peak graph above remains 26 processes/28 tasks; the conservative
cumulative inventory is at most 47 unique PID/start identities per instance and 94
per bundle. A full broker graph has at most 20 payload identities, 21 wrapper/
audit-reaper identities and four nft helper identities: 45, within the existing
47 ceiling. Six nsenter/shim/bwrap image chains reuse six wrapper identities;
their image invocations are counted separately, not as six additional processes.
The earliest observed initial export and latest observed final export
retain their actual broker identities; intermediate event prefixes and receipts
are replayed from the full history, not mislabeled as separately captured files.
Actual lifecycle observations distinguish bootstrap, steady, transient journal
and closed/sealed phases. There is no broker audit-producer FD: the host adapter
owns it. Descriptor numbers are builder-chosen; exact role/type/device/inode,
access mode and absence of extras are independently checked.

There are exactly 288 selected test-node identities: 273 new (160 portable plus
113 owned native) and 15 existing fresh physical integration regressions. The
full portable expectation is 29085; the native deselection expectation is 2347.
The existing S4.2a 68 / S4.2b 80 tests already belong to the 28925 baseline, not new
counts. New canonical native bundles are exactly 113 and saved Python/CLI
inspections exactly 226; these are independent replay calls, not additional native
cases or useful actions. Native execution selects 128 fresh nodes including the 15
regressions. Closed new-file allowlist count is 39, yielding 1140 tracked files;
1093 accepted nonstatus files remain byte/mode-identical. All 26 parent mappings
and 18 physical witnesses must pass, with no count-only substitution.

Before any acceptance run, freeze a clean full source tree and installed runtime
manifest, preserve exact collected nodeID-to-gate union, and retain source/native
hashes before and after. Native validation uses owned namespaces and actual
terminal/GUI test interaction, no external target or credential. Preserve every
failed attempt, exact logs/XML/bundles and diagnostics; no automatic retries or
rerun-until-green policy is implied. Any corrected implementation is refrozen
and its affected/full required proof explicitly rerun. The complete portable
suite and supported CI matrix remain separate gates. The final read-only audit
checks exact IDs, artifact bytes, original source/runtime and full parent coverage;
none of these counts alone marks S4.2 accepted.

## Fixed owned instrumentation boundary

Ordinary production source has no fault opcode, clock override, barrier control,
affirmative shortcut or test environment switch. An owned native gate may use only
its predeclared sealed source variant at an exact compiled phase from the case
inventory. Retain baseline and variant source hashes plus bounded fixed
configuration, actual process/role identity and the explicit owned_gate label.
A test variant cannot mint a successful approval, substitute a fake witness,
weaken policy/current-state/runtime checks or expand target/effect caps.

A barrier uses a fixed test-only frame/phase on the existing role channel in the
sealed variant, with a separate explicitly bounded instrumentation projection.
There is no production handler for that frame, no extra ambient FD and no arbitrary
callback. The harness and validator accept only the exact case's declared phase
and fixed source/configuration hash; unknown or diagnostic variants cannot satisfy
a gate. Clock fault variants synchronize a fixed stimulus across every relevant
role. Actual elapsed/cleanup/watch latency uses separately retained host monotonic
observations unaffected by that test clock; a fabricated clock delta is not a
physical 6100 ms revocation-latency witness. Such variants never change OS clocks.

A scripted owned review can still produce a useful actual native operation. Its
operation outcome remains useful when proved, while evidence_class/instrumentation
keep it separate from ordinary uninstrumented production-success populations.
Role-only probes have no fabricated client or ledger rows. Denial cases must reach
their declared actual isolated boundary and retain actual no-effect/cleanup proof;
a host-only ValueError is not relabeled as a physical worker refusal. A case whose
real earliest guard differs from its declared expectation must be corrected openly
before acceptance, without weakening the production boundary merely to reach a
later guard.

## Runner entrypoint

The root-owned `scripts/engagement_live.py` accepts only `--execute`,
`--store-directory PATH`, `--audit-path PATH`, `--output-directory PATH` and
`--review-mode terminal|graphical_v1` (plus `--help`). Duplicate/unknown options
refuse. Without `--execute` it emits only the fixed closed inert object
{schema_version:'1',profile:'engagement-http-prefix-live-v1',execute:false,
description:'Owned HTTP engagement execution requires --execute, an existing engagement store, audit and evidence paths, and an explicit review mode.'}
under 8192 bytes and 2 s. Supplied options are validated even without `--execute`,
but no operator store, runtime, target, credential or evidence path is opened;
normal Python import reads are not described as zero filesystem reads. Each PATH
is nonempty UTF-8 of at most 4096 bytes with no NUL or newline; the actual private
custody validators enforce filesystem identity and permissions. Effects require
the explicit execute flag and all four path/mode inputs; there are no target, argv,
clock, deadline, consent, unattended or arbitrary configuration flags.

The ordinary CLI opens one session and attempts its two exact approved slots.
The Python API supports two sessions only for bounded concurrent use; neither
path expands the plan. Its outer bound is 150 s: live startup/execution/cleanup
within 120 s, then exclusive data-only packaging within 15 s and parser-only saved
inspection plus successful stdout within 15 s, all clipped by the original outer
deadline. The 60 s session, 30 s action, native 5 s / 1 s and narrower leases remain
unchanged. The CLI emits the same deterministic inspector report, not a packaging
receipt presented as operational success. Failures remain separate: a valid
refusal can have complete evidence; failed packaging never upgrades live status.
The Python EngagementSession API ends at live cleanup; callers explicitly choose
the separate data-only save/inspect operations.

## Contract correction S42C-A01

The first implementation pass exposed a missing transcript union for the direct
approval witness. The witness is an unframed canonical packet; recording an
invented outer protocol frame would misrepresent what the broker received. The
explicit `approval_witness` transcript kind retains the exact bounded raw bytes
as base64, their SHA256, the matching decoded witness and actual broker receipt
time. A framed protocol row cannot stand in for this direct packet.

The inventory also fixes the member containers for process observations, operation
results, cleanup, export custody and core-case selectors. An operation's broker
result is null when no actual acknowledgment was received. Its outcome remains
unresolved, and the inspector derives admission and GO observations from retained
history and channels; a missing reply never means zero effect. Core selectors
reference exact retained rows and reconstructed state digests, without supplied
pass/fail or expected-outcome assertions.

A recovery export records its fresh read-only data handle, verified store identity,
original two-second observation interval and actual closure separately from the
broker's sealed export descriptors. It can start only after all live roles are
verified reaped. Saved inspection does not reopen the store.

This correction follows the original contract commit `cf1b47f` and precedes any
native acceptance run. It changes no authority, target, test identity, count,
source allowlist, byte cap, deadline or roadmap increment. Original contract and
review receipts remain retained.

### A02: actual meter forwarding and complete client scope

Before any native acceptance, integration established two missing data paths.
The broker forwards the exact validated final endpoint METER to the matching launcher over its already inherited broker-control channel. This observation supplies no release authority. It must follow the original endpoint METER observation, match the pending dispatch and original GO, and may not replace or revive an active slot. The launcher verifies the existing meter grammar, exact envelope/GO/endpoint/slot/ARM binding and original deadline before deriving its final client result. Forwarding preserves the full meter bytes as a canonical protocol object; no supplied host summary substitutes for endpoint observation. Missing, conflicting, repeated or late settlement cannot produce usefulness. Cancellation/EOF remains terminal and takes priority. The entire framed packet remains bounded to 32,768 bytes including wrapper overhead. Saved replay requires the original endpoint observation before the identical launcher forwarding observation.

The fixed client bootstrap also includes the complete accepted scope already validated by its launcher. The client checks the scope digest against the immutable Prepared envelope and compares the derived fixed action exactly. This permits the actual configured SSH denial witness; scope data grants no authority. The keyword-only client API is `prepare_client(*, runtime, prepared, endpoint_identity, scope, control)`. Descriptor ownership, fixed native arguments, permissions, resource caps, source allowlist and all 288 case identities remain unchanged.

### A03: ingress identity and retained nested observations

Each inherited ingress uses its own exact preallocated ingress_channel_id, sent in its slot bootstrap. IDs must be distinct across both slots and fixed for that broker lifetime. No additional channel or observer identity is invented. Lifecycle channel_id remains broker_id; reviewer/launcher/endpoint IDs remain their actual worker IDs.

OBSERVATION is launcher-to-broker only, over the existing inherited role-bound channel; it grants no authority and cannot cause GO or ARM. Each observation matches the actual active Prepared dispatch. Capture slot and aggregate stdout+stderr length obey8192 identify or2048 headers, independently of32768 complete frame cap. Exact decoded bytes/counts/SHA match; zero-byte captures remain explicit. At most one capture pair per dispatch and four per invocation bundle. role_readiness records only actual client/admission/parser children observed by this exact isolated launcher; their parent observer identity, source/runtime digest, namespaces, prepared references and separately recorded child lifecycle must match. Existing NATIVE_OBSERVED carries actual Nmap ELF observation. cleanup records exactly the actual observed child identity and same original bounded reaping result. capability_projection uses the existing closed admission ISSUE/REDEEM union with reference digests only; no raw permit or approval capability is exported. The broker validates every object, reserves transcript capacity before accepting ordinary continuation, and records the exact frame as an ordinary launcher protocol row. Missing/conflicting/duplicated capture or missing child evidence refuses usefulness; no host-supplied summary substitutes. Client-result capture digests and parser input/output commitments resolve these actual captured bytes and child observations. Meter remains independently received from endpoint then explicitly forwarded to launcher by A02. Session packaging may extract these exact retained broker transcript objects after sealed completion or confirmed reaping; it never invents host observations or presents the relay as a new host process readback. Parser receipt remains inside existing client_result; no extra parser_receipt kind is needed. Admission projections remain inside their actual launcher OBSERVATION protocol records; replay never relabels that relay as direct broker or host witness custody.

The launcher alone receives `/run/engagement-runtime-bundle.json`, containing the same complete validated runtime bundle as read-only mode 0444 sealed data (seals 15), bounded to 2 MiB. One temporary snapshot descriptor counts against the existing 128-file and 128-MiB staging limits and closes before payload entry. The launcher validates the full canonical digest and selected manifest before confinement; the trusted parent independently rereads the mounted bytes through the pinned actual process root. No new steady descriptor, SCM transfer, executable, permission or child choice is introduced.

The inventory now spells out both existing owned fixture scopes: A uses `owned-example`, HTTP `10.77.0.10:8080/` and SSH `10.77.0.20:2222`; B uses `owned-example-alternate`, HTTP `172.23.0.10:18080/` and SSH `172.23.0.20:12222`. Inspection compares labels to actual retained scopes. Ordinary production code retains the same bounded owned scope grammar. All 288 case identities, 39 new paths, process limits, deadlines and roadmap estimates remain unchanged. No native acceptance preceded this correction.

### A04: actual startup observations

`processes.json` includes a required `startup` array of at most 94 existing closed parent observations with stage exactly `entry`. Startup observations retain only actual trusted parent readback at stage entry, without worker READY or a claim of sealed self-checks. Startup/readiness/native observations share a ceiling of94 distinct payload PID/start-time identities; repeated stages of one actual payload count once. Every known startup payload must resolve actual cleanup. Runtime source/role capture is separately required and entry identity alone does not prove post-bootstrap ROE/source validation. No endpoint/client identity is invented when startup refused before those roles were created. The existing 1-MiB member cap and all gate identities, runtime limits and source paths remain unchanged. No native acceptance preceded this correction.

### Pre-acceptance amendment A05: actual execve denial

The existing `creation_denial.operation` enum includes `execve` with `flags=0`, so the already-required new-image denial can retain its actual returned failure, errno and unchanged task observations. A successful exec cannot supply a returned denial. Multiple existing boundary observations retain the required fork, namespace and exec attempts under the same gate; no case, capability, source path or resource limit is added.

### Pre-acceptance amendment A06: owned connection-cap fixture custody

Only owned-gate cases `S42C-X45` (`meter_connection_cap_identify`) and
`S42C-X46` (`meter_connection_cap_headers`) may use the exact instrumented
connection fixture in `runtime_contract.owned_meter_connection_fixture`. The
ordinary endpoint descriptor maximum remains **7**. Initial bootstrap rights,
entry validation and all production socket restrictions remain unchanged.

The fixed sealed test endpoint creates one abstract AF_UNIX/SOCK_STREAM listener
and four identify peers or two headers peers in its private network namespace,
after ordinary bootstrap/network setup and before sealing. These are injected
metering primitives, not native-valid HTTP traffic or additional execution
authority. No peer is transferred after bootstrap and no new socket creation is
allowed after sealing. The same fixed per-case runtime source is sealed in the
worker closure and used by its trusted parent. No arbitrary descriptor-limit
argument or skip flag enables this path.

Actual READY and independent process readback retain all **11** identify or **9**
headers descriptors: six ordinary steady endpoint descriptors, one named fixture
listener and four or two named preconnected peers. The inventory pins the exact
FD numbers and purposes, actual types, identities and flags; the worker's digest
must match the parent readback. One accepted-stream descriptor may exist at a
time and closes before the next accept, giving a **source-derived** transient
upper bound of **12** or **10**. READY does not measure that transient peak. Any
claim of a measured peak additionally retains the actual complete peak-time FD
inventory as a bounded private artifact and pins its hash in the native run
receipt. No descriptor is omitted to make an ordinary inventory appear valid.
The role's RLIMIT_NOFILE 64 and parent readback ceiling 32 remain unchanged.

Saved validation establishes this exception only after structural member loading
has identified exact owned-gate X45/X46 metadata, canonical case/variant/role
configuration and both sealed endpoint/runtime source commitments in the selected
runtime and endpoint role closure. A private `_retained_fixture_validation(loaded)`
context scopes the same exact allowance around context, authority/transcript,
parser replay and report checks, including writer validation, and resets it on
every exit. It permits only the fixed complete endpoint inventory for that
fixture; all source, namespace, process, cleanup, clock and meter checks remain
required. Missing or conflicting metadata, missing/extra descriptors, a different
case or role, or ordinary production evidence refuses. The case proof, observed
control readiness and saved meter must resolve the same fixture runtime. This
pure saved-data allowance creates no live capability or authority.

The other nine byte/partial/clock primitive cases reuse the already inherited
stdin socket and add no descriptors. Their injected labels and actual saved
meter-event derivation remain mandatory. This amendment adds no process, target,
permission, inherited right, case identity, source path, deadline or byte budget.
All 288 cases, 113 new native cases, 160 portable cases, 15 accepted regressions,
26 parent obligations and 18 physical parent obligations remain unchanged. No
native acceptance preceded this amendment.


### Pre-acceptance amendment A07: actual audit inventory and retained custody

An audit-only diagnostic of unchanged source `82f4e8d` observed six steady
descriptors. The accepted audit worker retains the pinned read-only libffi image
imported by its unchanged planner module. The former five-descriptor assumption
also assigned append and witness purposes to the wrong positions. The diagnostic
receipt is `c4cb1ba6412c55d93d74323c149f1db10218ee190e274a8ff9f04aaeab95e9e7`;
it is diagnostic evidence, not native acceptance. Original failed runs remain
retained.

The unchanged accepted audit worker has exactly six steady descriptors: stdin/stdout/stderr plus audit_append, audit_witness and audit_import_libffi, with complete FD0..5 inventory. Derive the three non-stdio purposes from actual held identities and the pinned mounted library; do not infer append/witness identity from descriptor position. No unnamed, optional or count-only extra descriptor is accepted. Initial transferred rights remain append_file and audit_witness (the one-way writer) only.

Required audit_readiness.import_image is the closed seven-field object destination/device/inode/mode/size/sha256/read_only_mount. The parent actually rereads the exact selected-runtime libffi mounted image and held descriptor under the original startup deadline, verifies regular0444 and O_RDONLY without O_PATH, unchanged device/inode/mode/size/bytes/SHA, a read-only mount and the same executable mapped-image destination/device/inode. The retained read_only_mount is true; all other roles retain their existing verified import-descriptor closure. Accepted audit_worker/planner_worker sources and audit source partition remain unchanged.

Audit readiness binds audit_append descriptor device/inode/mode to append_identity and initial.device/inode, with private0600 regular file and O_WRONLY|O_APPEND and no O_PATH; audit_witness descriptor matches initial.witness transferred writer endpoint, nonblocking SEQPACKET lineage. source_manifest is the distinct reader endpoint held by the broker and must not be conflated with initial.witness.

Protocol validation may validate the closed audit readiness shape without runtime authority. Service acceptance, broker AUDIT_OBSERVED admission and retained transcript replay must additionally require the same mandatory runtime-binding check: import_image destination/size/SHA resolves the single selected libffi native row in the exact runtime parser manifest, and descriptor/map identities resolve that actual observed image. No optional omission at an authority site.

Retained AUDIT_OBSERVED must be actual broker_memfd lifecycle received traffic with observer_id and channel_id equal to that broker_id, null session/dispatch, and at most one admitted audit readiness per broker instance. Preserve existing channel sequence rules. Its source_manifest reader device/inode must match the unique audit_witness descriptor in separately retained actual readiness of the same broker. Missing actual broker readiness is incomplete; conflicting identity or host-projected substitution is invalid.

Every actually retained AUDIT_OBSERVED parent payload PID/start_ticks and wrapper PID must resolve actual role=audit cleanup with exit/returncode/reaping, descriptor closure and chronology. Include those audit observations in the same cumulative94 distinct payload identity ceiling and all-reaped checks alongside startup/readiness/native observations, deduplicating only identical identities and rejecting conflicts. Missing cleanup remains incomplete. Do not fabricate compound new-role readiness for the accepted audit worker, or invent an audit process when startup ended before one was observed.

Existing portable cases W04/W07/I05/I12/T06/T10 carry the additional regression
obligations. All 288 case identities, 39 new paths, 26 parent obligations,
18 physical parent obligations, 160 portable cases, 113 new native cases and
15 accepted regressions remain unchanged. This amendment adds no process,
transferred right, target, action, credential, resource-limit allowance or budget.
The exact six-descriptor audit inventory replaces only the inaccurate five-FD
assumption; it does not permit an arbitrary extra descriptor. No new native
acceptance preceded this amendment. Stage 4 scope and roadmap estimates are
unchanged.


### Pre-acceptance amendment A08: host construction and exclusive child channels

The bounded launcher diagnostic at frozen `9e02273` identified an incorrect
socket-pair denial witness. Its receipt is
`08ff2ed212093b7f6142208ef70c6470f6904bb89f1c99a38d6ff931af52e994`.
The witness and actual session failure retention were corrected at `7322466`;
32 focused runtime cases and five private retention checks passed. Neither that
diagnostic nor those portable checks is native acceptance. Source review then
identified two independent blockers: a child inherits its parent's seccomp
filters across fork/exec, and the launcher's hard FSIZE 0 prevents sealed child
image staging. Adding a child filter cannot undo the inherited denial. Preserve
all four original failed native attempts and the diagnostic separately.

The trusted host now constructs, observes and reaps the fixed client, admission
and parser children. The isolated launcher remains the sole holder of their
request/release endpoints and of endpoint ARM. It receives GO only from its
existing broker peer. Host supervision neither issues nor redeems an admission
permit, writes a client GO, sends parser input, arms an endpoint, emits an audit
event, nor changes the ledger. There is no new isolated network-capable builder
role. This replaces the former nested-launcher construction path, rather than
relaxing its network filter.

Before broker startup, the existing role bundle creates exactly six child
SEQPACKET pairs for each of its two session slots. Fixed child slots are identify
client/admission/parser and headers client/admission/parser; their roles are
respectively nmap/admission/parser and headers/admission/parser. Every slot has
one fixed worker UUID and at most one start. The launcher receives the six request
ends, together with broker_control and endpoint_arm, in its sole INITIAL rights
transfer. Its complete initial inventory is FD 0 through 10. The host closes all
copies of those request ends and retains only the opposite child ends until
their one fixed spawn. Unused ends close during cleanup.

Slot declarations bind the actual pair-creation identities, canonical launcher
descriptor and opposite child stdin identity, exact role and worker UUID. The
two socket endpoints have different inodes; equality is never used as a peer
test. Check the exact original pair declaration and both observed endpoint
identities. Queues must be empty before bootstrap handoff. A swapped endpoint,
duplicate retained writer, unexpected descriptor, slot reuse, role change or
foreign session/runtime refuses. Each child still enters with only FD 0/1/2 and
receives an INITIAL with no rights. Its actual FD 0 must match the fixed opposite
endpoint, and its bootstrap digest must match its committed argv and READY.

Each launcher has one fixed host supervisor thread. At most two such threads
exist; host thread capacity changes explicitly from four to six. The supervisor
is started before the launcher is admitted for preparation. It alone owns its
child spawn state, pipes, pidfds, process readback and cleanup. Concurrent ingress
calls cannot compete to read the supervision channel or replace an active
child's original control with a fresh caller deadline. The lifecycle monitor
remains independent, and no additional thread is created for a child or request.
Both supervisors must terminate before a successor broker can start.

The existing launcher stdin/host channel becomes a closed supervision protocol
after INITIAL. It remains separate from broker GO and endpoint ARM. It has exact
request/reply correlation, monotonically increasing per-direction sequences and
the actual launcher identity. The closed operations are START, OBSERVE_READY,
NATIVE_BEGIN, OBSERVE_NATIVE, CAPTURE and REAP, with their exact schemas in the
inventory. Every complete encoded frame, including its wrapper, is at most
32768 bytes. No ordinary message carries ancillary data or descriptors. Reject
the first malformed, unsolicited, duplicated, wrong-phase or foreign-slot frame
and terminate that supervisor; do not retry a command. There are at most 22
received requests per session, including a terminal refused request. STOP/EOF
and the earliest original deadline take priority over ordinary progress.

Startup is deliberately split. The host first registers a pending owner, takes
the original bounded setup lock, derives the fixed payload/argv/source snapshot
and proves that the complete BOOTSTRAP reply fits. It spawns the fixed child with
the already-owned child stdin end and host-local stdout/stderr/info pipes. It
publishes actual process ownership immediately and independently verifies entry,
FD 0, source images, namespace and PID/start identity. It then returns only the
exact committed bootstrap object. It cannot wait for READY before returning
that object. The launcher validates its fixed slot, session, Prepared, runtime,
worker and deadline, and sends INITIAL once through its sole request endpoint.
Only the later OBSERVE_READY exchange reads actual READY and returns the host's
independent sealed-process observation. No synthetic Popen, parent channel or
readiness object stands in for a real child owner.

For nmap and headers, the host obtains a fresh short namespace lease exclusively
from the still-pinned live endpoint. It verifies liveness and the exact retained
user/net identities before and after acquisition. No request may name a PID,
namespace path, descriptor, arbitrary role or executable. Fixed nsenter
`--no-fork` and the fixed shim's `execv(bwrap)` enter only that endpoint's user/net
namespaces; setup descriptors close before payload entry. Admission and parser
instead receive their own private net namespaces. The host serializes snapshot
staging and namespace/helper setup across both supervisors under the original
control; waiting for that lock does not create a new time allowance.

Launcher confinement becomes a leaf boundary: all required process creation,
namespace creation and socket/socket-pair denial witnesses must actually pass.
NPROC is 1, NOFILE is 64 and FSIZE remains 0. The launcher mounts neither bwrap,
Nmap nor child worker executables and performs no child source staging. Its
closed source closure retains only the validation/proxy modules it actually
uses. The full runtime bundle remains immutable data for verifying observed
children; its presence does not permit executing another role.

After actual broker GO and actual admission redemption, admission must be
observed reaped before client release or ARM. NATIVE_BEGIN establishes one
conservative host monotonic native deadline before the launcher writes client
GO: no later than the original effect/action/session/broker deadline or now plus
five seconds for Nmap/one second for headers. Both parties use that exact
returned deadline. OBSERVE_NATIVE and CAPTURE cannot renew it. Nmap's actual
pinned ELF/maps observation still precedes ARM. Headers require ARM ACK before
NATIVE_BEGIN and the subsequent client release. Parser replaces the already-reaped client and receives
input directly from the launcher.

The supervisor enforces the earliest outstanding startup, action and native
deadline even when no further request arrives. During active native work it
also drains bounded stdout/stderr and enforces the shared 8192/2048-byte output
cap. A stalled launcher cannot extend native lifetime or postpone overflow
handling until CAPTURE. CAPTURED contains only child_slot, the existing compact
raw capture, status and the actual single-child cleanup receipt or null. It
does not duplicate complete readiness/native objects. Missing or failed cleanup
cannot support useful success. Subsequent close uses the actual cached receipt;
it does not issue another REAP or create a later cleanup allowance.

Cancellation uses one shared first-stop epoch. Autonomous timeout/overflow or
Session shutdown publishes the earliest absolute cleanup deadline, at most two
seconds after that stop. Later close calls clamp to it. Stop/channel shutdown
does not wait for an operation or ingress lock, and no state lock is held across
I/O, Popen, readback or wait. The supervisor owns FD closure; another thread must
not close or recycle a pidfd/procdir it is still using. A pending-start token
exists before Popen. A result published after the stop fence is immediately
owned and cleaned under the same recorded deadline, never bootstrapped or
released. Unresolved publication, an unjoined thread or incomplete reap is
failed/unknown cleanup, never complete. Retain actual supervisor start, stop,
join, channel closure and pending-owner terminal observations alongside actual
child cleanup; pidfd reaping alone does not prove thread termination.

All parent observations, including audit and the new host-supervised children,
resolve one actual trusted-host PID namespace and observer identity. Retained
host source facts are distinct from the launcher's relays and the broker's
receipt of those relays. Save fixed slot/pair identities, exact bootstrap
reconstruction inputs and commitment, actual entry/READY/native observations,
raw capture and cleanup once in their existing bounded evidence members. Closed
host supervision projections retain original request/reply sequence, byte count
and digest and resolve those exact source facts. A bootstrap hash without all
its reconstruction inputs is insufficient. A null reply remains null.

START may arrive before the outer broker PREPARED acknowledgment. Retain its
actual validated Prepared and source provenance even if that outer reply is
lost; do not invent a successful result. Actual host capture survives a missing
launcher relay, but missing required broker traffic remains incomplete. Saved
inspection checks both direct host facts and exact relayed commitments, rejects
conflicts and orphaned identities, and never relabels host observation as
launcher-parent readback. The exact schemas and per-source reservations in the
inventory fit the unchanged 18-file, 16-MiB bundle and combined 2-MiB/4096-row
transcript limits. Each source reserves its bounded current request/reply and
terminal evidence before acknowledging further work. Capacity is an additional
fail-closed limit: a source may exhaust it before its maximum lifetime or action
count. This does not promise escrow for every future effect-bearing frame.
Exhaustion after GO retains actual partial/uncertain evidence and durable started
audit/quota state, without a useful result, refund, truncation or dropped history.

The isolated peak remains 26 processes/28 tasks. The conservative cumulative
47/94 distinct-process ceilings remain, with the corrected 45-identity derivation
and six separately counted nsenter image invocations. Broker, audit, approval,
GO, endpoint meter, targets, actions and credential scope are unchanged. The
inventory assigns the new supervision, custody, timeout, concurrency and cleanup
obligations to the existing exact cases. All 288 identities, 39 new paths,
26 parent obligations and 18 physical parent obligations remain. Every affected
native obligation requires fresh physical proof after implementation and a new
clean source/runtime freeze. No native gate was accepted before this amendment;
S4.2c remains one integration increment and the roadmap estimates are unchanged.

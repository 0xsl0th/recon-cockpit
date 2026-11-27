# S4.3 — synthetic credential custody and one authenticated status read

**Design draft and exact obligation map; not an execution-ready contract.**
The user authorizes a corrected, independently reviewed design-only publication.
Implementation and acceptance remain later work with every obligation retained.
The historical6–7 PR estimate is superseded by this additional design checkpoint.
Recovery bootstrap design is specified below; runtime execution remains disabled.

S4.2c is accepted at merge `3e51cf8912370f6833b75e5bd2b182479e9e7671`, tree
`a970eddaf534516f79f09f8377c255872b1b785d`. PRs #104 and #105's competition
documents and the exact `pytest==9.1.1` dependency are part of that baseline.
The historical [Stage 4 contract](stage4-engagement-custody.md) and its
[inventory](stage4-engagement-custody-gates.json) remain byte-identical.
Their old pending wording is historical; it does not reopen S4.2c.

The adjacent [machine inventory](stage4-synthetic-custody-gates.json) copies
all **19 S4.3 obligations** verbatim. Sixteen require physical proof; the three
replay obligations use the original retained observations. Planned test names
are reservations for later implementation, not collected or passing tests.
Ten additional authority witnesses cover the new broker/store. They do not add
canonical obligations or reopen S4.2c: its accepted evidence covers different code.
Runtime identities and the new authority store's exact schemas still need the
specific bindings listed below. No placeholder, passing parser test or case
count permits native execution or a custody acceptance claim.

## Selected operation and engine

The proposed engine is a new minimal CPython `ssl.SSLObject`/`MemoryBIO` client,
a strict parser inside the custody boundary, and a new owned TLS status-service
fixture. No provider worker, provider model/configuration, legacy credential
loader, generic HTTP library, catalog profile or ambient HTTP proxy is activated.
The accepted provider workers are design precedents only: their credential
appearance checks and secret-bearing launch digests do not satisfy this contract.

The one production path is `GET /api/status` at IPv4 `127.0.0.1:9443` **inside a
fresh disconnected owned service namespace**. Host is exactly
`status.owned.invalid:9443`; SNI and the leaf's sole DNS SAN are
`status.owned.invalid`. Host loopback is never a fallback. A trusted connector
opens at most one TCP connection in the owned namespace and transfers its exact
connected descriptor to the isolated client. Peer/local addresses, socket
identity and namespace custody must match before TLS. No DNS lookup, host route,
arbitrary URL, alternate address family or new client socket is allowed.

Use a fresh TLS context and one handshake: minimum and maximum TLS 1.2,
`ECDHE-RSA-AES128-GCM-SHA256`, `prime256v1`, and ALPN exactly `http/1.1`.
The fixture uses a pinned RSA-3072/SHA-256 certificate chain and explicit public
CA bytes. Check chain, validity, SAN, negotiated version/cipher/ALPN and no
session reuse before reading the credential descriptor. No CN fallback,
compression, renegotiation, tickets, resumption, client certificate, default
CA store, OpenSSL configuration/provider discovery or key logging is allowed.
Unavailable controls refuse; no compatibility fallback is authorized.

This selects a finite development profile, not a general TLS recommendation.
Python documents that `SSLObject` separates TLS from network I/O and that
`set_ciphers()` does not restrict TLS 1.3. Explicit TLS-version bounds and
explicit trust avoid relying on defaults; `SSLKEYLOGFILE` must be absent before
imports. These are design choices pending actual-runtime verification.
See the [Python 3.14 SSL documentation](https://docs.python.org/3.14/library/ssl.html).

The plaintext request is exactly this template, with CRLF line endings, one
final empty line and no body. The symbolic placeholder is never sent literally:

```text
GET /api/status HTTP/1.1
Host: status.owned.invalid:9443
Authorization: Bearer <private-credential-bytes>
Accept: application/json
Connection: close
Content-Length: 0

```

No retry, redirect, referral, refresh, cookie, second request, pagination,
credential probing, alternate account or state-changing method exists.

## Credential custody and public output

The machine inventory declares a finite set of deliberately public synthetic
fixture values: allowed, invalid and restricted. Their purpose is exact fixture
selection, never appearance-based detection of a real credential. A dedicated
fixture source inside the trusted custody boundary supplies one sealed read-only
descriptor for the selected value. The coordinator passes only a fixture ID and
opaque reference; it never reads or serializes credential bytes. The operation
worker reads that descriptor only after the final one-use release decision and
verified TLS identity. Exact source provenance is checked before any read;
arbitrary paths, environment names, legacy records and mode switches are refused
without opening them. Negative files contain only declared synthetic stand-ins.

The source worker, operation/parser worker, release guard and owned service are
the explicitly trusted secret-bearing boundary. Their code and actual custody
need separate review. A static public fixture declaration is permitted input;
it is not a released run artifact. Do not put credential values or their hashes
in a bundle, public protocol, command line, environment, traceback, launch digest,
saved request, raw response, captured packet or evidence filename. Runtime/source
commitments must exclude dynamic credential input. The execution lock must
distinguish public fixture-source provenance from the private credential object.

Raw HTTP and potentially reflective TLS plaintext stay inside this boundary.
A separate isolated release guard receives the worker's private output and emits
only the closed public schema. It has no network, authority-store or planner
channel except its one public output endpoint. Reject malformed private output
without preserving its contents or a content-derived digest. Preserve the fixed
failure code, last valid public observation and known byte count instead. The
guard's stdout/stderr and wrapper failure paths follow the same rule. Original
public failures remain retained; secret-bearing raw capture is never enabled.

The only successful body values are the exact canonical ASCII JSON encodings of
`{"public_service_identifier":"recon-owned-status-v1","status":"ready"}`
and the same object with `status:"degraded"`. Arbitrary service identifiers,
strings, extra keys, duplicate keys, alternate encodings or trailing values are
not accepted. A valid response has one HTTP/1.1 200 status line and exactly
Content-Type `application/json`, canonical decimal Content-Length and Connection
`close`; no other or repeated header is allowed. HTTP 401/403 is classified as
authentication/authorization refusal only with the pinned empty-body framing.
Error bodies, unknown statuses/headers and response-directed work are unsupported
or invalid, never echoed. A complete accepted exchange also requires the pinned
TLS closure observation; partial framing or a missing closure is not success.

Public result keys are exactly `schema_version, operation_id, outcome,
service_identifier, service_status, http_status`. Version is `1`; operation ID
is a trusted fresh UUID4. The inventory fixes the outcome enum. Only a useful
ready/degraded outcome has the fixed service identifier, matching service status
and HTTP 200. Refusal outcomes carry only their exact 401/403; all other outcomes
have null service fields and null HTTP status. No diagnostic string or raw body
field exists. Separate non-secret authority, accounting and lifecycle records
must be closed schemas before implementation; they are not extension maps.

Finite sentinel checks cover literal, JSON-escaped and base64 forms across all
released outputs and retained run artifacts. They supplement the closed grammar;
they do not establish a universal redactor or remove covert channels. Python and
TLS-library memory copies may persist. Disable core dumps and key logging; pin
the host/swap policy and state its limits. No memory-zeroization or hostile-host
protection claim is made.

## Authority, reservation and release ordering

The S4.2 stores and action grammar describe the fixed unauthenticated HTTP/SSH
profiles. They cannot authorize this new HTTPS operation. Do not relabel an old
action, add an Authorization header to that client, or treat its receipt as a
credential-release grant.

Use a new, explicitly versioned authority domain for this operation, with a fresh
engagement ID and no implicit migration/import from S4.2 or legacy case storage.
One trusted broker owns its durable ROE, lease-generation, reservation and
revocation state. The exact SQLite DDL, event grammar, request/result schemas and
transaction APIs are a required remaining design deliverable. A second store or
caller snapshot cannot serve as current authority. Accepted modules stay intact;
durability patterns are reused only through explicitly reviewed new code.

Every prepared action binds engagement/revision/generation, ROE digest, actual
broker/store-owner/session/reviewer IDs, operation ID, the one endpoint/trust
identity, public request-template digest, runtime lock and opaque credential
reference. Fresh terminal and graphical review show these non-secret commitments
and the exact limits. Both view modes need actual positive proof. An opaque
reference or an exported receipt grants nothing.

The required order is:

1. Validate current ROE, exclusions, window, fresh session, review and audit.
2. In the same durable authority domain as revocation, irreversibly reserve the
   entire one-operation allowance before any TCP connection or TLS work.
3. Open the single owned connection and verify the TLS peer with no credential
   read. Setup traffic is included in the reservation and observed counters.
4. At the named pre-release barrier, recheck current lease/engagement generation,
   window, original monotonic deadline and all live ownership bindings. Consume
   the lease exactly once in the revocation serialization domain, then permit
   the private descriptor read and single request.
5. Persist completion only from an observed closed result and the required
   authority/cleanup crosslinks. A missing or uncertain acknowledgment remains
   unresolved and cannot trigger a resend, refund or new grant.

If revocation wins before step 4, there is no credential read or HTTP request;
TLS setup may already have occurred and must not be reported as zero traffic.
If release wins, work is possibly sent: later revocation blocks further releases,
requests cancellation and retains observed partial counts. A database commit is
not an atomic network write. Check deadline/cancellation at every bounded I/O
step and before final result publication; do not claim that this retracts bytes
already delivered. Concurrent consumption of one reference must admit at most
one operation; concurrent distinct actions share the same persistent limits.

UTC start is inclusive and end exclusive. One original monotonic work deadline
is clipped by the window, session and lease. Clock rollback cannot extend it;
unknown clock state fails closed. Recovery uses a fresh owner/session and current
UTC checks; it never restores a token, TLS session, grant or saved monotonic time.
The broker can open a new operation only after the previous graph has closed and
against remaining allowance. A restart cannot replenish reservations.

The new authority implementation requires its own affected-gate proof, separately
allocated in the inventory as `S43-AUTH01` through `S43-AUTH10`:

| Witness | Required boundary and observation |
| --- | --- |
| AUTH01 — final shared allowance | Two distinct approved actions compete at the actual reservation transaction; exactly one may reserve and dispatch. The loser remains denied after the winner closes and the broker reopens. |
| AUTH02 — restart after reservation | Kill the broker after the reservation commits, before release; close the old graph, reopen the same owned store with fresh owner/session, retain usage and deny the old grant without sending. |
| AUTH03 — restart after release | Kill after release commits but before completion; reopen with retained usage and unresolved possibly-sent work, no resumed connection, resend or restored grant. |
| AUTH04 — restart after completion | Kill after durable completion but before its acknowledgment; recover the persisted observation once, without a second completion, dispatch or refund. |
| AUTH05 — reservation commit failure | Inject a real owned-store transaction failure at reservation; no TCP/TLS setup, release or request may follow a failed or uncertain admission. |
| AUTH06 — release commit failure | Fail the release transaction after reserved TLS setup; no credential read/request, and the original reservation stays consumed. |
| AUTH07 — completion commit failure | Fail persistence after the actual exchange; retain consumed allowance and uncertainty, with no durable-success claim or resend. |
| AUTH08 — audit failure before release | Fail the required audit write at the release barrier; deny credential read/request and further authority, retain reservations and close the graph. |
| AUTH09 — audit failure after release | Fail the required audit write after release; stop further authority, cancel/close, preserve observed progress and uncertainty without refund or late success. |
| AUTH10 — concurrent generation writers | Two writers compete with the same expected generation, including a revocation; one commits and the stale loser is refused. No update may erase the winning state or authorize stale work. |

K02's existing duplicate-consumption variant must use concurrent callers at the
new store's real transaction boundary. K03's revoke-before-release and A08's
revoke-after-release variants must exercise competing release/revoke transactions
with the named winner, not sequential model assertions. These controls run inside
one serial test worker; concurrency is confined to the declared owned case graph.

Before implementation, bind each witness to the exact new transaction API,
deterministic race/crash/fault barrier, required public observations and gate IDs.
Classify an unobserved commit acknowledgment as uncertain; absence of a returned
success is never proof of rollback. Before native execution, bind the owned-store
fixture and fault-injection source in the execution lock. A mocked return value,
an old-store test or a parser-only check cannot discharge a physical witness.
Only fresh S4.3 fixture stores and their copies may be reopened or faulted; never
touch historical evidence databases, journals, WAL or SHM files.

## Proposed closed ROE record (design slice; review pending)

The inventory's `authority_roe_schema` defines the first new authority record.
This is a data-format proposal, not an implemented validator or authority grant.
Independent review of this record and the lease/event/API/SQL proposals below
remains pending. Do not begin production implementation from this slice alone.

Accept at most 4,096 bytes of canonical ASCII JSON, without BOM or final newline.
Reject duplicate/unknown/missing keys, non-integer numbers, booleans in integer
fields, NaN/Infinity, invalid strings and any noncanonical encoding. Canonical
bytes use lexicographically sorted object keys, separators `,` and `:`, ASCII
string escaping and no insignificant whitespace. Validate the bounded closed
shape before canonical comparison or hashing. No text/error extension exists.
The maximum container depth is two (root object counts as one). UUID/hash
patterns match the entire string, including refusal of any trailing newline.

Every top-level field below is required; only `previous_revision_sha256` may be
null. The nested budget object also requires exactly its five listed fields.

| Field | Exact type and rule |
| --- | --- |
| `schema_version` | String `s43-roe-v1`. |
| `engagement_id` | Lowercase canonical UUID4, including RFC variant bits; a new live engagement ID comes from the trusted owner. |
| `revision` | Integer 1 through 2,147,483,647; no boolean, float or numeric string. |
| `previous_revision_sha256` | Null for revision 1; otherwise 64 lowercase hexadecimal characters binding the immediately preceding canonical record. |
| `operation_profile_sha256` | SHA-256 of the canonical public `operation` object in this inventory; the actual record must equal that computed digest. |
| `runtime_lock_sha256` | SHA-256 of the reviewed actual public runtime lock; 64 lowercase hexadecimal characters, matched to that lock before admission. No placeholder lock authorizes work. |
| `trust_sha256` | SHA-256 of the exact reviewed public CA bytes; 64 lowercase hexadecimal characters, matched to the runtime lock and actual TLS trust input. |
| `included_operations` | Exactly `["synthetic-service-status-v1"]`. |
| `excluded_operations` | Exactly `[]` or `["synthetic-service-status-v1"]`; exclusion wins and the latter permits no operation. |
| `allowed_fixture_ids` | A possibly empty subset of `allowed`, `invalid`, `restricted`, in that order, without duplicates; these IDs resolve only through the pinned private fixture source. |
| `not_before_utc`, `expires_utc` | Real Gregorian UTC instants in exact `YYYY-MM-DDTHH:MM:SS.ffffffZ` form, years 0001–9999, no leap seconds; start strictly precedes end, start inclusive/end exclusive. |
| `active_operation_limit` | Integer 1, excluding boolean. |
| `budgets` | Exact integer fields: `actions` 0–64; `connections` 0–64; `outbound_tls_bytes` 0–524288; `inbound_tls_bytes` 0–1048576; `runtime_ms` 0–320000. |

The profile digest binds the already declared numeric endpoint, namespace,
Host/SNI, method/path, TLS selection and no-follow-up policy. There is no URL,
hostname, credential value, credential-file path, ambient source name or custom
effect field in a ROE. Hash only this validated public record, never a credential
or credential-bearing request. Its digest is consistency evidence, not authority.

Budget ceilings are independent and cumulative for the engagement's entire life,
across revisions, owners and sessions. Reserve the existing fixed vector
`(1, 1, 8192, 16384, 5000)` against all five remaining allowances atomically.
A zero or insufficient dimension denies admission; uneven ceilings are valid
restrictive policy, not an invitation to round up. Revising a ceiling never resets
usage, refunds a reservation or refreshes a grant. Smaller live policy limits may
further narrow execution; they cannot reduce the charged reservation vector.

Record parsing checks shape and intrinsic relations only. Before accepting a
revision, the live broker must compare engagement identity, exact next revision,
previous digest and current generation in its single authority transaction; it
must invalidate prior approvals/leases on a successful change. A copied record,
revision 1 for an existing engagement, skipped revision or old digest cannot
reset state. The version/generation overflow path refuses; there is no wraparound.
The generation itself is mutable store state and is deliberately absent from
this immutable ROE. Its bound is specified in the lease proposal below; the
transaction schema is still pending.

The proposed validator must eventually cover unknown/duplicate keys, encoding,
type confusion, UUID/hash/time bounds, exclusion precedence, empty fixture set,
each insufficient budget dimension and copied/skipped/stale revisions. Live
admission/revision behavior additionally belongs to AUTH01/AUTH10 and the new
authority transaction tests. This paragraph allocates design checks, not new
collected test identities or passing outcomes; the affected portable parameter
map must be frozen with the remaining schemas before implementation.

## Proposed one-use lease record and transitions (review pending)

`authority_lease_schema` in the inventory is the exact proposed closed field
list. It is an internal broker-owned record, not a transferable capability or a
public protocol extension. Copying, parsing or replaying it grants no authority.
This design slice does not implement a store, worker or credential source.

Use the ROE's canonical ASCII JSON rules, at most 4,096 bytes and one container
level. Every listed field is required. Only the named lifecycle links, monotonic
times and `close_kind` may be null. UUID4, digest, UTC and integer rules retain
the ROE meanings; integer bounds exclude booleans. `cancel_requested` alone is a
boolean. Generation is an integer 0–2,147,483,647; increment overflow refuses
further authority, never wraps or opens a replacement engagement automatically.

| Binding group | Exact fields and meaning |
| --- | --- |
| Version and lease | `schema_version` is `s43-lease-v1`; `lease_id` is a fresh broker-issued UUID4. |
| Current authority | `engagement_id`, `revision`, `generation`, `roe_sha256`; must match current authoritative state at reservation and release. |
| Exact action | `operation_id` (UUID4), `action_sha256`, `operation_profile_sha256`, `request_template_sha256`, `runtime_lock_sha256`, `trust_sha256`; all hashes bind only reviewed public data. |
| Live principals | `broker_id`, `store_owner_id`, `session_id`, `reviewer_id`, `approval_id`, `clock_epoch_id` are UUID4 references resolved by the live broker to observed identities, not caller assertions. `review_view` is `terminal` or `graphical`. |
| Private source | `credential_reference` is a broker-issued opaque UUID4; `fixture_id` is `allowed`, `invalid` or `restricted`, permitted by current ROE. No descriptor number, file path, secret or secret-derived digest is serialized. |
| Validity | `prepared_utc`, `expires_utc`; preparation is inside the current window, expiry is later and no later than ROE/session expiry or 30 seconds after preparation. |
| Mutable lifecycle | `state` is `prepared`, `reserved`, `released` or `closed`; `cancel_requested` starts false and may only become true. |
| Durable links | `reservation_id`, `release_event_id`, `completion_event_id`, `closure_event_id`: null until their specific committed transition; otherwise UUID4 referencing the same engagement/operation/lease. |
| Original deadlines | `operation_started_ns`, `work_deadline_ns`, `cleanup_deadline_ns`: null before reservation, then integer monotonic nanoseconds in 0–9,223,372,036,854,775,807, fixed in the original clock epoch. |
| Closure | `close_kind`: null until closed, then `unadmitted`, `unreleased`, `completed` or `interrupted_unknown`. |

All authority/action/principal/source/UTC bindings are immutable after preparation.
Mutable state, links and deadline assignment change only through the following
broker transactions; callers cannot supply replacement rows. Each transaction
compares the expected state and current authority under the same serialization
domain as revision/revocation. Unlisted transitions are forbidden.
Lease and operation IDs cannot be reused within the authority domain; each
operation has at most one lease. A credential reference resolves only for its
bound lease/action and is never rebound after consumption or closure.

| Transition | Required effects and boundary |
| --- | --- |
| Create → `prepared` | Fresh exact-action approval and healthy audit; all links/times/close kind null, cancellation false. No reservation, network or credential read. |
| `prepared` → `reserved` | Recheck current bindings, clock/window, approval, no cancellation, capacity and remaining budgets. Atomically reserve the full fixed vector, assign one reservation ID and original deadlines. Only confirmed commit permits the single connection/TLS setup. |
| `reserved` → `released` | Verified live TLS peer, same observed worker/source bindings, unexpired original deadline and healthy required audit; atomically consume the lease and append the release event. Only confirmed commit authorizes one private descriptor read and one request. |
| `prepared` → `closed` | Confirm physical closure of any prepared graph; kind `unadmitted`, no reservation/release/completion or monotonic times. |
| `reserved` → `closed` | Retain reservation/deadlines. Kind `unreleased` for proved no release, `completed` for an observed pre-release refusal with durable result, or `interrupted_unknown` when required progress/completion is uncertain. No release link may be invented. |
| `released` → `closed` | Retain reservation/release/deadlines. Kind `completed` only with durable observed result and physical closure; otherwise `interrupted_unknown`. Never classify released work as unadmitted or unreleased. |

The completion event (if any) and closure event are persisted atomically with
the terminal state. Every closed row has a closure event; only `completed` has
a completion event. A pre-release completed refusal cannot carry a useful
ready/degraded or HTTP 401/403 result. Those outcomes require the release event
and actual exchange. Nonclosed rows have null completion/closure/kind. Existing
non-null links never change. A read-only lookup may return a durable completion
after a lost acknowledgment; it cannot append another completion or return a grant.
`completed` means a persisted observation, not necessarily useful success.
Cancellation, expiry or failed final publication checks cannot produce a late
ready/degraded result even if an earlier response was useful.

Closing requires actual whole-graph process/descriptor closure. If closure cannot
be proved, retain the nonclosed state, block new work and report cleanup failure
through the separately specified observation path. A timeout is not proof of
closure. Cancellation is an orthogonal monotone flag on nonclosed rows; it denies
reservation/release, requests bounded cleanup and cannot clear consumed usage.
Revision or revocation must invalidate affected leases in the same authority
order, including cancellation of already released work. A closed row is immutable.

At reservation, derive cleanup deadline as the earliest of start + 5 seconds and
the ROE, session and lease deadlines, converted from a single trusted UTC/monotonic
observation. Work deadline is the earlier of start + 4 seconds and cleanup deadline
minus 1 second. If work deadline is not strictly after start, deny before reserving.
No arithmetic overflow or unknown clock conversion is accepted. Deadline values
never extend. Clock epoch is bound to the original live broker/boot observation;
recovery retains saved times only as historical evidence and never executes on them.

Broker death, failed/uncertain commit or audit failure cannot issue a release
permission. Stop that graph and deny further authority until bounded reconciliation
and physical closure. If committed state cannot be established, keep the authority
domain unavailable; do not manufacture a terminal row or infer rollback from a
missing acknowledgment. Reopening never resumes an old lease. AUTH02–AUTH04 use
fresh owner/session identities for reconciliation only; any later new action needs
fresh review, a new lease and sufficient retained allowance.

The machine inventory maps these transitions to the existing ten authority
witnesses and K02/K03/A08 controls. Proposed event/audit records and transaction
signatures and SQL constraints follow below. Reconciliation integration and
evidence projections remain pending and must agree before implementation.
This is a self-reviewed proposal; independent design review remains pending.

## Proposed authority ledger and transaction APIs (review pending)

`authority_event_schema` and `authority_transaction_api` in the inventory define
the exact field lists, event variants and method signatures for this slice.
These are internal typed interfaces; no public RPC or caller-supplied context
object is authorized. Contexts and observation references resolve only through
the trusted broker's live authenticated role bindings. Their transport and
physical observation schemas remain prerequisites, not implicit trusted inputs.

Use one append-only event ledger as the authority audit within the same SQLite
transaction as each state change. No separately committed audit store can supply
the required acknowledgment. A failed event insert aborts its associated mutation;
a failed or unknown commit returns no permission and makes the authority domain
unavailable until reconciliation. No success/failure event may be invented when
the store itself could not be observed. Retain a closed non-secret failure receipt
outside the failed transaction, without raw exceptions, inputs or SQL text.

Each canonical event is at most 4,096 ASCII JSON bytes with container depth at
most three, using the ROE's strict parsing rules. Required envelope fields are
`schema_version, event_id, transaction_id, sequence, previous_event_sha256,
engagement_id, revision, generation, actor_owner_id, actor_session_id,
operation_id, lease_id, recorded_utc, kind, details`. Version is `s43-event-v1`;
IDs are UUID4, revision is 1–2,147,483,647, generation is 0–2,147,483,647,
and sequence is 1–2,147,483,647. Sequence and predecessor chain are global to
this store and survive restart; overflow denies new authority. Only sequence 1
has a null predecessor. Other predecessor values hash the preceding canonical
public event. UTC is an observation, not a substitute for sequence ordering.

The event envelope records the current authority revision/generation and actual
writing owner/session. Lease bindings retain their original immutable values.
Operation and lease IDs are null together only for engagement-level events;
otherwise both match the affected lease. `details` is the exact closed object for
its `kind`, never an arbitrary payload. No credential-bearing material is a field
or digest input. The inventory fixes these variants:

| Kind | Meaning and atomic relationship |
| --- | --- |
| `roe_adopted` | Bind new and preceding public ROE digests; adopt revision, advance generation for a revision change and invalidate old leases in the same transaction. First creation uses revision 1/generation 0 and a fresh engagement. |
| `engagement_revoked` | Compare expected generation, increment once and deny further admission/release; set cancellation for every affected nonclosed lease atomically. |
| `lease_prepared` | Insert the broker-built prepared lease and its public binding digest together. |
| `allowance_reserved` | Insert reservation, charge lifetime usage and assign original deadlines with the event. |
| `credential_released` | Consume the reserved lease once and assign this event ID as its release link. |
| `exchange_observed` | Mandatory audit of the actual released worker at a declared pre-write barrier; this event must commit before its next request I/O. It gives no second release permission. |
| `cancellation_requested` | Set the lease's cancellation flag without changing its immutable generation; repeated cancellation is a refusal, not a fresh grant or event. |
| `result_observed` | Retain only the release guard's already validated six-field public result, matched to this operation. This alone is not durable completion or proof of cleanup. |
| `result_recorded` | Link an existing result observation and its public digest; write in the same transaction as `lease_closed` and the terminal lease row. |
| `lease_closed` | Bind actual physical cleanup observation, permitted close kind and completion-event link (null except for `completed`). No reset of reservation, release or usage. |
| `owner_recovered` | After exclusive ownership and old-graph closure are established, record a fresh owner/session and the prior owner reference. Never resume old leases or reconstruct a permission. |

Result observation accepts `reserved` or `released` leases only. Ready/degraded
and HTTP 401/403 require released state and actual exchange; reserved-state
observations are restricted to pre-release refusals. Only one result observation
per lease is admissible. Terminal `completed` references it; an observation made
before later cancellation/expiry may remain historical but cannot become a late
successful completion. Close as `interrupted_unknown` when completion cannot be
established without that prohibited late success. A closure failure remains a
nonclosed lease with new work blocked, not a fabricated `lease_closed` event.
The closure API requires a non-null observation event ID exactly when the close
kind is `completed`; every other close kind requires that argument to be null.

All mutation methods return one closed `s43-txn-result-v1` receipt: exactly
`schema_version, call_id, status, reason, transaction_id, last_event_sequence,
operation_id, lease_id`. The enum/status/null rules are in the inventory.
`committed` describes persisted state only. TCP setup or credential release
requires the original broker's separate one-use live delivery after renewed
deadline/cancellation checks. Neither a receipt nor a read-only lookup can be
replayed to obtain that delivery. Unknown commit acknowledgment never triggers
an automatic mutation retry. Deterministic refusals write no mutation/event.

Methods cover ROE adoption, preparation, reservation, release, exchange/result
observation, cancellation, engagement revocation, closure and owner recovery.
Every method compares expected state under the single writer serialization order;
adoption/revocation additionally compare the supplied expected generation, while
reservation/release compare the lease's bound generation with current authority.
Cleanup and recovery authenticate the new current owner, but must not demand
that the dead lease's old owner/generation become current again. They may only
close/reconcile that stale work, never admit it. A read-only `lookup_operation`
returns at most the existing closed lease and its permitted completion result,
with no grant, private channel or state mutation.

For AUTH05/06/07, inject actual faults at reservation/release/closure COMMIT
boundaries respectively. AUTH08 fails the required `credential_released` audit
INSERT before descriptor access. AUTH09 fails `exchange_observed` INSERT after
release at the live pre-write barrier; retain possibly-sent classification rather
than infer delivery from the durable release. AUTH04 kills after closure COMMIT
but before acknowledgment; lookup may recover that one committed observation.
These are named semantic boundaries; concrete SQL/API instrumentation and exact
physical fixture pins remain required before execution.

Recovery first proves exclusive fresh ownership and old-graph closure, then reads
committed records with bounded consistency checks. Already closed records remain
unchanged. Nonclosed old leases can only take a permitted closure transition;
saved completions are returned read-only. Ambiguous or inconsistent storage keeps
authority unavailable. The storage model and recovery order below narrow these
choices. The executable SQL proposal follows; observer-reference schemas and physical runtime
enforcement still need review. No implementation or execution-readiness gate is
closed by these proposals.

## Proposed storage model, quotas and recovery order (review pending)

`authority_storage_contract` specifies one new engagement per owned store. It
cannot open a historical S4.2 database, import a snapshot or migrate a legacy
store. The table model below is implemented by the proposed exact SQL statements
in `authority_sql_contract`; the portable checks described below exercise only
fresh in-memory databases. No production authority store has been implemented.

Select rollback-journal `DELETE`, `synchronous=EXTRA` (3), 4,096-byte pages,
`max_page_count=8192`, `foreign_keys=ON`, `recursive_triggers=ON`, `read_uncommitted=OFF`, `mmap_size=0`,
`temp_store=MEMORY` and `busy_timeout=0`. Set/check connection settings outside a
transaction; read back every required value and refuse mismatches or unsupported
settings. Each mutation uses one `BEGIN IMMEDIATE` transaction and one COMMIT;
no automatic retry, implicit transaction, nested savepoint or journal-mode fallback.
No SQL input, extension loading, ATTACH, VACUUM or schema migration is exposed to
operation workers or callers. A busy/error/unknown commit cannot authorize I/O.

SQLite documents that EXTRA adds directory synchronization for DELETE-mode
commits, foreign keys must be enabled for each connection, and BEGIN IMMEDIATE
can fail when another writer is active. These settings do not prove the host's
storage guarantees. Actual SQLite build/VFS/filesystem identities and bounded
I/O/cleanup remain execution-lock prerequisites. See the official
[PRAGMA reference](https://www.sqlite.org/pragma.html#pragma_synchronous),
[foreign-key rules](https://www.sqlite.org/foreignkeys.html#fk_enable) and
[transaction rules](https://www.sqlite.org/lang_transaction.html).

| Table | Keys and required constraints |
| --- | --- |
| `store_state` | Exactly one row: store/engagement IDs, schema version, current revision/generation/owner, revoked flag, recovery status, event head and allocation counters. Current pointers reference retained rows. Never reset counters or clear revocation. |
| `roe_revisions` | Revision primary key; unique canonical public digest; bounded canonical ROE bytes. Revision 1 has no predecessor; later rows reference the exact preceding revision/digest. Append only, at most 64 rows. |
| `owners` | Unique owner ID and session ID; prior-owner link and cleanup-observation reference for recovery. Initial owner is committed with the initial ROE; later owners with `owner_recovered`. Append only, at most 64 rows. |
| `leases` | Unique lease ID, operation ID and credential reference; canonical record plus indexed state/revision/owner/lifecycle projections. No deletion or rebinding; immutable fields and closed rows cannot change. At most 128 lifetime rows, at most two nonclosed rows and at most one `reserved`/`released` row. |
| `reservations` | Unique reservation ID and unique lease ID; fixed full reservation vector and matching operation/lease identity. Append only; at most 64 rows. Lifetime usage is the sum of these rows, never of observed network bytes. |
| `transactions` | Unique transaction ID and broker call ID, first/last event sequence. Append only; one or more contiguous events per successful transaction, at most 2,048 rows. Failed or refused calls have no committed row. |
| `events` | Unique sequence and event ID; transaction/subject references and canonical public event bytes. Append only, at most 2,048 rows; contiguous predecessor chain, kind/subject nullability and all event/lease links checked. |

Use explicit non-null primary/unique keys and foreign keys of matching types;
no cascading delete or replace/upsert that can erase history. Closed-record
validators enforce UUID, canonical encoding and boolean/integer distinctions
before SQL binding. Indexed projections must equal the decoded canonical record
on every write/read; a database CHECK alone is not a substitute for that validation.
Lease-state CHECKs, immutable/append-only guards and the one-active partial unique
index belong in the exact DDL. Cross-row ownership, generation, event ordering,
budget and matching-link checks also run inside the serialized broker transaction.
Any disagreement blocks authority. Deferred crosslinks may be used only when
the same transaction inserts their targets and verifies them before COMMIT.

The lifetime admission quotas are 128 leases, 64 reservations, 64 ROE revisions
and 64 owners. These are additional storage ceilings, not new operation allowance.
Preparing a lease irreversibly allocates eight of 1,024 lease-event slots. Its
possible events are preparation, reservation, release, pre-write observation,
result observation, explicit cancellation, result recording and closure, each
at most once. The preparation event consumes its first allocated slot. Remaining
slots stay assigned to that lease; unused slots are not recycled after closure.
ROE adoption, engagement revocation and owner recovery use a separate 1,024-slot
management pool. They cannot consume lease slots. Broad revocation cancels leases
atomically under its one management event, without duplicating per-lease events.
All allocation/count changes commit with the relevant event/state mutation.

The database cap is 32 MiB; the owned rollback journal cap is 40 MiB; the whole
owned storage directory cap is 80 MiB. Those are private authority-store bounds,
separate from the existing 4 MiB public bundle/source caps. SQLite page limits
bound the database, not the active journal or available filesystem space. Actual
journal/directory enforcement and inode/path custody must be pinned in the role
graph. Logical event slots do not preallocate disk pages or guarantee a future
write: disk-full, I/O, audit or cleanup failure keeps authority unavailable.
No deletion, journal truncation, quota increase or retry is a recovery shortcut.

Recovery has this fixed order:

1. Establish a fresh exclusive owner and physically close the old owned graph
   before opening the owned store. A stale PID, saved handle or timeout is not
   proof. No new operation is admissible during recovery.
2. Open only the verified new S4.3 store with the selected settings; allow SQLite
   to handle its own owned rollback journal. Never manually repair/remove it.
   Within the bounded row/byte limits, verify schema identity, integrity/foreign
   keys, canonical projections, contiguous event chain, transaction ranges,
   lease links, reservation sums and slot allocation. Failure leaves it unavailable.
3. In one transaction, compare the prior owner/head, insert the fresh owner and
   `owner_recovered`, change current owner and cancel old nonclosed leases.
   Preserve their original immutable owner/session/generation/deadline bindings.
   Set recovery status to `recovering`; if all leases were already closed it may
   become `ready` in this same transaction, subject to current policy/revocation.
4. Reconcile each of at most two old nonclosed leases in lease-ID order, one
   closure transaction each, using actual cleanup evidence. Prepared becomes
   `unadmitted`; reserved becomes `unreleased` only with proof of no release,
   otherwise `interrupted_unknown`; released becomes `interrupted_unknown`.
   Never promote a merely observed old response to a new useful completion.
   Existing closed completions are returned read-only and remain byte-identical.
5. The final closure transaction may also set recovery status `ready` after
   checking that no old graph or nonclosed lease remains. This is not a grant:
   current revocation/window/budgets still govern every new reviewed action.
   Do not add an unaudited ready-state transaction. Crash at any step requires a
   fresh owner on the next attempt, with retained reservations and allocated slots.

Recovery uses management slots for ownership and each old lease's own closure
slots. Exhausting the owner quota or failing to prove consistency prevents renewed
authority; physical cleanup still proceeds without a credential/request grant.
SQLite integrity checks and a known committed row do not prove network delivery,
restore original monotonic time or justify resending uncertain work. The native
AUTH01–AUTH10 witnesses remain pending; no existing test validates this new store.

## Exact SQL design artifact and portable validation (review pending)

The inventory's `authority_sql_contract` contains 42 exact DDL statements:
seven tables, four explicit indexes and 31 guard triggers. `table_columns` lists
the exact projections. `transaction_sql` supplies SQL for all ten mutation APIs,
empty-store bootstrap, the bounded cancellation loop, common transaction/event
inserts, event-head update and nine precommit checks. `read_sql` defines bounded
lookup/recovery reads. These are proposed SQL source, not production runtime code.

Every foreign key is explicitly deferred until the single outer COMMIT. This
permits same-transaction lease/reservation/event crosslinks, not missing targets.
All key columns are non-null; UUID/hash/basic scalar checks supplement the closed
record validators. Append-only guards forbid updating/deleting historical tables;
lease guards forbid rebinding, backwards transitions, cancellation reset and any
closed-row update. A partial unique index permits only one reserved/released lease.
No statement uses REPLACE, conflict-ignore behavior or caller-selected SQL names.
See SQLite's [trigger](https://www.sqlite.org/lang_createtrigger.html) and
[partial-index](https://www.sqlite.org/partialindex.html) definitions.

Inside BEGIN IMMEDIATE, read and verify all required gate rows before mutation.
Allocate transaction/event identities and sequence positions from the current head
before using them in mutations; compute canonical event bodies/hashes after the
corresponding state changes. Every expected gate/insert/update requires exactly
one row, except bootstrap's empty-store gate and the declared 0–2 cancellation
loop. A missing row aborts the entire transaction; it never falls through to audit
or permission delivery. Each precommit check requires zero discrepancy rows.
Failed/unknown COMMIT is not retried. Confirmed SQL persistence still requires the
separate original-owner live delivery and renewed deadline/cancellation checks.

The SQL checks do not replace canonical-record validation, projection equality,
fresh approval, trusted TLS/cleanup observations, final result semantics or event
hash reconstruction. These required broker-side predicates are enumerated in
`semantic_checks_not_replaced_by_SQL`; their codecs/adapters are still pending.
The lookup query returns stored public bytes for validation, not a trusted grant.

Portable validation compiled the DDL and 60 declared SQL statements using SQLite
3.46.1 in fresh `:memory:` databases. A committed synthetic SQL bootstrap passed
the precommit checks. Ten negative checks exercised append-only records, deletion,
counter rollback, deferred orphan refusal, event gaps, malformed UUIDs, the active
lease limit, closed-lease immutability, nonclosed capacity and owner quota.
The fixture uses synthetic scalar rows with placeholder canonical blobs; it tests
SQL-layer constraints only and does not pass the full closed-record validator.
It establishes no disk durability, ownership, credential custody or native gate.
The actual runtime SQLite version remains unselected until the execution lock.
The initial validation-harness failure and corrected results are retained privately.

## Trusted observations, references and broker validation (review pending)

`authority_observation_contract` supplies six closed internal observation types
and their allowed API consumers. The broker creates their envelopes after
authenticating the observed producer role and validating its bounded message.
A caller cannot submit an envelope, select its issuer or promote an imported
record to a trusted reference. The logical producers below are not yet pinned
processes: their actual identities/channels belong to the pending role graph.

Every record has exactly `schema_version, reference_id, kind, issuer_role,
issuer_instance_id, observer_owner_id, observer_session_id, clock_epoch_id,
observed_monotonic_ns, engagement_id, operation_id, lease_id, subject_owner_id,
subject_generation, action_sha256, runtime_lock_sha256, payload`.
Version is `s43-observation-v1`. UUID4/hash/integer rules follow the lease schema;
the broker assigns all envelope identities from its live context. Only the named
subject fields may be null as specified below. Records are canonical ASCII JSON,
at most 4,096 bytes/depth three; payload fields are exact for the selected kind.
They are internal validated observations, not an added public evidence format.

| Kind / logical producer | Exact payload and required observation |
| --- | --- |
| `action_prepared` / broker | `roe_sha256, revision, operation_profile_sha256, request_template_sha256, trust_sha256, fixture_id, credential_reference`. Bind the exact current reviewed public action and private-source reference before lease creation; no credential read. |
| `approval_recorded` / reviewer | `action_reference_id, approval_id, review_view, decision, reviewed_action_sha256`. Decision is exactly `approved`, view exactly `terminal` or `graphical`; observe the actual fresh reviewer interaction for the same action/session. Denial creates no approval reference. |
| `tls_verified` / operation worker | `socket_observation_id, trust_sha256, peer_certificate_sha256, negotiated_version, negotiated_cipher, negotiated_alpn, session_reused`. Version/cipher/ALPN equal the selected profile, session reuse is false; the worker completed the actual verified handshake on the connector's exact observed socket, before credential access. Hash only public certificate bytes. |
| `pre_write_reached` / operation worker | `release_event_id, socket_observation_id, phase`. Phase is exactly `pre_write`; observe that same released worker waiting before request I/O. Its required audit event must commit before it continues. |
| `result_released` / release guard | `result`. This is exactly the existing six-field public result, emitted through the guard's sole public output endpoint for the bound operation. No new authority-store channel is added to the guard. |
| `graph_closed` / lifecycle monitor | `scope, graph_id, physical_receipt_id, processes_reaped, descriptors_closed`. Scope is `operation_graph` or `owner_graph`; both booleans are true only after the trusted monitor has actual whole-graph process/descriptor closure evidence for that immutable graph identity. A timeout or stored receipt alone is insufficient. |

For action/approval, operation and action digest are non-null and lease is null.
TLS/progress/result records bind a non-null operation, lease and action digest.
An operation-graph closure does likewise. An owner-graph closure has null
operation/lease/action fields and identifies the previous owner in
`subject_owner_id`; it does not authorize every operation by implication.
`subject_generation` is the exact action/lease generation, except owner-graph
closure where it is null. Envelope observer owner/session/epoch always describe
the currently observing broker context, including a fresh recovery owner.

`socket_observation_id`, `graph_id` and `physical_receipt_id` resolve through
the trusted runtime registry to actual socket/namespace and process/descriptor
observations. They are not self-authenticating UUIDs. Concrete receipt fields,
pidfd/start identities, graph membership, FD custody and peer-channel checks
must be fixed with the role graph before implementation. Until then, these
schemas cannot stand in for a physical TLS or cleanup proof.

The broker keeps a bounded, nonpersistent registry of at most 32 references per
live session, including spent entries. Graph closure disables admission/progress
use; guard results and cleanup proofs remain available only for terminal
observation/persistence until the operation closes durably or the session ends.
Session end clears the registry. No persisted record
recreates an entry after restart. Capacity exhaustion denies registration; it
cannot evict a spent identity to make a duplicate appear fresh. The five single-use
kinds pass `available → claimed → spent` under the broker's serialization
lock; no transition restores availability after a failed/unknown transaction.
`prepare_lease` claims action and approval together, `release` claims TLS,
`observe_exchange` claims progress, and `observe_result` claims the guard result.
Reusing an ID, wrong kind, foreign operation, producer or subject fails closed.

Cleanup references are read-only proofs, reusable only for that exact closed
graph and subject in the current observer session. `recover_owner` accepts only
owner-graph closure; `close_lease` accepts only its own operation-graph closure.
When an owner-wide cleanup includes multiple operations, the monitor must supply
separately bound operation-graph records for their individual closure APIs.
Reusing closure evidence cannot close a different graph or supply a grant.

For action, approval, TLS and progress, require the same current owner/session,
clock epoch and generation, observation time between the known session start and
current monotonic time, and the original live session/action/lease deadlines.
TLS/progress also postdate this reservation's start. Recheck live socket,
worker and authority bindings at use; an earlier observation does not freeze
revocation or ownership. Result collection may retain a same-owner, same-operation
historical result after cancellation/generation change, but cannot publish late
success. Cleanup may inspect a previous owner's subject from a fresh observer;
it never restores that subject's authority or saved clock epoch. Unknown clock
or registry provenance denies use rather than guessing freshness.

`broker_codec_contract` fixes the validation order: bound the frame; reject
duplicate/unknown/missing fields and invalid scalar types; enforce the exact
kind/null/enum rules; compare canonical bytes; resolve live producer and subject
bindings; verify cross-record/authority predicates; only then derive public hashes,
SQL parameters or retained projections. Integer fields reject booleans/floats;
boolean fields accept only JSON true/false. Unknown content is neither echoed
nor hashed. Errors are fixed codes with no input fragment or exception text.

For a public result, only ready/degraded carries the fixed service ID, matching
status and HTTP 200. `authentication_refused` carries only HTTP 401 and
`authorization_refused` only HTTP 403; both have null service fields. Every other
outcome has null service fields and null HTTP status. All three observed HTTP
status classes require the actual post-release exchange. Pre-release results
must follow the explicit refusal/invalid/limit/cancellation rules without implying
authentication. Record validation alone does not establish the physical exchange.

Before SQL binding, the broker validates the entire canonical record and every
normalized projection, checks the exact current ROE/profile/trust/runtime and
finite source ID, then verifies state/link/event/accounting predicates in the
single transaction. It reconstructs hashes only from validated public templates,
records and results. A truthy observation field, valid digest or successful SQL
query never substitutes for an authenticated producer or measured progress.
These are codec and reference-resolution specifications, not implementation.
Independent review and the concrete role/receipt/transport definitions remain
pending; all native observations and acceptance counts stay unchanged.

## Proposed role graph, channels and physical receipts (review pending)

`runtime_role_graph` replaces unspecified helpers with the following finite
process topology. The case driver starts one supervisor; that supervisor is PID 1
in a fresh owned PID namespace and directly parents/reaps the other roles. Its
lifecycle-monitor and cleanup functions run in the same single-threaded process.
There is no shell wrapper, extra namespace-init process, xauth helper, daemon or
unlisted cleanup subprocess. Any necessary extra process requires a scope change.

| Role | Processes / tasks / FDs at most | Function and retained access |
| --- | ---: | --- |
| `driver` | 1 / 1 / 8 | Owned per-case harness, supervisor control and public report; no credential/store FD. The outer test scheduler is outside this runtime graph and grants nothing. |
| `supervisor` | 1 / 1 / 64 | Bootstrap, namespace setup, pidfds, role lifecycle channels and metadata-only observations; never receives a credential FD or raw private output. |
| `broker` (ordinary profile) | 1 / 2 / 16 | Authority-store reader/writer, reviewer and worker control, validated public guard output. AUTH02/03/04 use the explicit two-instance, one-task-per-instance recovery exception below, with one store user at a time. |
| `reviewer` | 1 / 2 / 16 | One terminal or graphical review process; fixed public commitments only. |
| `fixture_source` | 1 / 1 / 12 | Pinned synthetic values and sealed credential descriptor; direct transfer to operation worker after current release authorization. |
| `connector` | 1 / 1 / 12 | One TCP setup in the owned service network namespace; transfers the connected socket directly to operation worker and closes its copy before TLS. |
| `operation_worker` | 1 / 1 / 12 | TLS/parser, connected socket, released credential FD, private result channel to guard and closed broker control. |
| `release_guard` | 1 / 1 / 8 | Private input from operation worker, one public output endpoint to broker; no authority-store or network access. |
| `owned_service` | 1 / 1 / 12 | Owned TLS listener, fixed fixture behavior and private fixture material; no host network or authority store. |
| `graphical_display` | 1 / 8 / 32 | Optional owned X server for graphical cases only; no host display reuse or external authentication helper. |
| `fixture_probe` | 1 / 1 / 12 | Optional explicitly inventoried positive-control probe against owned fixtures; no credential/store FD and no acceptance credit as the operation worker. |

Nine base roles give a ceiling of nine processes/eleven tasks (ten in ordinary
single-thread broker cases). Graphical display and probe raise the whole-graph
ceiling to eleven processes/twenty tasks, with 204
FDs across the complete declared role set. These are proposed structural bounds,
not observed counts. No role may borrow another's unused allowance. No role may fork/clone/exec after READY; all declared role creation occurs during
reviewed bootstrap within the same totals. Recovery uses exactly one prestarted,
confined broker instance in its reviewed profile; runtime execution remains
disabled. Lifetime worker replacements also
need explicit fixture allocation; a crash does not trigger automatic respawn.

The execution graph includes driver and supervisor. An owner graph contains its
broker/reviewer/display and all operation/probe descendants; its observer is not
part of the graph it claims to have reaped. An operation graph contains source,
connector, operation worker, guard, service and any declared probe. Physical
cleanup checks both child termination and any remaining root-side FD copies.
The driver separately observes final supervisor termination. No receipt claims
that its own still-running producer has been reaped.

Use one fresh owned PID namespace for supervisor and children so child-role IPC
identities are mutually visible. Every child has a private mount view, no ambient
home/configuration and only its declared resources. After bootstrap, child roles
have zero capabilities, no-new-privileges and their reviewed syscall restrictions.
Distinct role UIDs/GIDs and their host mappings must be bound to verified owned
IDs before execution; no ambient identity or unlisted setuid helper is a fallback.
The supervisor's retained namespace/cleanup privileges require a separate exact
capability pin. The service and connector share one fresh disconnected network
namespace; the operation worker has no network creation authority and receives
only the already-connected socket. No DNS, host loopback or host route is exposed.

The inventory's channel list defines allowed peers, direction and FD transfers.
After bootstrap, only connector→operation may transfer one connected socket, and
source→operation one credential FD. All other runtime channels reject ancillary
FDs. Broker never relays these two descriptors. Connector drops its copy before
handshake; source drops its copy after acknowledged transfer and bounded shutdown.
The source retains the credential FD until confirmed one-use release, so the
operation worker cannot read it during preparation or TLS setup, and a lease
revoked before release cannot receive it. Revocation after delivery cannot recall
bytes from process memory; cancellation and the pre-write gate still apply.

The credential object is a bounded memfd, created and populated inside the source
boundary, with WRITE/GROW/SHRINK/SEAL seals and a separately obtained read-only
descriptor. Sealing alone does not make the original O_RDWR descriptor read-only.
The source closes every writable alias before transfer; recipient verifies access
mode, seals, size and bound source provenance before reading. No broker/supervisor
copy, credential-derived name, raw-byte capture or content hash is permitted.
The [Linux memfd documentation](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
describes the initial read/write descriptor and sealing mechanism.

Child-role control and transfer channels are private inherited AF_UNIX
SOCK_SEQPACKET pairs. Each bounded packet has exactly `schema_version, channel_id,
sequence, kind, operation_id, payload`, with version `s43-channel-v1`; sequence
is a strictly increasing integer 1–2,147,483,647. Packet size is at most 4,096
bytes including its envelope. Allowed kind names and direction come from
the channel inventory; their exact payload codecs remain a prerequisite. No
generic command or arbitrary extension exists.
The packet cap also narrows its embedded observation's existing 4,096-byte cap.
Reject MSG_TRUNC/MSG_CTRUNC, unexpected rights/credentials, unknown kinds and
sequence/subject mismatches without echo or content-derived hash.

For child-role messages, verify per-message kernel credentials against the live
PID/start/pidfd/role/UID/GID binding; a creator's socketpair-time SO_PEERCRED value
does not authenticate a later child sender. Exact PID namespace coordinates must
match. The driver bootstrap channel crosses the PID boundary: bind it by the
exclusive inherited endpoint and observed launcher/pidfd custody, not by treating
an unmapped PID as a child identity. Driver messages are bounded proposals, never
approval or release observations. See the Linux [UNIX-socket](https://man7.org/linux/man-pages/man7/unix.7.html)
and [PID-namespace](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html) rules.

Private operation output to the guard is a bounded pipe; the guard's public output
uses its sole separately inherited pipe to the broker. Neither accepts FD passing.
Secret-bearing stderr goes to the pinned null sink; no wrapper captures raw
exceptions. Operation stdout, if used, stays on its private guard input. Other
secret-bearing stdout is a null sink; only the guard emits the closed public
result. Supervisor records fixed exit/failure classification and physical facts.
Numeric FD slots, startup-only descriptors and every READY/transfer/cleanup
transition must match the execution lock and observed FD receipts; the ceilings
above do not permit arbitrary descriptors below the limit.

`physical_receipt_contract` supplies closed schemas for process, descriptor,
socket, source and closure observations. Receipt identifiers bind a current
monitor registry, not a saved assertion. Process identity includes PID namespace
coordinates, boot/start identity and a live pidfd reference. Descriptor identity
includes holder/FD number, object device/inode, access mode, CLOEXEC and seals;
source receipts contain metadata only. Socket identity binds both transfer ends,
namespace and actual local/peer addresses. Closure binds the exact validated
receipt set and graph manifest; a digest without the underlying live observations
is insufficient. Receipt hashes cover only validated public metadata, never data
read from a credential FD or raw TLS/request/response.

Each receipt fits the 4,096-byte frame limit; process/FD receipt sets are bounded
by the eleven-process/204-FD graph per snapshot, with at most five declared phase
snapshots per graph, and emitted as individually bounded records,
not one unbounded nested object. One final graph-closure record may reference
their validated public metadata digest only after all expected members and
outstanding transfers are accounted for. External host-owner interference and
kernel correctness remain trust assumptions; there is no hostile-host guarantee.

The broker alone receives the private authority directory mount. Namespace/mount
policy excludes it from other roles. The runtime-policy proposal below selects
physical quota and file-size mechanisms; their host applicability and actual
denial witnesses remain required. A page cap or free-space reading is insufficient.
Bootstrap/control codecs and candidate role/FD tables now appear in the inventory;
actual runtime feasibility, image pins and independent review remain pending.
No worker, namespace, GUI, socket or credential fixture was launched here.

## Proposed credential transfer and cancellation ordering (review pending)

`credential_transfer_contract` closes six selected channel payloads. Every packet
uses the existing six-field transport envelope and 4,096-byte total cap. The
inventory gives exact required fields, typed bounds, channel IDs, ancillary FD
counts and predicates. All payloads bind the original engagement, operation,
lease, owner/session/clock, generation, source/worker instances, credential
reference, runtime lock and work deadline. No message creates or extends a grant.

| Kind | Sender → recipient | Meaning |
| --- | --- | --- |
| `release_committed` | Broker → source and operation, separately | The same original confirmed release event, transfer ID, fixture and verified socket binding; no retransmission or replay from stored state. |
| `credential_transfer` | Source → operation | Exactly one metadata-validated sealed read-only memfd, once; no credential bytes in the packet. |
| `transfer_ack` | Operation → source | Matching release notice and descriptor received and metadata checked; credential not yet read. |
| `source_closed` | Supervisor → operation | Expected source termination/reaping and closure of source/root aliases observed for this transfer; no whole-graph closure claim. |
| `exchange_committed` | Broker → operation | Required pre-write audit actually committed for this waiting worker/release/socket; permits resuming the existing operation, never a second release. |
| `cancel` | Broker → source and operation, separately | Sticky stop for the original lease, including a stale generation. Confirmed policy/revoke events are linked; local deadline/store/protocol failures do not invent committed events. |

The two new notifications use existing supervisor→operation and broker→operation
channels. They add no process, FD-transfer edge, durable authority transition or
event kind. `source_closed` needs live kernel/lifecycle evidence, with its exact
observation mechanism and successful-exit mapping still prerequisites. A saved
receipt, ACK, normal-looking EOF or self-reported boolean is insufficient.

The required successful sequence is: confirmed release COMMIT; matching release
notices and the one descriptor; receiver metadata validation and ACK; source
closes its aliases and exits; supervisor observes that closure; operation checks
local stop/deadline and reads the bounded credential; operation pauses at its
pre-write barrier; broker commits `observe_exchange`; operation receives the
matching `exchange_committed`, rechecks stop/deadline, then attempts request I/O.
Source exits only after its matching ACK in the successful path. Timeout, broker
loss, malformed ACK or unexpected source death takes the cleanup path and cannot
satisfy the successful closure notification.

Different channel arrival orders are explicit. If the credential FD arrives
before the worker's broker notice, hold at most one FD without reading or ACKing
it, within the original deadline. Only the matching notice and validated source,
FD access mode, seals, size and transfer binding permit ACK. A notice without an
FD also waits. Duplicate, mismatched, extra or uncertain transfers fail closed;
no resend is allowed. Close all received ancillary FDs on refusal without reading
credential contents. Source EOF after expected shutdown is distinct from loss of
the broker or supervisor authority channel, which stops progress.

Cancellation is sticky at each recipient. A ready stop/cancel takes priority over
local progress; expiry/control loss independently stops it. Revocation ordered
before release COMMIT prevents transfer/read/request. If release commits first,
later cancellation may suppress delivery or sending but cannot recall a queued FD,
a read credential or transmitted bytes. The pre-write audit is not atomic with
the network write. Released work retains its possibly-sent classification and
consumed reservation even when local checks stop it; incomplete evidence cannot
prove zero traffic, refund allowance, resume a lease or publish late success.

The inventory includes nine race traces and a finite abstract ordering model for
static validation. Its flags record historical milestones, not current descriptor
liveness. It assumes authenticated messages and valid physical observations; it
cannot prove working IPC, cancellation latency, actual races or cleanup. Existing
SQL, lease/event schemas, gate counts and native prerequisites remain unchanged.

## Proposed socket transfer and pre-TLS ordering (review pending)

`socket_transfer_contract` defines five selected payload schemas, all inside the
existing 4,096-byte channel envelope. Schema dispatch uses `(channel_id, kind)`:
the connector ACK and credential-source ACK deliberately have different payloads.
All fields are required and non-null. Common fields bind the original operation,
lease, owner/session/clock, generation, connector/worker instances, reservation,
socket transfer, runtime/profile/trust, owned namespace and original deadlines.
Socket and credential transfer IDs must differ.

| Kind | Sender → recipient | Meaning |
| --- | --- | --- |
| `reservation_committed` | Broker → supervisor and operation, separately | Original reservation and audit commit confirmed, with exact numeric peer and live setup bindings. Never a credential-release grant. |
| `connect_reserved` | Supervisor → connector | Forward the identical validated reservation payload once; permit the single owned TCP setup. |
| `socket_transfer` | Connector → operation | Exactly one successfully connected socket and bounded metadata; no TLS or application data from connector. |
| `transfer_ack` | Operation → connector | Own reservation notice and actual socket metadata match; TLS has not started. |
| `connector_closed` | Supervisor → operation | Expected post-ACK connector termination/reaping and closure of connector/root socket aliases observed. |

These purposes use existing channels and the existing one socket-transfer edge.
Supervisor forwards metadata only, never the socket. There are no additional
processes, connections, authority transitions, SQL events or gate nodes.

Before reservation, preparation binds fresh approval/action/lease, actual role
instances, runtime/profile/trust and the owned service namespace/listener. Required
roles must be READY under their bootstrap confinement and static FD-slot rules;
dynamic connected-socket and credential slots are empty. READY cannot depend on
TCP setup, TLS or release, which would make the ordering circular. Listener
readiness must not consume a hidden probe connection. Guard readiness remains a
passive supervisor observation, with no new guard channel. Exact prepare/READY
codecs, kernel predicates and per-role FD tables remain prerequisites.

After confirmed reservation, supervisor forwards its notice to the connector.
Connector checks its live context, deadline and stop state, then makes at most
one nonblocking connection attempt to `127.0.0.1:9443` in the owned disconnected
namespace. Polling completion of that same in-progress connect is allowed within
the original deadline; a second connect, socket, DNS lookup or fallback is not.
Failure or uncertainty stops the graph. Connector never sends TLS/application
bytes or reads credentials; TCP setup traffic still counts.

The receiver checks actual connected socket type/protocol, nonblocking state,
CLOEXEC, numeric local/peer addresses, descriptor identity and connector/namespace
provenance without data I/O. If the socket arrives before its broker reservation
notice, it quarantines one FD until the matching notice, never ACKing or starting
TLS early. Both arrival orders must satisfy the same metadata and live-context
checks. Reject duplicate/mismatched/unexpected descriptors and close every
received FD on refusal; no transfer retry is permitted.

After the matching ACK, connector closes its aliases and exits. Supervisor must
observe successful expected termination/reaping and all connector/root copies
closed before emitting `connector_closed`. ACK, EOF, saved metadata or an
unexpected crash is insufficient. With that notice, its own reservation, the
validated FD and fresh stop/deadline checks, operation creates the existing
`socket_custody` receipt and starts its one TLS handshake. Only verified TLS can
produce the existing observation consumed by the separate release transaction.

Cancellation/control loss is sticky when observed; a remote revocation may race
with already reserved setup. Retain measured setup traffic and consumed allowance;
never infer zero traffic from refusal, retry uncertain dispatch or treat socket
custody as release authority. The ten race traces and finite ordering model check
only these abstract prerequisites. Actual closure mechanisms, successful-exit
mapping, remaining control codecs and native feasibility are still unvalidated.

## Proposed fixed limits and required runtime lock

These are upper bounds for the proposed implementation, not measured runtime
facts. Smaller ROE limits narrow them. Infeasible limits require a reviewed
contract change before a run, never a retry with expanded limits.

| Quantity | Maximum |
| --- | ---: |
| Concurrent active operations per broker | 1 |
| TCP attempts / TLS handshakes / HTTP requests per operation | 1 / 1 / 1 |
| Plaintext credential | 64 ASCII bytes; exact declared values only |
| Plaintext request / response headers / response body | 512 / 1,024 / 256 B |
| Total decrypted response / individual TLS I/O chunk | 2,048 / 4,096 B |
| Client-to-peer / peer-to-client TLS bytes, including setup/closure | 8,192 / 16,384 B |
| Public result / static stderr / public protocol frame | 1,024 / 128 / 4,096 B |
| Original operation interval, including cleanup reserve | 5,000 ms |
| Work interval / final cleanup reserve within it | 4,000 / 1,000 ms |
| Session / broker lifetime | 30 / 60 s |
| Single secret-bearing worker address space / CPU / file size | 256 MiB / 3 s / 0 B |
| Each secret-bearing worker: tasks / executable replacements after READY | 1 / 0 |
| Source package / public bundle / bundle members | 4 MiB / 4 MiB / 32 |
| One evidence reader wall time / JSON nesting | 2 s / 12 |

The full reservation is one action, one connection, 8,192 outbound and 16,384
inbound TLS bytes, and 5,000 ms. Plaintext counters are additional observations,
not extra budget. No refund follows a refusal or unobserved send. Reads/writes
must stay within their remaining allowance; no uncharged one-byte overflow probe.
MemoryBIO buffering is charged and bounded separately from OS delivery. Unknown
delivery remains null, never inferred from bytes buffered or a completed TLS call.

Before native work, a reviewed execution lock must name exact role images and
their source/dependency hashes, Python/OpenSSL ABI, certificate/trust bytes,
per-role UID/GID/capabilities, user/net/mount/PID namespaces, mount/device/FD and
syscall allowlists, descriptor transitions, actual parent/pidfd/start identity,
whole-graph process/task ceilings, readiness, release and cleanup predicates.
The limits above do not replace that role-by-role lock. In particular, the
whole-graph bound cannot be guessed from worker count; wrappers, source worker,
reviewer, connector, service, release guard and cleanup helpers all count.
No inherited FD except the role's exact declared channels is permitted.

Sanitize the environment before Python/TLS imports. No HOME-derived configuration,
proxy, credential variable, agent socket, default trust/keylog location or writable
host filesystem is exposed. Validate actual executable mappings and source
coverage, not only package size. Physical witnesses must include positive controls
for denied endpoints, process/namespace creation, unexpected FDs and late output.
No current runtime manifest is claimed to cover these new TLS/secret-bearing roles.

## Design checkpoint: bootstrap, evidence and implementation map

The inventory now contains `bootstrap_contract`, `runtime_policy_contract`,
`public_evidence_contract` and `implementation_plan`. These are proposals for
independent review and the design commit required by the delivery order below.
They do not mark an implementation or native gate passed. Remaining actual host,
image, syscall-argument, FD and graphical applicability must be demonstrated;
a candidate table is not an observation.

Three corrections to earlier proposals require explicit scope review before use:

- The broker may use two prestarted threads only for mapped concurrent authority
  fixtures, with one separately configured SQLite connection per thread. Ordinary
  cases retain one thread. This raises the proposed base-task ceiling to eleven
  and the all-variant ceiling to twenty; processes remain eleven at most, FDs204,
  and each secret-bearing worker remains single-task. Two real contenders must
  reach the actual SQL barrier; a sequential mock does not prove a race.
- A stock graphical X server has no custom control protocol. Its supervisor
  socket pair is removed; observe its pidfd, confinement, owned AF_UNIX listener
  and actual reviewer handshake instead. There is no wrapper daemon, xauth
  subprocess or host display fallback. The display's actual slot/task/protocol
  feasibility remains a native prerequisite.

- PR106 withdrew the impossible post-READY recovery fork. AUTH02/03/04 remain
  mandatory and unexecuted. The reviewed prestarted recovery design below now
  fixes the creator and evidence contract; runtime execution remains disabled.

The bootstrap contract specifies closed `start`, `ready`, `stop`, `fixed_failure`,
`prepare`, case-proposal/cancellation/report and transfer-ACK observation payloads.
Existing observation and physical-receipt schemas bind the remaining typed
channels; schemas are selected by channel ID and kind. Secret result pipes carry
only the independent six-field result grammar. A parser cannot pass arbitrary
private response data into a purported result envelope. The guard validates that
record independently; broker constructs the observation envelope from the bound
pipe identity. Graphical and declared probe transports are explicit exceptions
whose concrete runtime protocol must be locked before launch.

Each role has a proposed numeric FD-slot table, including phase-limited bootstrap,
store/journal, pidfd, private/public output and dynamic transfer slots. Logical
bidirectional channel purposes share a physical endpoint per peer pair. Empty
slots are not arbitrary extra FD permissions. Incoming ancillary allocation,
remapping, transient resources and actual SQLite/X server FD behavior must fit
these declared slots or receive a reviewed amendment; no feasibility is claimed.
Driver's owned public export/input slots are separate from custody descriptors.

READY follows observed confinement and static resources; it cannot require a
connected operation socket, TLS or credential release. Guard readiness is a
passive observation of its confined image and exact pipes before private input.
For source/connector closure, operation sends a closed `transfer_ack_observed`
notification on its existing supervisor channel after the private ACK succeeds.
Supervisor combines that live binding with actual expected child reaping and
root-copy accounting; it never snoops the private transfer pair or duplicates
secret FDs. Only the ACK-validated child path exits0 successfully. Signals,
premature/nonzero exit, missing acknowledgment, timeout or merely disappearing
`/proc` entries cannot satisfy successful closure. Linux documents
[pidfd-based wait semantics](https://man7.org/linux/man-pages/man2/waitid.2.html);
actual kernel permissions and negative observations remain gated.

The runtime policy assigns distinct proposed child IDs and minimal mounts,
capabilities and default-deny syscall candidates. Actual host mappings, driver
identity, bootstrap privileges, syscall arguments and compiled filters must be
measured and reviewed before launch. Zero child capabilities do not establish
supervisor metadata visibility; the retained metadata privileges are explicitly
scoped and cannot authorize secret FD duplication or process-memory inspection.

Physical storage is proposed on a dedicated **owned XFS project with enforced
80MiB hard quota**, plus a three-inode limit for directory/database/journal.
Database logical length remains32MiB through SQLite's page cap; broker FSIZE40MiB
bounds journal length. Allocated-block quota and logical file limits are distinct.
The directory is broker-only,0700, with constant database/journal names and0600
files; inode/project identity and exact entries are checked. Filename semantics
still trust the reviewed broker/SQLite/VFS. No quota is claimed to enforce honest
code. Verify actual quota/inode/FSIZE denials on a separate disposable owned
allocation, then bind controlled store faults to the authority witnesses.
[Kernel XFS documentation](https://docs.kernel.org/admin-guide/xfs.html) distinguishes
project quota accounting from enforcement. No filesystem, quota, mount or live
store has been created or modified in this design work.

The public bundle has exactly nine members: manifest, context, result, authority,
physical, progress, transaction-witness, observation and binding files. Inventory
schemas give their exact names/fields, bounds and member/kind dispatch. Total cap
is4MiB, public records3072bytes and complete channel frames4096bytes; limits apply
together, never by truncation. Null counters mean unknown, not zero. Source,
request, response, exception, journal and database-page bytes are not evidence
fields. Only validated public records are hashed or forwarded to the driver.
Receipt-set digests use a specified domain and deterministic ordering, with all
underlying observations required. A digest does not replace physical proof.

Both readers open only owned regular nonlinked members, enforce before/after
identity and size checks, exact manifest membership, typed crosslinks and semantic
ordering, and produce their bounded closed inspection receipts. Original
Python/CLI inspections remain immutable outside the bundle; replay modifies copies.
Useful results require their actual TLS/release/exchange/closure/completion chain.
Startup failure and unknown counters cannot satisfy later negative witnesses.
Failure artifacts remain preserved and sentinel checks never echo matched bytes.

The implementation plan allocates seventeen new modules under the independent
`recon_cockpit_synthetic` package, the two already named test files and three public
synthetic TLS fixture files. It avoids importing the legacy `recon_cockpit`
initializer. Only explicit own-module dependencies and reviewed standard-library
imports are proposed; no provider/legacy/catalog/dependency edits are authorized.
A later reviewed preservation amendment must name each new path literally before
implementation. These files have not been created by this checkpoint.

Every existing portable node and all89 unique native nodes map to source modules,
actual barriers and public evidence. All ten authority witnesses and the concurrent
K02/K03/A08 controls have explicit transaction/ordering bindings. The two-thread
fixtures retain per-connection safety and configuration; Python documents
[connection thread ownership](https://docs.python.org/3/library/sqlite3.html).
Production SQL, old schema invariants, budgets and canonical obligations are
unchanged. PR106 published the corrected design at merge834c9da. The recovery
contract below is a later bounded design amendment; implementation, runtime proof
and native acceptance remain separate gates.

## Evidence and the exact 19-obligation mapping

The inventory is authoritative for the finite proposed variants and planned node
IDs. Each original obligation, requirement list, gate list, stimulus, expected
outcome and proof text is copied unchanged. K01's terminal positive also supplies
A01's ordinary ready proof; it is one physical observation, not two useful reads.
All other native variants are distinct. Parents and test/variant counts are
different denominators. Every declared reflection, follow-up, malformed framing,
source, clock, cap and interruption variant must have its own retained outcome.
The plan contains 79 distinct custody/operation native variants plus 10 affected
authority variants: 89 native observations, 178 original reader observations and
29 planned portable nodes. The 19 canonical parents and 16 physical parents stay
unchanged; authority witnesses have separate counts. These are planned coverage,
not executed or accepted results, and give no new credit to S4.2c.

Each new native variant produces one bounded public bundle and its original
immutable Python and CLI inspection pair. V02 covers that complete original
inventory without rerunning those readers. V03/V04 use copies for their finite
mutations, retaining originals and exact before/after path/descriptor metadata.
Replay cannot reconstruct discarded credential-bearing wire data, authenticate a
secret, contact the service or restore authority. Hashes provide consistency,
not protection against coherent host-owner rewriting.

Every native case must reach its named boundary and positive-control predicate.
A startup refusal cannot count as a TLS trust negative, authentication denial,
live revocation, reflection rejection or useful result. K03 before-release
variants require the actual waiting custodian and zero credential read/request;
after-release interruption belongs to K06/A08 and retains uncertainty. K05 and
A07 require a real bounded response from the owned fixture. A05 requires a live
follow-up witness with no extra connection or request. A06 distinguishes a
pre-connect binding refusal from an actual failed TLS peer/name/trust check.

Keep separate totals for ready, degraded, authentication refusal, authorization
refusal, authority refusal, invalid/unsupported response and interrupted unknown.
Record attempts, reservations, setup traffic, actual delivered bytes when known,
elapsed intervals, stop reason and physical closure. No provider calls/cost or
new accepted catalog capability results from these cases. Original failed public
evidence is retained; diagnostics receive no formal acceptance credit.

## Delivery order and stop conditions

This draft is a concrete reviewable first step, not permission to skip unresolved
design. The inventory records each readiness gate separately:

1. **Now:** validate verbatim 19-parent coverage, finite variants, planned node
   uniqueness, preservation and this design's independent review. Run only the
   affected preservation check with the new documents tracked; retain any failure.
   No TLS, credential-source or native execution is needed for this step.
2. **Before implementation:** complete and review the exact authority ROE/lease/
   event/store DDL and protocol schemas; the role/channel graph and ceilings;
   the public evidence schema; the allowed new-file/import plan; and the complete
   affected-gate validation plan, including each new-authority witness and the
   concurrent K02/K03/A08 controls above. Publish this corrected design-only draft only after clean review and required checks.
3. **Later implementation after this design-only publication:** closed portable schema/state/parser
   behavior first, then the isolated runtime and owned service. Do not alter
   accepted S4.2, provider, legacy or competition sources as a shortcut.
4. **Before native execution:** freeze actual code/runtime/trust/fixture identities,
   collect the exact planned test nodes and compare them to the inventory. Review
   actual isolation/readiness and environment applicability. Missing or null pins
   block execution; source changes invalidate only the affected declared gates.
5. Run targeted portable checks once, then one reviewed useful terminal control
   and its source/evidence review before the remaining native variants. Use one
   serial native worker, preserve failures and stop at the first unclassified
   failure. Complete original reader inventory, semantic obligations and required
   affected regressions/full portable/CI/final review. No automatic retry loop.
6. Recheck main and conflicts before merge; verify the actual merged tree and
   postmerge checks. S4.4 real use and Stage 4 remain open after S4.3 acceptance.

Do not rerun S4.2c's completed evidence census or suites just to resume this draft.
The only existing-file amendment in this change is
`tests/test_secure_engagement_live_preservation.py`: add the two exact new document
paths with literal SHA-256 pins and regular-file/non-executable checks to its
tracked-path allowance. Retain every historical manifest, hash, count and check.
The inventory records the original test hash and this amendment's scope; it does
not hash the amended test back into itself. No wildcard, inventory-derived path
permission or blanket S4.3 source exception is allowed. Future implementation
paths need their own explicit reviewed scope update.

All existing production, dependency, historical contract, legacy, provider and
competition files remain unchanged. The eight already reviewed status-document
edits are preserved separately in the main checkout. Any further shared-source
change, additional PR split, variant removal, limit relaxation or runtime fallback
requires an explicit reviewed scope update before use.

## Review corrections and design-only publication

PR106 left recovery allocation unresolved after withdrawing an impossible
replacement mechanism. The later reviewed contract below supplies a finite
prestarted design. AUTH02/03/04 retain their exact nodes and remain unexecuted.
No post-READY clone/fork privilege or native execution is granted.

Progress now has authenticated closed reports on existing connector, operation
and service supervisor channels. Live subject/session/epoch/runtime and sample
sequence must match; producer perspectives and fields are distinct. Connector
attempts, client writes and server receipts are different observations. Unknown
fields are null, samples are cumulative, and missing reports never establish zero.
At most16 reports each (48 total) fit the existing64-record cap. Physical metadata
cannot manufacture private counters; crashes retain uncertainty.

Failed reader receipts always use null observed bundle/manifest identities with
non-none reason. Valid receipts require both validated identities and reason none.
Counts describe successfully validated progress only. Rejected input is never
opened or hashed solely to populate a refusal. Trusted harness association stays
outside observed identity fields in a closed independently trusted record.

AUTH04 uses a separate read-only lookup_observed projection in transactions.jsonl,
sharing its existing caps. References resolve exported closed lease/closure and,
only if completed, the original completion/result. Other lookup statuses have
null completion claims. There is no mutation/audit event or restored grant.

The latest user authorization supersedes earlier same-PR/no-contract-only-merge
wording in this draft. This publication is design-only; independent review and
required CI remain mandatory. Implementation/native/Stage4 acceptance stay false.


## Reviewed recovery bootstrap contract

`recovery_bootstrap_contract` is the exact bounded design for AUTH02/03/04.
Independent protocol/provenance and accounting reviews covered this amendment.
Its implementation/execution flags remain false. This scope adds no production
source, tests, credential source or native observation and grants no acceptance.

The existing supervisor creates exactly one recovery-only broker during original
privileged bootstrap, before its own confinement. Both broker instances use the
existing broker UID/GID10001, zero capabilities and distinct instance/owner/session
IDs. The recovery image/filter and private authority mount are established then;
it receives only its supervisor endpoint and declared storage directory. Its
confined receive barrier opens no database/journal. Supervisor observes SIGSTOP
through its birth pidfd before the initial broker may open/create the store.
This explicitly permits two broker processes in these three terminal fixtures,
with one store user at a time; all other cases retain one broker. It is not an
extra general launcher or a post-READY fork exception.

Only after actual original-owner graph closure may supervisor consume its sole
activation, recheck the stop, send SIGCONT and observe the actual continued event.
Recovery then receives the closed activation packet and starts its fresh observer
session. Its one challenge obtains authenticated historical provenance and fresh
cleanup bindings before SQLite open. Recovery validates the same store/history,
executes existing recover_owner/close_lease transactions, and performs read-only
lookup. It cannot reserve/release, reconnect, resend, replenish or restart.

The five exact packet payloads are prepared, activate, challenge, response and
refused under the recovery prefix. Existing fixed-failure/monotone-stop and public
record transports have explicit recovery endpoints. All fields are mandatory,
closed and typed; response lists at most three separately validated binding IDs.
Flattened control receipts preserve the existing physical nesting-depth3 limit.
No extra public bundle member, arbitrary transcript or opaque extension is added.

Supervisor continuously retains actual birth pidfds, original wait events and
immutable instance membership. Original records retain their original observer
sessions/times. Typed termination records prove actual reaping; process identity
alone does not. Fresh recovery bindings require a current terminal-state and
root-descriptor/transfer audit by that same live monitor. Canonical execution-graph
identity ancestors may support exact owner/operation subsets; they never stand
for whole-graph cleanup. Historical records delivered to the bounded read-only
recovery cache cannot enter its live authority registry or be republished.

The only cross-session authority exception is fresh graph_closed -> fresh
recovery_closure_binding -> immutable original closure/member/wait provenance.
An old action, approval, TLS, result or progress reference gains no new permission.
AUTH04 looks up its existing closed completion; it creates no duplicate completion
or operation closure. Unknown delivery remains unknown in AUTH03. AUTH02 retains
the consumed reservation and refuses the old grant. Supervisor loss destroys this
live-monitor path; saved receipts cannot reconstruct it.

| Resource | Recovery allocation | Existing limit |
| --- | --- | --- |
| Processes / tasks / lifetime processes | 10 / 11 / 10 | 11 / 20 / 12 |
| Snapshot process / descriptor records | 10 / 94 | 11 / 204 |
| Phase snapshots | 10 total, at most5 per graph | 10 / 5 |
| Physical records | 1,070 | 1,075 |
| Public records including manifest | 1,395 | 1,530 reader cap |
| Reserved public bytes | 2,909,552 | 4,194,304 |
| Authority references | At most12 original +3 recovery | 32; no reuse |

Every member has a count and byte reservation, including failures, waits,
control receipts, bindings and final manifest/result. Physical records are bounded
to2048 bytes in this profile; complete transport packets remain4096. The ten-slot
snapshot ledger names every graph/phase. Reaped processes are never assigned a
new /proc snapshot. Original broker publishes cut/witness evidence; recovery alone
exports validated authority history and final recovered result, once.

Transport accounting charges every hop, including the historical provenance
cache: at most3960 seqpacket attempts and four bounded result-pipe frames. These
are internal serialized-message bounds, separate from network/TLS budgets and
the4MiB public artifact. Unknown/failed sends consume their allowance, with no
retry. Failed prefixes remain failed; no cropping or invented late observations.

No deadline restarts: standby consumes the original session/broker allowance,
and original operation/work/cleanup bounds remain. Exact pidfd wait/signal
arguments and both direct and indirect signal-producing interfaces are restricted.
See Linux [waitid semantics](https://man7.org/linux/man-pages/man2/waitid.2.html),
[inherited seccomp filters](https://man7.org/linux/man-pages/man2/seccomp.2.html)
and [descriptor-driven signals](https://man7.org/linux/man-pages/man2/F_SETOWN.2const.html).
The static contract does not prove actual filter, mount, VFS, timing or runtime
feasibility; those remain mandatory native prerequisites.

The next implementation step requires a separately reviewed literal source/import
preservation amendment for selected portable modules and tests. This design
amendment updates only these two design documents and their literal pins in the
existing preservation test. Historical contracts, SQL semantics,19 obligations,
29 portable node identities,89 native node identities and global limits remain.

## Portable public-result codec amendment

The first implementation slice provides intrinsic validation and canonical
encoding for the six-field public result only. Its independently reviewed scope
contains exactly three new source files: `recon_cockpit_synthetic/__init__.py`,
`recon_cockpit_synthetic/contract.py`, and `recon_cockpit_synthetic/codec.py`.
The empty initializer avoids legacy package imports. The contract imports nothing;
the codec imports only `json`, `re` and its own contract, and performs no
application I/O, hashing, authority lookup, SQL, TLS or native operation.

The existing planned file `tests/test_secure_synthetic_custody_contract.py`
contains exactly six additional unit nodes, listed in `portable_result_codec_slice`
in the inventory. These are implementation regressions with no acceptance credit.
The current slice collects six unit nodes; the existing 29 formal portable node
identities remain planned and unimplemented. The eventual portable union is35
(29 formal plus6 unit), recorded separately. All89 native identities, original
obligations, variants, limits, pending statuses and acceptance counts remain.

The only existing-file changes are this appended note, the new scoped inventory
object and mechanical `contract_sha256` refresh, and literal document/source/test
pins plus path/mode/import checks in the existing preservation test. The inventory
object records the narrowly approved implementation scope; all broader readiness
and acceptance flags retain their historical values. No other source allowance
is implied. Private review receipts are retained with the handover.

`decode_public_result` checks bounded canonical bytes and equality with a supplied
trusted operation UUID4. `encode_public_result` checks exact built-in values and
produces the same canonical bytes. Fixed rejection codes reveal no input fragments.
Neither function establishes that the caller's subject is authenticated or that
release, actual exchange, current authority, cancellation/expiry or cleanup has
been proved. Those checks remain mandatory downstream before use/publication.
No runtime, native execution, broader implementation readiness or S4.3 acceptance
is established by this portable slice.

## Portable intrinsic ROE codec amendment

After verified PR108 publication, the independently reviewed next slice extends
only the existing contract/codec, codec unit tests, these two design documents
and the existing preservation test. It adds no tracked paths. The exact scope
and node ledger are recorded separately in `portable_roe_codec_slice`.

`decode_public_roe` and `encode_public_roe` validate the existing fourteen-field
ROE grammar, five budget dimensions, ordered fixture subsets, fixed operation
profile, canonical UUID/hash/UTC forms, Gregorian dates and intrinsic
revision/predecessor/time relations. Frames remain bounded to4096 bytes/depth2.
The only additional import is `datetime` for calendar validation; no wall clock,
timezone discovery, I/O, hashing, SQL or runtime operation is performed.

Valid empty fixture lists, exclusions and zero/insufficient budgets remain valid
declared records. Parsing neither adopts a revision nor establishes admission,
remaining lifetime allowance, current predecessor/owner/generation, live trust or
runtime bindings. Those authority predicates remain separate and unimplemented.
The returned subject equality is only equality to a caller-supplied trusted ID.

Six exact ROE unit nodes join the six result unit nodes: actual unit collection12,
formal portable identities29 unchanged, eventual portable union41, native89
unchanged. No formal acceptance credit follows. Existing schema values, limits,
case mappings, prior result-slice ledger and broader readiness flags are unchanged.
The preservation amendment updates only literal changed-file pins and the explicit
datetime import allowance. Native execution and publication of this new slice
remain separate gates; all failed evidence is retained.


## Reviewed portable lease codec slice

After verified PR109 publication, this independently reviewed slice extends the
same six existing paths with an intrinsic lease codec. No new tracked paths or
imports are admitted. The prior result/ROE helpers and twelve unit nodes remain
unchanged. The exact local scope is pinned by `portable_lease_codec_slice`.

The codec checks the closed 33-field snapshot, canonical ASCII bytes4096/depth1,
exact scalar types and subject equality, Gregorian UTC intervals up to30 seconds,
bounded monotonic deadline differences and state/close-kind nullability. Completed
pre-release observations and cancellation in any stored state remain legal.
Single-record validation proves neither transitions nor live identity, authority,
original clock health, external deadline minima, event links or physical cleanup.
Stored deadlines never authorize resumption.

Seven new finite unit nodes join the preserved twelve: actual collection19 and
eventual portable union48 remain distinct from the unchanged formal29/native89
identities. No formal acceptance is claimed. The preservation amendment refreshes
only literal hashes; source/import allowances, historical assertions and all
broader implementation/native readiness and acceptance flags remain unchanged.


## Reviewed portable event codec slice

After verified PR110 publication, the independently reviewed next slice extends
the same six existing paths with an intrinsic authority-event codec. No new paths
or imports are admitted; all shared helpers and nineteen prior unit nodes remain
unchanged. The exact local scope is pinned by `portable_event_codec_slice`.

The codec validates the fifteen-field envelope and eleven closed variants within
4096 canonical ASCII bytes and depth3, with exact types and expected engagement/
operation/lease/event equality. Intrinsic checks cover sequence/predecessor
nullability, variant subject scope, reservation vectors/totals/deadlines, local
adoption/revocation relationships, closure/completion links and nested result
bindings. Returned nested dictionaries are fresh. These checks do not establish
ledger history, actual accounting, authenticated observation, same-store commit,
current authority or physical cleanup.

Eight new finite unit nodes give actual collection27 and eventual portable union56.
Formal29/native89 identities and all broader readiness/acceptance flags remain
unchanged. The preservation amendment updates only five literal hashes; no
existing path/import allowance or historical assertion changes.


## Reviewed portable observation record codec slice

After verified PR112 publication, the independently reviewed next slice extends
the same six existing paths with intrinsic observation record encoding and
decoding. PR112 corrects the owned portable fixture that failed after PR111;
PR111's original failed main-CI evidence remains failed and preserved. The reviewed
prerequisite amendment binds this slice to the verified PR112 merge. No new paths
or imports are admitted; all shared helpers and twenty-seven prior unit nodes
remain unchanged. The exact scope is pinned by `portable_observation_codec_slice`.

The codec validates the seventeen-field envelope and six closed payload variants
within 4096 canonical ASCII bytes and depth3. Checks include exact types, claimed
role consistency, operation/lease/owner subject nullability, approval digest and
nested result relationships, declared TLS literals and exact closure booleans.
Expected engagement/operation/lease/reference IDs are compared after intrinsic
and canonical validation; returned nested dictionaries are fresh.

These records do not authenticate a producer, register or resolve a reference,
establish clock freshness, prove TLS or physical closure, or authorize an
operation. A fresh observer may name an old subject owner. The operation profile
hash remains syntax-only here; all external authority and physical bindings stay
gated.

Seven new finite unit nodes give actual collection34 and eventual portable union63.
Formal29/native89 identities and all broader readiness/acceptance flags remain
unchanged. The preservation amendment updates only five literal hashes; existing
path/import allowances and historical assertions remain unchanged.

## Portable custody receipt codec slice (partial intrinsic coverage)

The independently reviewed six-path scope extends the verified PR113 base
`b5c9dc092ec977125b8d7a8ba9895ba2559a8c9e` with only `socket_custody` and
`source_custody` record parsing/encoding. `decode_custody_receipt_record` and
`encode_custody_receipt_record` require expected subject-owner, nullable operation,
graph and receipt identifiers. These APIs cover two variants of the existing
physical-receipt schema; they are not a complete physical-receipt validator.

The closed 14-field envelope and 13/12-field payloads retain the existing
4096-byte ASCII JSON bound, depth-three guard, canonical representation and exact
built-in scalar types. All five declared phases and nullable operation identifiers
remain representable for both variants. Claimed issuer role must be the declared
`operation_worker`; this consistency check does not authenticate that producer.
No issuer/receiver equality, pairwise UUID distinction or stronger phase mapping
is inferred. Socket namespace zero remains a valid u64 value. Source size is
checked only against the declared 1..64 range; fixture material is never read.

Actual producer identity, current registry resolution, socket/memfd identity,
namespace/address metadata, seals and access mode, exact fixture size, live alias
closure, release commitment, ordering, deadlines and current authority remain
external gates. A parsed record proves neither physical custody nor closure and
authorizes no operation. No runtime, registry, SQL, descriptor or native behavior
is implemented by this slice.

Six new finite unit nodes extend the prior 34 unchanged codec nodes to 40 actual
units. Local validation collects those exact 40 nodes and runs only the six new
units plus the affected preservation check. Formal portable29/native89 counts
remain unchanged; the eventual portable union is69. This slice grants zero formal
acceptance credit and does not reopen S4.2c checks or authorize native execution.

## Portable descriptor identity receipt codec slice

The independently reviewed six-path scope extends verified PR114 main
`e7fa35c21cdec329e08257e86a1fbb0d9a1287b0` with only `descriptor_identity`
record parsing/encoding. `decode_descriptor_receipt_record` and
`encode_descriptor_receipt_record` require expected subject-owner, nullable
operation, graph and receipt identifiers. Existing custody APIs retain their
original socket/source coverage.

This slice validates the existing closed 14-field envelope and 11-field payload,
canonical ASCII JSON within4096 bytes/depth3, exact built-in scalar types, declared
UUID/hash formats and numeric limits. FD numbers retain the0..2147483647 range;
the204-descriptor graph ceiling is not a scalar FD-number limit. Device/inode
values retain the entire u64 range, including zero. Claimed issuer roles are
supervisor, driver, fixture_source, connector or operation_worker; the claim does
not authenticate the producer. All five phases remain representable.

Peer and transfer identifiers are independently nullable in the record syntax.
Their required eligibility for declared nonchannel/nontransferred objects remains
unproved until the runtime manifest/slot/channel/transfer bindings are available.
No joint-null rule, issuer-holder equality, or object/access/seal mapping is
invented. All eight object kinds, three access modes and two seal values remain
representable; a descriptor credential_memfd record is not narrowed to source
custody constants. Actual issuer, holder/process incarnation, registry, exact slot
and phase, object/transfer identity, access/seals/CLOEXEC and permitted observation
methods remain external gates. Parsing grants no authority or physical evidence.

Six new finite unit nodes extend the prior40 unchanged codec nodes to46 actual
units. Local validation collects exact46 and runs only those six new units plus
the affected preservation check. Formal portable29/native89 stay unchanged;
eventual portable union75 grants zero formal acceptance credit. No native or
closed S4.2c execution is authorized by this slice.


## Portable process identity receipt codec slice

The independently reviewed next slice follows verified PR115 at
`7d48672df86c56ac70b3f1ee4633c5e719703287`. It adds only `process_identity`
record parsing/encoding through `decode_process_receipt_record` and
`encode_process_receipt_record`, with required expected subject-owner, nullable
operation, graph and receipt IDs. The closed14-field envelope and16-field
payload retain canonical ASCII JSON,4096-byte/depth3 limits and fixed errors.

Ten claimed issuer/subject pairs are representable: driver observes supervisor;
supervisor observes its nine declared child roles. Driver identity remains with
outer-launcher custody. Child capability masks must be zero; supervisor masks
retain canonical16-lowercase-hex syntax with actual privilege pins external.
Task counts obey the declared static role ceiling after generic1..8 validation;
broker count2 does not establish concurrent-fixture or recovery eligibility.

PID syntax is1..2147483647; namespace inodes/start ticks retain full unsigned64,
including zero; UID/GID are0..4294967294; no-new-privileges is exact True.
Parent references remain independently nullable, with no invented UUID equality,
non-nullness or distinctness rule. All five phases and nullable operation remain.
Actual parentage, supervisor PID1, namespace visibility, pidfd custody, boot/start
identity, image/credentials, privilege pins, profile eligibility and current
registry bindings remain external gates. Parsed claims authenticate no producer,
prove no live process identity or termination/reaping, and authorize no operation.

The six append-only process units bring actual codec collection to52; prior46
remain unchanged. Seven affected checks cover these units and preservation. The
formal29 portable and89 native nodes remain unchanged; eventual portable union81
carries no acceptance credit. Existing helpers/imports and custody/descriptor APIs
remain unchanged. No runtime, process inspection, SQL, registry or native execution
is introduced; closure, termination and recovery variants remain separately gated.


## Portable monitor termination receipt codec slice

The independently reviewed next slice follows verified PR116 at
`b82b05b7b0d93bb89fca0179ede1b7ea0c4a3e37`. It adds only `monitor_termination`
record parsing/encoding through `decode_termination_receipt_record` and
`encode_termination_receipt_record`, with required expected subject-owner, nullable
operation, graph and receipt IDs. The closed14-field envelope and10-field non-null
payload use canonical ASCII JSON, a complete-record2048-byte limit and depth3.
The generic physical4096-byte ceiling does not override this variant's profile.

Claimed issuers are driver or supervisor. Exit codes are CLD_EXITED, CLD_KILLED
or CLD_DUMPED, each retaining scalar exit-status0..255; si_signo is SIGCHLD.
PID syntax is1..2147483647; child-UID syntax is0..4294967294. Both monotonic
fields retain0..9223372036854775807, and all UUID/hash fields retain their full
canonical syntax. All five phases and nullable operation remain representable.
No session equality, timestamp ordering, UUID distinctness or unproved child-role
relationship is imposed by this intrinsic parser.

Actual waitid/reaping, retained birth pidfd, direct parentage, child PID/real UID,
authenticated issuer, original session/time and live ancestry/graph/epoch/runtime
bindings remain external gates. The aggregate ten-record cap remains external.
Parsed claims prove no actual termination or live custody, establish no successful
source/connector closure and authorize no operation. Signal-death claims never
establish successful source_closed/connector_closed; even CLD_EXITED/status0
syntax does not establish that closure. No wait, signal or process operation is
introduced; recovery ancestry exceptions remain unchanged and separately gated.

Six append-only termination units bring actual codec collection to58; prior52
remain unchanged. Seven affected checks cover these units and preservation.
Formal29 portable/native89 remain unchanged; eventual portable union87 earns no
acceptance credit. Existing helpers/imports and prior receipt APIs are unchanged.
Graph closure and other recovery variants remain separate; no native execution
is authorized by this slice.

## Portable graph-closure receipt codec slice

The independently reviewed slice follows verified PR117 at
`85dfad26815eb21f1181b7650ea6e9cc15fa84a5`. It adds separate
`decode_graph_closure_receipt_record` and `encode_graph_closure_receipt_record`
APIs for intrinsic `graph_closure` claims only. The closed14-field envelope and
closed10-field payload use canonical ASCII JSON with the generic physical
4096-byte/depth3 limits. Recovery still requires its additional2048-byte gate;
generic parsing does not establish recovery eligibility.

Only a claimed supervisor issuer is allowed. The codec checks canonical scalar
syntax, integer counts0..11, exact zero descriptor/transfer claims, and an exact
built-in list of0..11 unique UUID4 member receipt IDs. It preserves array order
and permits empty lists. Expected/reaped counts must equal the list length, and
payload/envelope graph IDs must agree. Owner scope requires null operation;
operation scope requires non-null operation. Both reasons and all five phases
remain representable. Explicit expected owner/operation/graph/receipt IDs bind
the parsed record; outputs contain fresh envelope, payload and member-list objects.

These checks only reconcile claims. The codec authenticates no producer and
registers/resolves no receipt. Exact live manifests/membership, actual reaping,
observer exclusion, root-side descriptor closure and absence of transfers remain
external. A zero-member claim proves no empty live graph. Digest computation and
framing remain pending design; only hash syntax is checked. Session/epoch/runtime
lock, ancestry and continuous custody, aggregate quotas and successful cleanup
remain external gates. Saved records/digests grant no authority or cleanup proof.

The exact six-file scope is pinned by `portable_graph_closure_codec_slice`.
Prior58 codec units and existing helpers/imports remain unchanged. Six additional
finite units bring actual unit collection to64; affected local validation runs
those six plus the preservation check. Formal29 portable/native89 remain
unchanged; eventual portable union93 gives no acceptance credit. No runtime
registry, native execution, closed S4.2c rerun or strategic gate change is included.

## Portable recovery closure-binding codec slice

The independently reviewed slice follows verified PR118 at
`94d5b6054d83e98d2e755fde59640cd3566e0598`. It adds separate
`decode_recovery_closure_binding_record` and
`encode_recovery_closure_binding_record` APIs for intrinsic
`recovery_closure_binding` claims only. The closed14-field envelope and
closed12-field payload use canonical ASCII JSON, a complete-record2048-byte limit
and depth3. Explicit expected owner/operation/graph/receipt IDs bind the record.

The codec allows only a claimed supervisor issuer and closed phase. Envelope
observer session, graph and observed time must equal payload consumer session,
subject graph and evaluation time respectively. The three closure predicates
require exact Boolean True. Termination receipt IDs form an exact built-in list
of1..10 unique canonical UUID4 strings sorted in ASCII order; unsorted input is
rejected, never repaired. The nullable envelope operation remains representable.
Returned envelope, payload and termination-ID list are fresh plain objects.
Existing graph-closure member-list ordering and every prior API remain unchanged.

These checks authenticate no producer and register/resolve no receipt. They prove
no historical membership/reaping, unbroken supervisor/pidfd custody, current
terminal/root-copy/transfer observations, successful cleanup or recovery
eligibility. Parsed True values confer no authority. Original-owner/current-
consumer binding, ancestry and immutable historical sessions/times remain external
registry checks; no general owner/session inequality or UUID distinctness is
invented. Separate provenance cache, cleanup registration, AUTH04 lookup-only
behavior, exact operation binding and aggregate quotas remain mandatory gates.
No store open, protocol action, digest framing or public evidence export is added.

The six-file scope is pinned by `portable_recovery_binding_codec_slice`.
Prior64 codec units and existing helpers/imports remain unchanged. Six additional
finite units bring actual collection to70; affected local validation runs those
six plus preservation. Formal29 portable/native89 remain unchanged; eventual
portable union99 gives no acceptance credit. No native execution, closed S4.2c
rerun or strategic gate change is included.


## Portable recovery lifecycle codec slice

The independently reviewed slice follows verified PR119 at
`f4e2b5fea0681250f025625387c538a1db2969f5`. Separate
`decode_recovery_lifecycle_record` and `encode_recovery_lifecycle_record` APIs
validate intrinsic `recovery_lifecycle` claims in a closed14-field envelope and
closed13-field payload. Canonical ASCII records retain the complete-record2048-byte
limit and depth3. Expected owner/operation/graph/receipt IDs bind each record.

Only a claimed supervisor issuer is allowed. The three accepted state/wait/signal
tuples are stopped/CLD_STOPPED/SIGSTOP, precontinue/CLD_STOPPED/SIGSTOP and
continued/CLD_CONTINUED/SIGCONT. SIGCHLD is exact; PID is1..2147483647 and UID
is0..4294967294. Envelope/payload observation times both use0..9223372036854775807
and must match. Four digests require full lowercase SHA-256 syntax only. All five
phases and nullable operation remain representable, without inferred phase/state,
monitor/observer equality, UUID distinctness, digest equality or sequence ordering.
Decoded envelope/payload are fresh plain objects.

Parsed claims authenticate no producer, register/resolve no receipt, prove no
actual wait/stop/continue, installed filter, live custody or recovery eligibility,
and authorize no operation. Actual birth pidfd/child PID/real UID, one-task stopped
state, retained initial notification, consumed precontinue notification and the
one SIGCONT remain external observations. Native wait sets remain initial
WSTOPPED|WNOHANG|WNOWAIT, precontinue WSTOPPED|WNOHANG, continued
WCONTINUED|WNOHANG, and separate termination WEXITED|WNOHANG without WNOWAIT.
Trusted installed-filter contents/provenance, exact bootstrap/FD layout, continuous
custody and supervisor/monitor identity remain mandatory external gates. At most
three chronological records, one per state with the same birth pidfd/bootstrap
manifest, remains an aggregate gate. No wait, signal, protocol or digest action
is added; a parsed receipt cannot substitute for termination/reaping evidence.

The six-file scope is pinned by `portable_recovery_lifecycle_codec_slice`.
Prior70 codec units and existing helpers/imports remain unchanged. Six new finite
units bring actual collection to76; local validation runs those six plus
preservation. Formal29 portable/native89 remain unchanged; eventual portable
union105 gives no acceptance credit. No native execution, closed S4.2c rerun or
strategic gate change is included.


## Portable prepared control-receipt codec slice

The independently reviewed slice follows verified PR120 at
`eb14e00a3d602167a54ab4bcd05f123ef0846249`. Separate
`decode_recovery_prepared_receipt_record` and
`encode_recovery_prepared_receipt_record` APIs validate intrinsic
`recovery_control_prepared` claims. The closed14-field envelope and flattened
closed18-field payload use canonical ASCII JSON, complete-record2048 bytes and
depth3. Explicit expected owner/operation/graph/receipt IDs bind each record;
returned envelope and payload are fresh plain dictionaries.

The claimed issuer must be supervisor or broker after validating the full role
enum. The payload requires message_kind recovery_prepared and exact Boolean
False for database_open. Channel sequence uses0..18446744073709551615; observation
time and original deadline use0..9223372036854775807. Six SHA-256 fields require
full lowercase syntax only. All five phases and nullable physical operation
remain representable. No timestamp ordering, cross-field ID/hash equality,
freshness or phase coupling is inferred.

These checks authenticate no producer/peer, register/resolve no receipt and prove
no actual packet receive, prepared barrier, installed filter/bootstrap, unopened
database, live custody or recovery eligibility. They authorize no operation.
Actual prepared direction remains recovery_supervisor with authenticated receiving
supervisor, exact peer/context and operation_id=null in the separate channel
envelope. A broker claim or non-null physical operation passing syntax provides
no transport credit. Original bootstrap monitor/session/time, immutable manifest,
image/filter installation, exact FDs/mounts/credentials, receive-only barrier and
continuous stopped one-task custody remain external gates.

The flattened projection contains packet fields plus message_kind/channel_sequence;
future reconstruction removes only those two fields. No reconstruction, packet
codec, receive, database access, digest computation, signal or wait is implemented.
The one-prepared-message allowance, zero rights, per-direction sequence and six
aggregate control-receive slots remain external; failed receives produce no
fabricated success. All existing runtime/transport restrictions and quotas remain.

The six-file scope is pinned by `portable_recovery_prepared_codec_slice`.
Prior76 codec units and shared helpers/imports remain unchanged. Six finite units
bring actual collection to82; affected local checks run those six and preservation.
Formal29 portable/native89 remain unchanged; eventual portable union111 gives no
acceptance credit. No native execution, closed S4.2c rerun or strategic gate change
is included.


## Portable activation control-receipt codec slice

The independently reviewed slice follows verified PR121 at
`adabe58f4d5ccabc748de03b257ae2f6b13b4c9e`. Separate
`decode_recovery_activate_receipt_record` and
`encode_recovery_activate_receipt_record` APIs validate intrinsic
`recovery_control_activate` claims. The closed14-field envelope and flattened
closed17-field payload use canonical ASCII JSON, complete-record2048 bytes and
depth3. Explicit expected owner/operation/graph/receipt IDs bind each record;
returned envelope and payload are fresh plain dictionaries.

The claimed issuer must be supervisor or broker after full role validation.
message_kind is exactly recovery_activate; channel sequence uses unsigned64
range0..18446744073709551615. Observation time and original deadline use
0..9223372036854775807. Both runtime-lock digests require full lowercase SHA-256
syntax only. All five phases and nullable physical operation remain representable,
without inferred time ordering, context/reference ID equality, digest equality,
freshness or phase coupling. Reference syntax establishes no resolution.

These checks authenticate no producer/peer, register/resolve no receipt and prove
no actual activation receive, continuation, owner closure, commit witness or
persisted history, live custody or recovery eligibility. They authorize no
operation. Actual activation direction remains supervisor_recovery with receiving
recovery broker, exact inherited endpoint/peer/context and null operation in the
separate channel envelope. A supervisor claim or non-null physical operation
passing syntax earns no transport credit. Activation must be spent before
signalling; sending requires old owner closure and actual CLD_CONTINUED/SIGCONT.
There is no resend or unknown-delivery retry. Recovery validates the exact message,
original deadline and context before challenge; no SQL or grants yet.

cut_transaction_id must resolve an actual after_commit_before_ack witness, with
persisted transaction/history validation on reopen; unknown commit is not a
witness. Bootstrap monitor session, original observations, continuous pidfd
custody, immutable old/new subjects and installed-filter/FD/bootstrap proofs
remain external. No store read/open, digest, wait, signal, protocol or reference
resolution is implemented. Native wait sets and runtime restrictions remain.

The flattened projection contains packet fields plus message_kind/channel_sequence;
future reconstruction removes only these two. No reconstruction API is added.
Only actual authenticated receives produce success projections. The one-activation
allowance, zero rights, exact sequence, activation-before-challenge and
bindings-before-response ordering, and six aggregate control slots remain external.
No quota reset or stateful protocol is added.

The six-file scope is pinned by `portable_recovery_activate_codec_slice`.
Prior82 codec units and shared helpers/imports remain unchanged. Six finite units
bring actual collection to88; local validation runs those six plus preservation.
Formal29 portable/native89 remain unchanged; eventual portable union117 gives no
acceptance credit. No native execution, closed S4.2c rerun or strategic gate change
is included.


## Portable challenge control-receipt codec slice

The independently reviewed slice follows verified PR122 at
`2285f3fa677ff363d1e02c5094d5dd6651a460c1`. Separate
`decode_recovery_challenge_receipt_record` and
`encode_recovery_challenge_receipt_record` APIs validate intrinsic
`recovery_control_challenge` claims. The closed14-field envelope and flattened
closed16-field payload use canonical ASCII JSON, complete-record2048 bytes and
depth3. Explicit expected owner/operation/graph/receipt IDs bind each record;
returned envelope and payload are fresh plain dictionaries.

The claimed issuer must be supervisor or broker after full role validation.
message_kind is exactly recovery_challenge; channel sequence uses unsigned64
range0..18446744073709551615. Observation time and original deadline use
0..9223372036854775807. Both runtime-lock digests require lowercase SHA-256
syntax only. All five phases and nullable physical operation remain representable,
without inferred time ordering, ID/digest equality, freshness or phase coupling.
Reference syntax establishes no resolution or one-time consumption.

These checks authenticate no producer/peer, register/resolve no receipt and prove
no actual challenge receive, freshness/consumption, activation or closure, live
custody or recovery eligibility. They authorize no operation. Actual challenge
direction remains recovery_supervisor with receiving supervisor and the exact
live resumed recovery instance after validated activation. The separate channel
envelope requires null operation, zero rights, exact endpoint/peer/context and
per-direction sequence, and at most one challenge. A broker issuer claim passing
syntax earns no receive credit. Supervisor derives old owner and all allocated
operation scopes from its immutable live registry; no requested graph list.

Fresh challenge is consumed once, with no reconnect, retry, new deadline or
activation; custody/identity discontinuity refuses. Old durable cut/owner closure,
activation spent before signalling and actual CLD_CONTINUED/SIGCONT before
activation remain prerequisites. Challenge/response use the fresh recovery
session; historical records retain their original sessions/times and continuous
supervisor/pidfd custody. No DB/journal/sync open or SQL before complete current
live bindings and response pass.

Original ancestors delivered after challenge belong to the bounded read-only
provenance cache, never the live registry. Exact owner/operation scope, complete
closure/member/death/digest backing records and current terminal/root-copy checks
remain external. This codec performs no cache import, reference resolution,
digest, store read/open or runtime action. Original deadlines, native wait sets,
confinement, resource caps and failed-prefix preservation remain unchanged.

The flattened projection contains packet fields plus message_kind/channel_sequence;
future reconstruction removes only these two. No reconstruction API is added.
Only actual authenticated receives produce success projections. Activation-before-
challenge, challenge-before-bindings and bindings-before-response ordering,
debit-before-send, no uncertain-delivery retry and six aggregate control slots
remain external. No quota reset or stateful protocol is added.

The six-file scope is pinned by `portable_recovery_challenge_codec_slice`.
Prior88 codec units and shared helpers/imports remain unchanged. Six finite units
bring actual collection to94; local validation runs those six plus preservation.
Formal29 portable/native89 remain unchanged; eventual portable union123 gives no
acceptance credit. No native execution, closed S4.2c rerun or strategic gate change
is included.


## Portable response control-receipt codec slice

The independently reviewed slice follows verified PR123 at
`3a9781c32b7c8ffb6897cbc010dbc5850524b4fa`. Separate
`decode_recovery_response_receipt_record` and
`encode_recovery_response_receipt_record` APIs validate intrinsic
`recovery_control_response` claims. The closed14-field envelope and flattened
closed16-field payload use canonical ASCII JSON, complete-record2048 bytes and
depth3. Explicit expected owner/operation/graph/receipt IDs bind each record;
returned envelope, payload and binding_receipt_ids list are fresh plain objects.

The claimed issuer must be supervisor or broker after full role validation.
message_kind is exactly recovery_response; channel sequence uses unsigned64
range0..18446744073709551615. Observation time and original deadline use
0..9223372036854775807. Both runtime-lock digests require lowercase SHA-256
syntax only. All five phases and nullable physical operation remain representable,
without inferred time ordering, ID/digest equality, freshness or phase coupling.

binding_receipt_ids is an exact built-in list of0..3 canonical UUID4 strings,
unique and sorted ASCII. Type and cardinality precede element traversal; exact
string/UUID checks precede comparisons. No sorting, deduplication or truncation
repairs input. An empty intrinsic claim conveys no successful-response credit.
Actual success still requires exactly one owner binding and every allocated old
operation binding, set size1..3, with immutable registry membership and no omission.

These checks authenticate no producer/peer, register/resolve no receipt and prove
no actual response receive, complete binding/ancestor validation, live custody or
successful recovery eligibility. They authorize no operation. Actual response
direction remains supervisor_recovery with receiving recovery broker, original
live supervisor and exact endpoint/incarnation/context. The separate channel
envelope requires null operation, zero rights, exact credentials, per-direction
sequence and at most one response; physical role claims earn no receive credit.

All binding records must have arrived and passed validation on that same
authenticated endpoint before the response end marker. Fresh current-session
bindings require exact old owner/operation scopes and uninterrupted supervisor/
pidfd custody. Complete original closure/member/death/descriptor/digest backing
records remain in the bounded read-only provenance cache with original envelopes
and times, never imported into the live registry. Current terminal/root-copy
checks remain mandatory; parsed list membership proves none of these predicates.

Refusal uses recovery_refused instead, never partial success. Only after complete
response validation may the broker create fresh graph_closed authority references
for the owner and only nonclosed leases. Already-closed operations need no new
close_lease, and supplied evidence conveys no grant. No caller-selected authority,
imported authority ID or persisted handle becomes available. DB/journal/sync open
and bounded store/history validation remain later gates.

Old durable cut/owner closure, actual continuation before activation, validated
activation and a fresh one-time challenge remain prerequisites. There is no
retry/reconnect/new activation/deadline. Original session, operation/work/cleanup
bounds, confinement, native wait sets, finite resource caps and failed-prefix
preservation remain unchanged. No runtime action is added.

The flattened projection contains selected packet fields plus message_kind and
channel_sequence; future reconstruction removes only these two. No reconstruction
API is added. Only actual authenticated receives produce successful projections.
Activation-before-challenge, challenge-before-bindings, bindings-before-response,
debit-before-send and no uncertain-delivery retry remain external. Six aggregate
control slots remain prepared,activate,challenge,response OR refusal,and at most
two fixed failures. No quota reset or stateful protocol is added.

The six-file scope is pinned by `portable_recovery_response_codec_slice`.
Prior94 codec units and shared helpers/imports remain unchanged. Six finite units
bring actual collection to100; local validation runs those six plus preservation.
Formal29 portable/native89 remain unchanged; eventual portable union129 gives no
acceptance credit. No native execution, closed S4.2c rerun or strategic gate change
is included.


## Portable refusal control-receipt codec slice

The independently reviewed slice follows verified PR124 at
`f5bd411173729d4d7a23205ffa2dde35a53448c4`. Separate
`decode_recovery_refused_receipt_record` and
`encode_recovery_refused_receipt_record` APIs validate intrinsic
`recovery_control_refused` claims. The closed14-field envelope and flattened
closed16-field payload use canonical ASCII JSON, complete-record2048 bytes and
depth3. Explicit expected owner/operation/graph/receipt IDs bind each record;
returned envelope and payload are fresh plain dictionaries.

The claimed issuer must be supervisor or broker after full role validation.
message_kind is exactly recovery_refused. reason is one of binding_refused,
bootstrap_refused, closure_unproved, deadline, resource_limit,
unexpected_transition or authority_unavailable. This recovery_reason enum is
distinct from fixed_failure's failure_reason; protocol_refused and unexpected_exit
are not accepted here. Exact string type and bounded length precede comparisons.
Reason syntax proves no actual failure cause or valid preceding challenge.

Channel sequence uses unsigned64 range0..18446744073709551615. Observation time
and original deadline use0..9223372036854775807. Both runtime-lock digests require
lowercase SHA-256 syntax only. All five physical phases and nullable operation
remain representable, without inferred time ordering, ID/digest equality,
freshness or phase coupling. No list or nested packet is declared.

These checks authenticate no producer/peer, register/resolve no receipt and prove
no actual refusal receive, valid preceding challenge, truth of failure reason,
live custody, completed witness or recovery eligibility. They authorize no
operation. Refusal is failed evidence, not a successful recovery witness. Actual
direction remains supervisor_recovery with authenticated receiving recovery
broker, exact live original supervisor/endpoint/incarnation/context. The separate
channel envelope requires null operation, zero rights, exact peer credentials,
per-direction sequence and4096-byte packet limit; physical claims prove none.

Actual refusal is permitted only after a valid challenge, when activation and
challenge IDs are known. Before that, authenticated context permits only the
separate fixed bootstrap failure path; otherwise driver records failed context
without invented peer fields. A failed receive produces no fabricated receive
projection. Response and refusal share one mutually exclusive allowance; retain
the prefix plus refusal as failed evidence, never partial success or completion.

No retry/reconnect, new activation/deadline, quota replenishment, fresh authority,
DB/journal/sync open, recovery grant, lease close or operation follows this parser.
Preserve unknown outcomes, owned store/journal and original owner/event history.
Successful-response checks for all owner/operation bindings, bounded historical
provenance, current terminal/root-copy state and continuous supervisor/pidfd
custody remain external and unchanged. Historical envelopes/sessions/timestamps
remain original; imported records convey no live authority.

Original epoch/session/broker/operation/work/cleanup bounds, confinement, native
wait sets, resource caps and failed-prefix reservations remain unchanged. Each
state may transition once to unavailable then cleanup; supervisor death or
ambiguous activation/commit remains unavailable. No runtime action is added.

Flattened projection contains selected packet fields plus message_kind and
channel_sequence; future reconstruction removes only those two. No reconstruction
API is added. Actual authenticated receives alone produce receive projections;
a received refusal still records failure. Six aggregate slots remain prepared,
activate,challenge,response OR refusal,and at most two fixed failures.
Debit-before-send and no uncertain-delivery retry remain external; no counter,
quota reset or stateful protocol is added.

The six-file scope is pinned by `portable_recovery_refused_codec_slice`.
Prior100 codec units and shared helpers/imports remain unchanged. Six finite
units bring actual collection to106; local validation runs six plus preservation.
Formal29 portable/native89 remain unchanged; eventual portable union135 gives no
acceptance credit. No native execution, closed S4.2c rerun or strategic gate
change is included.


## Portable recovery fixed-failure receipt codec slice

The intrinsic recovery_control_fixed_failure projection uses the closed14-field
physical envelope and closed14-field scalar payload. Complete canonical ASCII is
bounded to2048 bytes/depth3. Expected owner/operation/graph/receipt IDs bind the
record after intrinsic and canonical validation; fresh plain dictionaries are
returned. No packet reconstruction, runtime protocol or live adapter is added.

message_kind is exactly fixed_failure. failure_reason is bootstrap_refused,
binding_refused, protocol_refused, deadline, resource_limit, unexpected_exit or
authority_unavailable. stage is bootstrap, ready, reserved, tls, released,
exchange or cleanup. Exact string type and bounded length precede comparisons.
The recovery_reason-only closure_unproved/unexpected_transition are rejected.
Envelope issuer must be supervisor or broker after full role validation; payload
role accepts all eleven declared roles as claims, without inferred issuer equality.

Sequence uses unsigned64 range0..18446744073709551615. Observation/session deadline
use0..9223372036854775807. Envelope and payload runtime-lock digests and payload
bootstrap-manifest digest require lowercase SHA-256 syntax only. All physical
phases and nullable operation remain representable. No cross-field ID, role,
hash, time, phase/stage equality, freshness or failure causality is inferred.

Parsing authenticates no producer/peer, registers/resolves no receipt and proves
no actual receive, authenticated bootstrap context, claimed cause/stage, live
custody, completed witness or recovery eligibility. Failure claims authorize no
operation and earn no successful-witness credit. Actual fixed_failure projections
require authenticated receives on supervisor_recovery or recovery_supervisor,
the exact receiving broker/supervisor, original/recovery instances, credentials,
endpoints and all common bootstrap fields matching the declared context.

The separate channel envelope retains sequence1..2147483647, strictly increasing
per direction/instance, no wrap/reconnect/replay, zero rights and4096-byte cap.
Operation follows the declared owner/bootstrap rule; nullable physical operation
proves no channel compliance. Missing, wrong or truncated credential/ancillary
evidence refuses; unexpected rights require cleanup without reading secret data.

Unlike recovery_refused, early fixed failure needs authenticated bootstrap context
but no valid preceding challenge or activation/challenge IDs. Without context,
driver records failed context without invented peer fields. Required payload
fields are never repaired using dummy IDs/nulls. Assumed sends, missing delivery
or failed receives produce no fabricated receive projection.

Keep failed prefixes and uncertainty, mandatory cleanup, unknown activation/commit
outcomes, owned store/journal and original owner/event history. No retry/restart,
reconnect, new activation/deadline, counter refund, fresh authority, imported live
registry entry, database/journal/sync open, recovery grant, lease close or operation
follows this parser. Fixed enums disclose no raw exceptions/private bytes or
content-derived digests. Successful-response predicates remain complete exact
owner/operation bindings, live terminal/root-copy checks, bounded historical
provenance and uninterrupted supervisor/pidfd custody. Historical envelopes,
sessions/timestamps, deadlines, native wait sets, confinement/resource caps and
failed-prefix reservations remain unchanged.

At most two recovery-channel fixed failures fit within six aggregate control
projection slots: prepared,activate,challenge,response OR refusal,and two failures.
They consume two of eight total failure slots. Debit-before-send and uncertain
delivery spending remain mandatory; no fallback handshake or response-plus-refusal
is permitted. This accounting grants no runtime stop/failure authority.

Projection contains bootstrap_contract.variants.fixed_failure's twelve fields
plus message_kind/channel_sequence. Future reconstruction removes only those two;
there is no recovery_bootstrap_contract.packet_payloads.fixed_failure entry and no
reconstruction API here. No protocol state, counters or acceptance is implemented.

The six-file scope is pinned by portable_recovery_fixed_failure_codec_slice.
Prior106 codec units and shared helpers/imports remain unchanged. Six finite units
bring actual collection to112; affected validation runs six plus preservation.
Formal29 portable/native89 remain unchanged; eventual portable union141 conveys
no acceptance credit. No native execution, closed S4.2c rerun or strategic gate
change is included.


## Portable progress-record codec slice

The general s43-progress-v1 codec validates a closed24-field flat scalar record,
canonical ASCII up to3072 bytes and container depth1. All four expected owner,
operation,graph,record IDs are non-null UUID4 strings and checked before input;
record binding follows intrinsic relations and canonical validation. Returned
records are fresh plain dictionaries. Prior codec behavior remains unchanged.

Counts are exact integers0..1 or null; bytes are0..16384 or null before narrower
directional caps. Null means unknown, never zero. sample_sequence is1..16;
observation time is0..9223372036854775807. UUID4/hash checks establish syntax only.
Booleans, floats, subclasses/hooks, duplicate/missing/extra fields and noncanonical
encoding refuse. Exact enum strings are bounded before comparisons. reason is the
seven-value bootstrap stop_reason enum or null; stage uses only prepared,reserved,
socket_transferred,tls_verified,released,pre_write,exchange,closed. ready/closure
are not wire aliases. All scalar validation precedes relation errors.

Only connector/connector_local, operation_worker/client_local and
owned_service/server_local are permitted role/perspective pairs. Connector may
know only connection_attempts. Client may know credential_reads,http_requests,
tls_handshakes and four byte counters; connection_attempts and
server_received_requests must be null. Server may know tls_handshakes,
server_received_requests and four byte counters; credential_reads,
connection_attempts,http_requests must be null. Forbidden known zero also refuses;
permitted fields may independently remain unknown, with no inferred byte/count
relationship, stage completion or reason coupling.

Known client TLS outbound/inbound caps are8192/16384. Server local directions
invert to16384/8192. Plaintext request/response caps remain512/2048 for both.
Outside base scalar bounds is invalid_value; incompatible role/perspective,
known unobservable fields and narrower-cap violations are invalid_result.

This is the general3072-byte record API. Recovery-profile progress remains limited
to1024 bytes before allocation/publication; JSONL adds one LF. Passing the codec
alone establishes no recovery-profile eligibility. Independently frozen maximum
complete examples are connector:918 bytes (recovery1024 fits), operation_worker:923 bytes (recovery1024 fits), owned_service:920 bytes (recovery1024 fits). No profile limit or schema is widened.
Future profile integration must fail closed. No JSONL/file/stream/export/digest
adapter is implemented.

Parsing authenticates no producer/peer, registry membership or freshness, actual
counter/stage truth, interval coverage, remote receipt, physical closure,
successful witness or operation/recovery authorization. Live role/instance/graph/
owner/session/clock/runtime and envelope operation still require authentication
against the immutable registry. Across samples, sequence must strictly increase
per producer and known cumulative counters cannot decrease; never sum samples or
client/server counts. Unknown cannot establish a zero negative: those require
positive current interval-covering observations and actual physical closure.
Local first-write attempts/bytes never prove remote delivery.

At most16 samples per producer and48 for three producers remain within the
64-record/65536-byte member cap, at bounded milestones rather than each loop.
Producing code maps ready to prepared and closure to closed. Phase eligibility,
original deadlines, role ownership and bounded partial/failure reports remain
external. Supervisor may forward records but cannot originate secret counters.
Missing reports and crash outcomes stay unknown; failed evidence is preserved.
Success still requires actual required progress, positive controls, matching
authority/result records and physical closure. No recovery grant, fresh authority,
retry/restart/deadline reset, store opening or native action follows parsing.

portable_progress_codec_slice binds the exact six-file amendment. Prior112 units,
helpers/imports and historical gates remain unchanged. Six finite units bring
actual collection to118; affected validation is six plus preservation. Eventual
portable union147, formal29 and native89 remain distinct. This slice grants no
formal/native acceptance credit and runs no native or closed S4.2c checks.


## Portable public-binding record codec slice

The s43-public-binding-v1 codec validates six required fields: kind,
public_manifest_sha256,record_id,related_ids,schema_version,subject_id. kind is
runtime,graph,role,input or source_manifest. UUID4 and lowercase SHA-256 checks
establish syntax only. Expected subject/record IDs are non-null canonical UUID4
strings validated before input; binding follows intrinsic/canonical checks.

related_ids is an exact built-in list of0..11 unique canonical UUID4 strings.
Empty lists and arbitrary unique permutations are valid; order is preserved.
There is no sorting, per-kind cardinality or requirement that subject/record IDs
be disjoint from the list or each other. List type and cardinality are bounded
before iteration/copy; all element types/syntax are checked before uniqueness.
Returned root and list are fresh plain objects; encoding preserves caller data.

Complete canonical ASCII is bounded to3072 bytes/depth2. Reject duplicate,
missing, unknown or wrapped fields, invalid scalars, list duplicates, subclasses/
hooks and noncanonical encoding. Structural/list type errors are invalid_shape;
invalid scalar, list cardinality or duplicate ID is invalid_value. Preparse or
canonical failures are invalid_encoding; expected-ID mismatch is wrong_subject.
Rejections expose fixed codes without raw data or parser exception chains.

The independent maximum complete example is707 bytes (11UUIDs and longest kind),
within recovery's separate1024-byte record cap. Passing this general codec alone
does not establish profile eligibility. Recovery size validation before
allocation/publication, one LF per JSONL record and bindings.jsonl limits of64
records/131072 bytes remain external. No stream/member reservation or export
behavior is implemented; no cap or existing schema is widened.

Parsing authenticates no producer/peer, resolves no manifest/input, verifies no
digest, and establishes no live registry membership, provenance/freshness,
physical custody/closure, completed witness or operation/recovery authority.
The digest must later resolve the exact separately validated public fixed input/
manifest in frozen execution context; absent/unknown context refuses. Hashes do
not substitute for physical observations. Public role/graph/runtime/input
identities never contain runtime object contents or dynamic credential digests.
This codec calculates no digests of unvalidated/private data.

Preserve original evidence, failures/uncertainty and deadlines. Imported claims
do not become live registry entries or recovery_closure_binding records.
Successful recovery still needs actual authenticated controls, exact current and
bounded historical provenance, live custody and closure/wait/SQL predicates.
No native action, grant, store opening, retry/restart or deadline reset follows
parsing. Packet/stream/reader/manifest resolution and runtime remain unimplemented.

portable_public_binding_codec_slice binds the six-file amendment. Prior118 units,
shared helpers/imports and historical gates remain unchanged. Six finite units
bring actual collection to124; affected validation runs six plus preservation.
Eventual portable union153, formal29 and native89 remain distinct, with no formal
or native acceptance credit and no native or closed S4.2c execution.


### Intrinsic lookup-observation codec slice

This append-only portable slice follows the independently approved
lookup-observation scope and verified PR128 merge/main CI. It implements only
decode_lookup_observed_record and encode_lookup_observed_record: the closed
14-field s43-lookup-observed-v1 public record, with expected owner, operation
and record UUIDs checked before input and matched after full intrinsic/canonical
validation. Prior 124 codec units, imports and shared helpers remain unchanged.

All scalar types, canonical UUID4/hash syntax and monotonic integer bounds are
validated before relationships. Closed status requires lease/closure references;
completion/result references are both null or both nonnull, and a nonnull
result_operation_id equals this operation. Other statuses (not_closed,
absent, unavailable) require all four references null. These checks do not
establish completed lease state, actual lookup truth or reference resolution.
No other UUID equality, distinctness or temporal relation is inferred.

The flat canonical ASCII object has depth 1 and a general 3072-byte cap.
Recovery retains its separate 2048-byte lookup cap before allocation/publication;
JSONL adds one LF. Independent fixtures freeze five status/completion examples
and their maximum timestamp variants: closed without completion 679 bytes, closed with completion 747 bytes, not_closed without completion 615 bytes, absent without completion 611 bytes, unavailable without completion 616 bytes.
The maximum fits 2048; parsing alone does not establish profile eligibility.
transactions.jsonl still shares 64 records/131072 bytes with transaction
witnesses. The selected recovery profile shares 50 records, with two read-only
lookup attempts. This slice implements no member accounting or stream adapter.

Only a live broker after an actual authorized lookup may emit this record.
Issuer/session/epoch/runtime bindings, producer/broker/peer authentication,
provenance/freshness, history uniqueness and exact exported/persisted
lease/event/result crosslinks remain external. Forwarding through the existing
broker_supervisor public_evidence_record retains producer provenance.
Parsed/imported claims establish no physical custody/closure, completed witness
or operation/recovery authority. They create no audit event, mutation, registry
entry, permission, restored authority, retry/restart or deadline reset. Original
failure evidence, uncertainty and deadlines remain preserved; current/bounded
historical provenance, live custody and closure/wait/SQL predicates still apply.
No SQL, live lookup, fixture/file read, runtime/native action, packet/digest/export
API, manifest resolution or authentication is implemented.

Six finite units cover independent golden bytes, all 64 status/reference patterns,
same-operation result linkage, scalar/boundary/type/canonical failures, expected
ID precedence, fresh copies and error hygiene. Collect exactly 130 codec unit
IDs and run only the six new units plus the affected source-preservation check.
Actual 130 units and eventual portable union 159 remain distinct from the unchanged
29 formal portable and 89 native nodes. This slice earns no acceptance credit
and authorizes no native execution or closed S4.2c checks.


### Intrinsic transaction-result codec slice

This append-only portable slice follows the independently approved transaction-
result scope and verified PR129 merge/main CI. It implements only
decode_transaction_result and encode_transaction_result: the closed eight-field
s43-txn-result-v1 record with an expected nonnull call UUID checked before input
and matched after full intrinsic/canonical validation. Prior 130 units, imports
and shared helpers remain unchanged. This is the smaller prerequisite for the
future transaction-witness envelope; no witness or lookup-result wrapper is added.

Scalars and nullable UUID/sequence values are checked before relationships.
Committed requires null reason and nonnull transaction ID/sequence; operation
and lease IDs are both null or both nonnull, following the existing event-scope
rule. Actual scope selection and same-lease/event resolution remain external.
Noncommitted replies have null transaction/sequence/operation/lease fields.
Uncertain permits only commit_unknown; unavailable permits audit_unavailable,
store_unavailable or cleanup_unconfirmed; refused permits invalid_input,
stale_authority, wrong_state, expired, budget_exhausted or scope_refused.
No UUID equality/distinctness, sequence progression or freshness is inferred.

The flat canonical ASCII object has its own 1024-byte cap and depth 1.
Independent golden examples cover both committed scopes and all ten failure
reasons. Maximum complete fixture sizes: committed/engagement 247 bytes, committed/lease 315 bytes, refused/invalid_input 216 bytes, refused/stale_authority 218 bytes, refused/wrong_state 214 bytes, refused/expired 210 bytes, refused/budget_exhausted 219 bytes, refused/scope_refused 216 bytes, unavailable/audit_unavailable 224 bytes, unavailable/store_unavailable 224 bytes, unavailable/cleanup_unconfirmed 226 bytes, uncertain/commit_unknown 219 bytes.
The future witness must account for the entire envelope within its separate
general public cap and recovery 2048-byte cap; JSONL adds one LF. The shared
transactions.jsonl limit remains 64 records/131072 bytes; selected recovery
shares 50 records including two lookup attempts. No stream/member accounting
or transaction attempt is implemented.

Parsing proves no actual transaction, commit/rollback, authenticated broker or
trusted-call origin, persisted sequence/event resolution, event scope,
provenance/freshness, physical custody/closure, completed witness or operation/
recovery authority. A committed receipt is not a capability. Only the original
live broker may deliver the separate one-use setup/release signal after renewed
deadline/cancellation checks. Imported claims create no audit event, mutation,
registry entry, permission, signal, restored authority, retry/restart or deadline
reset. No SQL, actual lookup/transaction, file/fixture read, transport, runtime/
native action, manifest resolution, packet/digest/export API or authentication
is implemented.

State mutation and required audit insertion remain one durable transaction;
audit failure aborts mutation. Missing/unknown COMMIT acknowledgment stops live
delivery and leaves authority unavailable pending bounded reconciliation; it
never proves rollback. Store failure cannot manufacture a committed event;
closed non-secret failures are preserved outside that transaction. Refused
requests append no event or mutation. Missing acknowledgment, uncertain commit
and read-only receipt recovery authorize no mutation retry. Cleanup/recovery
never revalidates a dead lease as executable. Original evidence, uncertainty,
deadlines, live controls and closure/SQL predicates remain mandatory.

Six finite units cover independent golden bytes, all 704 status/reason/presence
combinations, scalar/canonical/type/boundary failures, expected-call precedence,
fresh copies and error hygiene. Sequence -0 is invalid_value because zero is
out of range before canonical comparison. Collect exactly 136 unit IDs and run
only the six new units plus the affected preservation check. Actual 136 and
eventual portable union 165 remain distinct from unchanged 29 formal portable
and 89 native nodes. No acceptance credit, native execution or closed S4.2c
checks are authorized.


### Intrinsic transaction-witness record codec slice

This append-only portable slice follows the independently approved witness scope
and verified PR130 merge/main CI. It adds decode_transaction_witness_record and
encode_transaction_witness_record for the closed nine-field
s43-transaction-witness-v1 record. Expected writer/call/record UUIDs are checked
before input and matched only after full intrinsic/canonical validation.
Prior 136 units, imports, APIs and shared helpers remain unchanged.

Outer scalars are checked before the event list, then the optional nested result
and its same-call relationship. event_ids is an exact built-in list of zero to
two unique canonical UUID4s; length is bounded before iteration, every scalar is
validated before uniqueness, and order is preserved. IDs need not be disjoint
from other fields. A nonnull result reuses the unchanged eight-field intrinsic
transaction-result validator and its separate 1024-byte canonical cap; its
call_id must match the outer call_id. Root/list/nested dictionaries are copied
fresh, and encoding does not mutate caller data.

General records are canonical ASCII with sorted object keys, at most 3072 bytes
and depth 2. Recovery retains its separate 2048-byte complete witness cap before
allocation/publication; JSONL adds one LF. Independent golden examples include
null and every valid nested status/reason/committed scope. Maximum complete
fixture sizes: null 402 bytes, committed/engagement 645 bytes, committed/lease 713 bytes, refused/invalid_input 614 bytes, refused/stale_authority 616 bytes, refused/wrong_state 612 bytes, refused/expired 608 bytes, refused/budget_exhausted 617 bytes, refused/scope_refused 614 bytes, unavailable/audit_unavailable 622 bytes, unavailable/store_unavailable 622 bytes, unavailable/cleanup_unconfirmed 624 bytes, uncertain/commit_unknown 617 bytes. The largest nested result is 315 bytes,
within its unchanged 1024 cap. The maximum complete witness fits 2048, but general
parsing alone does not establish recovery-profile eligibility.

The approved intrinsic boundary intentionally adds no undeclared barrier/result
table, method-specific event count or subject scope, terminal-result requirement,
or empty-event-list rule for null/noncommitted results. These combinations are
accepted only as closed syntax. A null result claims that no result exists yet;
actual availability at a reached boundary remains external. Uncertain COMMIT
does not prove rollback. Codec success proves no legal transaction, committed
event or successful witness.

Actual reached SQL boundaries, result availability, contender ordering, same-call
persisted-event resolution, method/event correspondence, refused calls producing
no mutation/event, no manufactured committed IDs and mutually exclusive terminal
outcomes remain mandatory external gates. Ordinal claims observed ordering, not
wall-clock atomicity. Authentication/trusted writer/call origin, provenance/
freshness, physical custody/closure, completed witness and operation/recovery
authority are not established. Imported records create no audit event, mutation,
registry entry, permission, signal, restored authority, retry/restart or deadline
reset. No SQL/hooks/lookup/transaction, file/fixture read, runtime/native action,
stream/packet/digest/export API, registry or manifest resolution is implemented.

transactions.jsonl still shares 64 records/131072 bytes with lookup records;
selected recovery shares 50 records including two lookup attempts. Twelve mutation
attempts each emit at most four actually reached barriers: call_entered,
before_begin, before_commit and exactly one after_commit_before_ack/refused/
unknown_commit. Additional barrier enum values remain syntactically valid without
earning selected-profile eligibility. No schedule or capacity reservation is
implemented. Mutation/audit remain one durable transaction; audit failure aborts
mutation. Missing COMMIT acknowledgment stops live delivery and requires bounded
reconciliation, never proves rollback and authorizes no mutation retry. Store
failure cannot manufacture committed audit events. Recovery cut_transaction_id
must resolve an actual after_commit_before_ack witness plus persisted history;
unknown commit cannot satisfy that gate. Original evidence, uncertainty, deadlines,
authenticated controls, live custody and closure/wait/SQL predicates remain.

Six finite units cover all method/barrier combinations, nested-result cases and
704 intrinsic nested relationships, list order/fresh copies, type/scalar/canonical/
depth/size failures and expected-ID/error precedence. Collect exactly 142 IDs and
run only the new six units plus the affected preservation check. Actual 142 and
eventual portable union 171 remain distinct from unchanged 29 formal portable
and 89 native nodes. This slice earns no acceptance credit and authorizes no
native execution or closed S4.2c checks.


### Reviewed portable case-context codec slice

This slice adds intrinsic parsing and encoding of the closed twelve-field
`s43-case-context-v1` record. The APIs require expected case and bundle UUID4
identities, checked in argument order before input and matched after complete
intrinsic and canonical validation. Matching caller-supplied IDs does not
authenticate them. No previous codec helper or import changes.

All fields are nonnull exact strings. UUID4 and SHA256 values retain their existing
validators. Closed statuses preserve `observed`, `refused`, `failed` and
`interrupted_unknown`; fixtures are `allowed`, `invalid`, `restricted`, and review
views are `terminal`, `graphical`. Parent/variant/node values must individually
belong to their frozen inventory enums, then match an exact inventoried triple.
The literal table preserves 90 triples, including 80 canonical parent mappings
and 10 authority mappings, with 89 unique native nodes. The shared terminal node
retains both `S4-K01` and `S4-A01`; portable-only V02/V03/V04 gain no native rows.
Runtime parsing reads no inventory or fixture files.

The general record cap stays 3072 bytes, with depth 1 for this flat grammar.
The 4096-byte `context.json` singleton member cap remains separate and unchanged.
The independently derived largest complete canonical record is
702 bytes, using the longest valid mapping and metadata
literals. Node strings are ASCII at most 256 bytes; variants and parents are
ASCII at most 64 bytes and must match the exact finite inventory values.

Root shape and bounded key checks precede scalar validation and the mapping
relationship. Unknown scalar members yield `invalid_value`; individually valid
members forming an uninventoried triple yield `invalid_result`. Duplicate keys,
including escaped-equivalent duplicates, retain `invalid_shape`. Byte/depth and
noncanonical failures retain `invalid_encoding`; floats/constants retain
`invalid_value`. Decoders reject nested wrappers before parsing at depth 1;
encoders reject wrong root shapes directly. Returned dictionaries are fresh and
caller input is unchanged. Rejections expose bounded codes without raw input.

The codec validates declared claims and the explicit plan mapping. Actual native
execution, fixture/review-view/status correspondence, public-only manifest hashes,
metadata freshness, code/runtime/graph identity, bundle membership, custody and
closure, and completed-witness acceptance remain mandatory external gates. No
additional fixture/view/status relationship is guessed from a variant name.
Parsing preserves failed/interrupted claims and grants no signal, retry, deadline
reset, authority or acceptance credit.

The approved scope changes exactly six existing files: append-only contract and
codec, six new finite unit nodes, this note, one inventory slice entry plus its
contract hash, and five literal preservation hashes. Prior 142 codec nodes and
helpers remain unchanged. Collect exactly 148 codec node IDs and run only the six
new units plus the affected preservation check locally. The eventual portable
union is 177 (148 codec plus 29 formal nodes); formal 29 and native 89 remain
unchanged and no formal acceptance node is implemented here. Independent review,
complete PR/main CI and current-main compatibility remain publication gates.


### Reviewed portable reader-receipt codec slice

This slice adds intrinsic parsing and encoding for the closed nine-field
`s43-inspection-v1` receipt. The required expected bundle argument is either a
canonical UUID4 or null. Null requires an exact null bundle match; it is never
a wildcard. Validate that argument before input, then compare the declared bundle
only after complete intrinsic and canonical checks. Caller-supplied equality
does not authenticate a bundle or establish trusted case association.

`valid` requires nonnull bundle UUID and manifest SHA256 identities and the
literal reason `none`. `invalid` and `unavailable` require both identities null
and a non-`none` reason. Mixed pairs and contradictory combinations are rejected.
Every scalar is validated before these relationships. Both `python` and `cli`
use the same table; no further status/reason classification is inferred.
Reader code SHA256 remains nonnull; malformed UUIDs/hashes and scalar subclasses
are refused. Declared member and record counts are exact integers in 0..9 and
0..1530, excluding bool/float. No count or identity is synthesized from status.

The complete canonical receipt cap is 3072 bytes, with depth 1. Independent
literal goldens cover all 23 status/reason/identity patterns and both reader kinds
are exercised. Complete maximum sizes with counts 9/1530 are:
valid/none 355 bytes, invalid/schema 263 bytes, invalid/identity 265 bytes, invalid/ordering 265 bytes, invalid/custody 264 bytes, invalid/budget 263 bytes, invalid/unsafe_path 268 bytes, invalid/changed_member 271 bytes, invalid/oversize 265 bytes, invalid/missing_member 271 bytes, invalid/unknown_member 271 bytes, invalid/unavailable_context 276 bytes, unavailable/schema 267 bytes, unavailable/identity 269 bytes, unavailable/ordering 269 bytes, unavailable/custody 268 bytes, unavailable/budget 267 bytes, unavailable/unsafe_path 272 bytes, unavailable/changed_member 275 bytes, unavailable/oversize 269 bytes, unavailable/missing_member 275 bytes, unavailable/unknown_member 275 bytes, unavailable/unavailable_context 280 bytes.
The receipt stays outside the immutable bundle; the eight payload members plus
manifest, aggregate and per-member limits remain unchanged.

Root shape and bounded key checks precede scalar and relationship validation.
Duplicate and escaped-equivalent keys retain `invalid_shape`; byte/depth,
malformed JSON and noncanonical encodings retain `invalid_encoding`.
Floats/constants retain `invalid_value`; count `-0` parses as intrinsic zero but
is rejected as noncanonical. Decoders reject nested wrappers before parsing at
depth 1; encoder root/scalar shape errors remain distinct. Both APIs return or
encode fresh validated data without changing caller input or echoing raw errors.

These are declared inspection claims. Actual validated counts, zero before
validation, complete membership, immutable original Python/CLI pairing, public
reader-code identity and metadata provenance/freshness, owned/stable files and
paths, 2000ms/4MiB reader limits, typed crosslinks, ordering, progress, physical
closure and recovery/witness predicates remain mandatory external gates. Parsed
valid claims with zero or partial counts confer no valid-bundle credit. Original
failed receipts remain retained and replay uses copies only. A closed trusted
harness must establish case association; rejected input data or filenames cannot
supply it. The codec performs no bundle file reads or hashing and grants no live
authority, signal, retry, deadline reset or acceptance credit.

Exactly six existing files change: append-only constants and codec, six new
finite units, this note, one inventory entry plus contract hash, and five literal
preservation hashes. Prior 148 codec nodes/helpers/imports remain unchanged.
Collect exactly 154 codec node IDs and run only the six new units plus affected
preservation check locally. The eventual portable union is 183 (154 codec plus
29 formal nodes); formal 29 remain unimplemented and native 89 unchanged.
Independent source review, complete PR/main CI and current-main compatibility
remain publication gates. No actual reader, CLI or native execution is added.


## Portable intrinsic public-manifest grammar codec

This six-file slice implements only encode_public_manifest_record and
decode_public_manifest_record. Both require a nonnull canonical expected bundle
UUID4 before examining input, compare it after intrinsic/canonical validation,
and convey caller-supplied equality rather than trusted origin.

The closed five-field manifest contains eight closed entries, exactly once in
ASCII name order: authority.jsonl, bindings.jsonl, context.json,
observations.jsonl, physical.jsonl, progress.jsonl, result.json,
transactions.jsonl. Exact built-in containers/scalars are required; nonnegative
integer claims obey the unchanged per-name byte/record maxima and total_bytes
0..4194304. No sorting, normalization, implicit positivity or fabricated relation
is performed. A successful decode returns fresh root/list/entry containers.

The finite canonical grammar maximum is 1251 bytes at depth 3:
147 root-prefix bytes + entry sizes (131,129,124,133,132,128,123,133)
+ 7 commas + 64 suffix bytes. This parser bound is derived from the existing
closed schema; it does not introduce a general manifest member policy or replace
the selected recovery manifest reservation of 4096 bytes. Independent literal
minimum and maximum fixtures are frozen in tests. A maximum grammar claim may
not describe a feasible aggregate bundle.

Root/entry closed shape and wrong container types yield invalid_shape.
Scalar/range, list cardinality and ordered member-name constraints yield
invalid_value. Duplicate/escaped duplicate keys retain invalid_shape; malformed,
oversize, excessive depth or noncanonical frames yield invalid_encoding.
Floats/constants remain invalid_value; noncanonical integer -0 yields
invalid_encoding. Root scalar checks precede member shape/scalars, all entry
validation precedes the ordered-name relation, and intrinsic/canonical validity
precedes wrong_subject. No new invalid_result relationship is introduced.

This codec proves no actual files, byte/record counts, hashes, aggregate
accounting, digest links, provenance, inspection, valid bundle or completed
witness. Two design prerequisites remain unresolved: the exact total_bytes
equality formula (eight payload files versus all nine serialized files), and
whether root context_sha256 equals the context.json digest together with its
precisely defined digest input. This slice treats them as separately bounded
claims. Actual exporter/reader and bundle-consistency implementation remains
blocked until those semantics receive explicit clarification and review.

Existing all-nine-file accounting, independent aggregate caps, total 4MiB and
2000ms reader limits, recovery reservations/profile allocations, public-only
validated-byte digests, manifest self-hash exclusion, exact owned regular
single-link/stable files, typed crosslinks, physical/progress/recovery and
acceptance predicates remain mandatory external gates. Grammar parsing grants
no live authority, signal, retry or deadline reset. No native execution or
formal acceptance credit is claimed.

Six new finite codec units extend the actual codec union from 154 to 160.
All prior 154 nodes/helpers/imports remain unchanged. Formal 29 portable nodes
remain unimplemented; eventual portable union is 189, with native 89 unchanged.
Affected validation collects exactly 160 IDs and runs six new units plus the
source-preservation check. Full PR/main workflow checks and independent review
remain publication gates.


## Manifest accounting and context digest — design clarification

This independently reviewed design-only amendment resolves the two definitions
left open in the historical intrinsic-manifest codec note above. It specifies
future consistency obligations; it does not implement them or change any
intrinsic codec, schema, acceptance status, native prerequisite or reservation.
The historical PR134 note and its implementation inventory remain unchanged.

### Payload total and complete-bundle accounting

For each of the eight fixed payload files, let B_i be its exact validated
serialized bytes. Define P = sum(len(B_i)). Require both:

- manifest.total_bytes = P = sum of the eight member-entry bytes claims;
- each member-entry bytes claim equals that file's actual validated byte length.

Let M be the final canonical manifest.json bytes containing that payload total.
Independently require A = P + len(M) <= 4,194,304. This accounts for all nine
files. The total_bytes field excludes manifest.json; the complete-bundle budget
includes it. Agreement among untrusted totals/member claims is insufficient.
Claims can justify early refusal but cannot authorize reads, allocation or
acceptance without the existing per-member, stable-file and provenance checks.

Count exact serialized bytes, not characters, filesystem allocation, normalized
input or external receipts/debug files. Every JSONL record's required LF counts.
Singleton context.json, result.json and manifest.json are exact canonical ASCII
JSON object bytes without BOM, leading/trailing whitespace or a trailing LF.
Manifest remains the ninth file and is not a payload entry or self-hash.

The payload-only field avoids self-inclusive length equations. No fixed-point
solver, placeholder total, padding, rounding or truncation is introduced.
For comparison only, self-inclusive arithmetic can have two fixed points:
K = 9995 permits both 9999 and 10000 when the serialized total's decimal width
is added. That alternative was not selected.

All existing per-member byte/record caps, independently enforced aggregate
requirements, owned regular single-link/stable files, descriptor/directory
checks and the 2000ms reader budget remain mandatory. Preserve the selected
recovery manifest reservation of 4096 bytes and total reservation of 2909552
bytes, with the existing per-file/profile allocations and reserved failure
space. Exact emitted sizes and the intrinsic 1251-byte/depth3 grammar maximum
do not replace or reduce reservations.

The member-byte ceilings sum to 4,133,888. Adding the grammar maximum yields
an upper bound of 4,135,139, which is 59,165 below 4 MiB. This bound does not
waive the independent aggregate check. Exact 4 MiB boundary examples below are
isolated arithmetic predicates, not bundles satisfying all current member caps.

### Context-file digest and upstream identities

Require this three-way equality:

manifest.context_sha256 = the unique context.json entry's sha256
= SHA256(exact validated canonical context.json bytes).hexdigest().

The digest has no prefix, domain tag, extra LF, zero-byte suffix, normalization,
digest-of-digest substitution or upstream-manifest substitution. For emission,
validate the closed public context record and its required identity/provenance
bindings, serialize it canonically once, and hash exactly the emitted bytes.
For inspection, observed context bytes must already equal their validated
canonical representation. Reject noncanonical input rather than normalizing it
into an accepted identity. No rejected/raw private input is hashed to populate
a successful identity or a failed inspection's null identity fields.

The context record's code_manifest_sha256 and runtime_lock_sha256 retain their
existing separately validated fixed source/runtime identities.
graph_manifest_sha256 retains its existing separately validated graph-manifest
identity and provenance. None is reinterpreted as the current evidence
manifest or as context.json's own digest. The outer manifest's context_sha256
is a distinct digest of the validated public context file. Dynamic credential
object bytes, request Authorization values and reflective data remain excluded
from either digest path.

The closed context schema has no current evidence-manifest digest field.
public_binding_record.public_manifest_sha256 still resolves a separate frozen,
validated public input; it is not repurposed as the current evidence manifest.
Reader receipts containing the evidence-manifest digest remain outside the
bundle. These schema distinctions avoid introducing a back-reference; they do
not establish actual upstream provenance. Trusted expected case/bundle/node/
variant association and resolved upstream inputs remain independent gates;
rejected manifest data and filenames never supply trusted expectations.

### Isolated design examples and remaining work

The following arithmetic examples use hypothetical size claims within each
existing member-byte ceiling. They do not assert valid records, complete files,
provenance or native bundles.

| Example | Payload P | Manifest length | All-nine A |
|---|---:|---:|---:|
| Eight payload-size claims of 1000 bytes | 8000 | 1227 | 9227 |
| Only physical payload-size claim is 9999 | 9999 | 1206 | 11205 |
| Only physical payload-size claim is 10000 | 10000 | 1208 | 11208 |
| Every member byte/record claim at its ceiling | 4133888 | 1251 | 4135139 |

The decimal transition changes M's length but never changes the definition
total_bytes = P. A total claim of 8001 with entry sum 8000 refuses. If false
entry claims sum to 7999 and total_bytes also says 7999, agreement still cannot
override actual payload lengths summing to 8000.

For the aggregate predicate alone, 4193053 + 1251 = 4194304 passes that one
inequality and 4193054 + 1251 = 4194305 fails it. Both payload scalars exceed
the sum of current member caps: neither is an attainable bundle satisfying
those caps, and neither receives acceptance credit.

The first existing CCX_GOLDENS context fixture is 609 canonical bytes with SHA256
1c545ff21379ab29eff1ed48fa4ad3e57083f851347aae904936d7893edbad79.
Equal outer/member digest claims that differ from that actual validated-byte
digest refuse. An added LF or leading space is rejected before hashing, not
normalized. Even a correct context-file digest cannot resolve absent or
mismatched upstream identities/provenance; those independently require refusal.

These examples are definitions for future consistency checks, not new test-node
reservations or executed acceptance tests. Reader reason/status mappings,
invalid/unavailable receipt null identities and failed-inspection retention
remain unchanged. A separately reviewed implementation scope and all existing
publication, execution and acceptance gates are still required before any
exporter, reader, bundle-consistency implementation or native work. Existing
160 codec units, formal 29, eventual portable union 189 and native 89 are unchanged.

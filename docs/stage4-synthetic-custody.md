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

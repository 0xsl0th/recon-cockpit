# S4.2a — offline engagement record preparation

Stage4 S4.1 was accepted by PR100 at `7a7eace9c30d315f9555f179f64b98f25633a219`
(tree `ea4bc9b9ced9b90bddaf63e997b9edc7453b77ed`). This contract selects the
already permitted S4.2 preparation/integration split. The Stage4 forecast is now
5–6 PRs within its original 4–6 range; S4.3 retains its optional split. The professional forecast narrows from47–65
to48–65 PRs and the broad forecast from87–135 to88–135; the original2026-10-20
baselines remain historical estimates, with no added outcome. This PR
contains the contract **and its implementation after the contract is pinned**.
The historical S4.1 contract/inventory remain byte-for-byte unchanged.

S4.2a adds strict nonsecret engagement records, immutable ROE revisions,
transactional revision/revocation metadata, and canonical export/inspection.
It creates no session, approval, grant, reservation, provider call, credential
lease, native process or network access. A stored record, its UUID, digest,
generation and export are data; none is an execution capability. `recorded`
means administrative metadata exists, not that execution is authorized.
S4.2b must separately bind the actual prerequisite/action chain, windows,
persistent allowances, fresh authority and revocation-versus-dispatch ordering.
Credential/native/real-use obligations remain open.

## Data contract and limits

All JSON objects have exactly their named fields. Types are exact: booleans do
not satisfy integers; strings cannot substitute numbers. Reject duplicate keys,
invalid UTF-8, nonfinite/floating numbers, excessive nesting, unknown fields,
noncanonical UUIDs and trailing JSON. APIs return detached JSON values.
Canonical bytes are ASCII JSON with sorted keys, compact separators,
`ensure_ascii=True`, `allow_nan=False`, and no newline. A CLI may append one
newline to its bounded report; exported files contain canonical bytes only.
Maximum decoded nesting is 12. UUIDs are lowercase canonical RFC4122 version4
strings. Digests are lowercase 64-character SHA256 hex.

| Bound | Inclusive maximum |
| --- | ---: |
| ROE canonical bytes / ROE input file | 4,096 |
| normalized mutation request / external JSON command input | 8,192 |
| immutable revisions | 64 |
| events | 65 (create, at most63 revisions, at most1 terminal revoke) |
| SQLite database | 2,097,152 bytes, 512 pages of4,096 |
| rollback journal | 4,194,304 bytes |
| canonical export / export input file | 524,288 bytes |
| individual CLI report / error | 4,096 bytes |
| SQLite lock wait | 250ms per statement, within original operation budget |
| one API operation's lock/SQLite/validation work | 2,000ms original monotonic budget |
| SQLite progress callbacks | 2,000, each after1,000 VM instructions |

The operation clock starts before acquiring the store lock; no phase resets it.
Use timed lock acquisition, bounded queries, a progress handler and post-work
checks. Check the original deadline immediately before and after commit. If
commit may have succeeded but the postcommit check or acknowledgment fails,
return an uncertain failure and require explicit reopen/receipt lookup; never
automatically retry with a new event ID. These bound application work, not uninterruptible filesystem/kernel
calls or a malicious host. Expired work cannot return success. Emergency
rollback/descriptor closure remains necessary after the work deadline.

An ROE object has exactly:

```json
{"schema_version":"1","mode":"disconnected_owned","scope":{"schema_version":"1","scope_id":"owned-example","http":{"target":"10.77.0.10","port":8080,"path":"/"},"ssh":{"target":"10.77.0.20","port":2222}},"allowed_profiles":["configurable_http_headers_v1","configurable_nmap_service_v1","configurable_ssh_host_keys_v1"],"excluded_services":[],"window":{"start_utc":"2026-10-20T00:00:00Z","end_utc":"2026-10-21T00:00:00Z"},"limits":{"max_actions":64,"max_connections":256,"max_request_bytes":1048576,"max_response_bytes":1048576,"max_action_ms":60000,"max_engagement_ms":86400000}}
```

`scope` uses unchanged `configurable_scope.validate_scope` **only**: exactly one
literal private IPv4 HTTP endpoint/path and one SSH endpoint, distinct endpoint
pairs, ports1024–65534, its existing strict path and scope-ID grammar. Do not call
`load_scope` or import `models`, adapters or native modules. These are declared
owned fixtures in a disconnected environment; RFC1918 syntax is not ownership
proof or authorization to contact an attached network.

`allowed_profiles` is a nonempty, sorted, duplicate-free subset of the three
literal profile IDs above. No registry expansion occurs. `excluded_services` is
a sorted duplicate-free subset of `http,ssh`, with at most one entry. An exclusion
removes that entire declared endpoint from the scope and overrides profile
membership. At least one endpoint remains. No arbitrary CIDR, name, URL,
credential, free-form note, shell or extension map is accepted. S4.2a does not
claim that every such declaration is a dispatch-ready workflow; S4.2b must check
its actual Nmap prerequisites and selected service against these fields.

Window strings are exactly `YYYY-MM-DDTHH:MM:SSZ`, valid Gregorian UTC dates in
2000–2099, with no fraction/offset/leap-second alternative. Start is inclusive,
end exclusive; `0 < end-start <= 86400` seconds. Preparation may record past or
future windows and performs no clock-based execution authorization. No
monotonic timestamp is serialized. Later runtime conversion is separately pinned.
All six limits are positive integers. Maxima are respectively64,256,1048576,
1048576,60000,86400000; `max_action_ms <= max_engagement_ms <= window_seconds*1000`.
These are declarations, not consumed counters or evidence of enforcement.

ROE digest is SHA256 of `b"recon-engagement-roe-v1\x00" + canonical(roe)` where
`\x00` denotes a single zero byte. All input is explicitly operator-declared
nonsecret metadata. Grammar cannot detect credentials disguised as a scope ID;
there is no secret-discovery/redaction guarantee or legacy automatic import.

## Requests, state and exact retry

A normalized request has exactly `schema_version, engagement_id, event_id,
operation, expected_revision, expected_generation, roe`. Version is `"1"`;
engagement/event IDs are UUID4. `operation` is `create`, `revise` or `revoke`.
Create has null expected values and a validated ROE. Revise has integer expected
revision1–64/generation0–64 and a validated ROE. Revoke has those same expected
types and `roe:null`; no free-form reason. Request digest is SHA256 of
`b"recon-engagement-request-v1\x00" + canonical(request)`.

A receipt has exactly `schema_version, engagement_id, event_id, sequence,
operation, expected_revision, expected_generation, revision, generation, status,
roe_sha256, request_sha256`. State has exactly `revision,generation,status,
last_sequence`. Status is `recorded` or `revoked`. There are no wall-clock event
timestamps: contiguous sequence establishes committed metadata order.

| Transition | Preconditions inside the transaction | Committed result |
| --- | --- | --- |
| create | new directory/store only | revision1, generation0, recorded, sequence1 |
| revise | exact expected revision and generation; recorded; revision<64 | revision+1, generation+1, sequence+1; new immutable ROE |
| revoke | exact expected revision and generation; recorded | same revision, generation+1, sequence+1, terminal revoked |
| exact event retry | existing event ID and identical normalized request digest and reconstructed request | original immutable receipt, no new event or state change |

Idempotency is checked before terminal/CAS rejection, so an exact retry can
recover its original receipt after a later revision or revoke. The receipt is
historical, not a claim about current state. The expected values are part of the
request; changing them under the same event ID conflicts. A different event ID
against a revoked record refuses, even if it also asks to revoke. No reactivation,
reset, deletion, import or restore API exists. A new engagement requires a new
directory and UUID. Repeating `create` against an existing directory refuses;
after a lost create acknowledgment, explicitly open it and retrieve its event
receipt. An exact no-content-change revision is still a new numbered revision
when requested with a fresh event ID and current CAS values.

Both CAS predicates, terminal state, capacity checks, new revision, state and
event commit occur within one `BEGIN IMMEDIATE` transaction. Exactly one of
concurrent distinct updates with the same expectations wins. Concurrent exact
event retries commit once and return the same receipt. Revision-versus-revoke
races are metadata ordering only, not dispatch/release races. Never convert a
commit error/lost acknowledgment into an automatic retry with a fresh event ID.

## SQLite and file custody

Use a separate store and schema, never the provider CostLedger as authority.
The implementation pins its exact DDL as a constant and verifies the full
`sqlite_schema` object inventory/SQL, including implicit indexes and triggers.
There are exactly three application tables:

* `metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1), engagement_id TEXT
  NOT NULL, current_revision INTEGER NOT NULL, generation INTEGER NOT NULL,
  status TEXT NOT NULL, last_sequence INTEGER NOT NULL)`;
* `revisions(revision INTEGER PRIMARY KEY, roe_json TEXT NOT NULL,
  roe_sha256 TEXT NOT NULL)`;
* `events(sequence INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE,
  request_sha256 TEXT NOT NULL, receipt_json TEXT NOT NULL)`.

Add fixed CHECK constraints for exact integer/range/status/string-length bounds
and a metadata current-revision foreign key to revisions. Four fixed triggers
reject UPDATE/DELETE on revisions/events. No views, virtual tables, extra
indexes/triggers or `sqlite_sequence` table are allowed. The adjacent machine inventory pins the exact SQL statements and implicit
index inventory; implementation constants must match them. No schema expansion.
`PRAGMA user_version=1`; no implicit migrations. On open and each transaction,
bounded validation checks schema, integrity/foreign keys, all row bounds,
canonical ROEs/digests, contiguous revisions/events, full reconstructed request
hashes, transition history and current metadata equality. A coherent malicious
host rewrite is outside the trust model; no signature/rollback-protection claim.

Use SQLite URI `mode=rw` or `mode=ro` with URI escaping, never create-on-open;
no `immutable=1` on live stores. Pin page_size4096/max_page_count512, DELETE
journaling, synchronousEXTRA, fullfsyncON, foreign_keysON, trusted_schemaOFF,
temp_storeMEMORY, busy_timeout250 and read-only query_onlyON. Verify applicable
PRAGMAs. SQLite accepts only implementation-controlled SQL. Set bounded SQLite
limits including LENGTH524288, SQL_LENGTH16384, COLUMN32, EXPR_DEPTH32,
ATTACHED0, VARIABLE_NUMBER64 and TRIGGER_DEPTH8. No extension loading, ATTACH,
user SQL, external plugins or SQL executed from export contents. Full DB
validation must share the original progress/time bound, including quick_check.

Create a new child directory0700 under an existing operator-owned private0700
parent. Resolve the parent once to canonicalize trusted platform aliases such
as macOS `/tmp`; hold/verify its directory FD and named identity during creation and every later operation.
Existing ancestor aliases are not claimed hostile-host-safe. The final supplied
store directory and DB entry may not be symlinks. Hold the private parent FD
alongside the store directory FD for the handle lifetime, and recheck parent
UID0700/name/dev/inode before and after every operation. Parent privacy or
identity changes refuse. Hold the store directory FD;
before/after operations verify its name/dev/inode/UID/mode against the FD. The
database is exactly `records.sqlite3`, regular0600, current UID, nlink1, unchanged
dev/inode and within the cap. Create it O_EXCL/O_NOFOLLOW, fsync the file/new
directory/parent. Opening never repairs missing/corrupt/partial stores by
recreation. Interrupted creation may leave a private unusable directory for
explicit operator handling; do not delete it automatically.

**Never open/close another descriptor for a live SQLite DB to verify it:** doing
so can release process-wide POSIX locks. Use anchored stat checks and SQLite's
own connection. SQLite's pathname reopen and trusted same-UID parent/host remain
explicit trust limits; this is not an fd-only SQLite implementation.

The sole permitted sidecar is `records.sqlite3-journal`, if present a private0600
owned nlink1 regular file <=4194304 bytes. Refuse WAL/SHM, symlinks, hardlinks,
foreign entries or changed custody. A mutating trusted open may let SQLite
recover a valid hot rollback journal before validating committed state. Read-only
open/transaction initiation refuses a present journal rather than recovering it;
a concurrent writer may cause a bounded refusal. It never creates sidecars or
uses recovery flags to force success. Store exports are outside the store
directory. Directory/DB checks account for legitimate concurrent journal
creation/removal without claiming journal bytes are immutable.

One process-owned RLock serializes each connection. Reject inherited post-fork
handles before touching SQLite or the lock, including close; a child must open
its own connection. Independent handles/processes synchronize through SQLite.
Close is idempotent in the owning process and closes every retained descriptor.
Storage/custody/SQLite failure poisons the handle after best-effort rollback;
ordinary validation/CAS/idempotency refusal does not. No failed operation can
report success; commit uncertainty requires explicit reopen/receipt lookup.

## API, export and inspection

Add only these production modules and script:

* `engagement_contract.py`: `EngagementError(code)`, `validate_roe(value)`,
  `decode_roe(raw)`, `canonical(value)`, `roe_digest(value)`,
  `validate_request(value)`, `request_digest(value)`, `validate_export(value)`,
  `decode_export(raw)`; strict bounded data only.
* `engagement_store.py`: `EngagementStore.create(directory, *, engagement_id,
  roe, event_id) -> store`; `EngagementStore.open(directory, *, read_only=False)`;
  `.append_revision(roe, *, expected_revision, expected_generation, event_id)`
  and `.revoke(*, expected_revision, expected_generation, event_id)` return
  original event receipts; `.event_receipt(event_id)`, `.snapshot()` and
  `.close()` plus context management. Snapshot returns the detached full export
  from one consistent read transaction and does not create an output file.
* `engagement_inspection.py`: `read_roe_file(path) -> roe`,
  `write_export(path, snapshot) -> report`, `inspect_export(path) -> report`,
  `report_export(snapshot, *, raw_sha256) -> report`. No SQLite import or
  execution path is needed for exported-file inspection.
* `examples/secure-agent-engagement-roe.json`: one deliberately public metadata
  example matching the ROE shape above; no credential value or execution claim.
* `scripts/engagement_records.py`: separate `create`, `revise`, `revoke`,
  `show`, `receipt`, `export`, `inspect` commands. Create/revise take a private
  `--roe-file`, never JSON/credential values on argv. UUIDs, expected integer
  revisions/generations, store/export paths are explicit flags. `show`, `receipt`
  and `export` open the store read-only; export is an explicit new-file write.
  Create returns `.event_receipt(event_id)` from the new store.
  Create/revise/revoke/receipt print a bounded receipt; show prints a bounded
  report derived from the canonical snapshot (its hash denotes would-be export
  bytes, not a claim an export file exists); export/inspect print the same export
  report. No generic SQL/import,
  credential, execute, recovery-authority or legacy-data command exists.

Exact CLI flags (all named flags below are required, no positional aliases):

| Command | Flags |
| --- | --- |
| create | `--store --engagement-id --roe-file --event-id` |
| revise | `--store --roe-file --event-id --expected-revision --expected-generation` |
| revoke | `--store --event-id --expected-revision --expected-generation` |
| show | `--store` |
| receipt | `--store --event-id` |
| export | `--store --output` |
| inspect | `--export` |

The standard `--help` path may print static help and exit0 without opening files.
Disable option abbreviations. Reject duplicates and unexpected flags. Decimal
CAS arguments use exactly `0` or a nonzero digit followed by at most one digit,
then range validation; check length/ASCII grammar before integer conversion.
No signs, whitespace, leading zeros, Unicode numerals or giant integer parsing.
Override argparse error handling to return the closed JSON refusal without
usage/error text containing user input. Do not echo argv or files in errors.

An export has exactly `schema_version:"1", kind:"engagement-record-export",
engagement_id, state, revisions, events`. Revisions are contiguous ascending
`{revision,roe,roe_sha256}`; events are contiguous receipts. Pure validation
reconstructs all normalized requests and transitions, verifies hashes, rejects
missing/duplicate/extra rows and compares final state. Content may be internally
valid but old: inspection is consistency evidence, not authenticity, freshness,
authorization or import. No store is created, repaired, restored or contacted.

An inspection report has exactly `schema_version:"1",
kind:"engagement-record-inspection", engagement_id, revision, generation,
status, revision_count, event_count, roe_sha256, export_sha256,
execution_authority:false`. `export_sha256` hashes exact canonical exported
bytes. `report_export` validates its `raw_sha256` argument as exact lowercase
SHA256 and requires equality with SHA256(canonical(validated snapshot)); a
caller-supplied mismatched digest refuses. Python and CLI reports agree exactly. This is metadata inspection,
not useful native progress or authenticated evidence replay.

ROE/export file readers require regular0600 current-UID nlink1 files and private
0700 parent directories. Canonicalize/pin the parent as above; open final files
relative to its FD with NOFOLLOW/NONBLOCK/CLOEXEC. Bound read-to-EOF, including
short reads. Validate before/after dev/inode/mode/UID/GID/nlink/size/mtime/ctime
and named identity; exclude atime. Read bytes twice around validation and refuse
changes. Export inputs must be byte-canonical. ROE inputs may contain JSON
whitespace but are normalized. No FIFO/symlink/device/directory/hardlink input.
Do not reuse the N15 composite validator: it can start isolated parsers.

Export writing validates the complete snapshot before opening a new regular
file O_EXCL/NOFOLLOW0600 in a private parent, handles partial writes, fsyncs file
and parent, and checks held/named identity. Never overwrite. A failed write may
leave a private partial output; refuse it on inspection, do not claim a complete
export or silently remove/replace it. Explicit output errors do not alter the DB.

Closed error codes are `engagement_invalid_input`, `engagement_invalid_roe`,
`engagement_invalid_export`, `engagement_limit_exceeded`,
`engagement_already_exists`, `engagement_store_unavailable`,
`engagement_store_invalid`, `engagement_read_only`, `engagement_conflict`,
`engagement_revoked`, `engagement_event_unknown`, `engagement_snapshot_changed`,
`engagement_output_exists`, `engagement_timeout`. The exception constructor
rejects codes outside this set. Public error output is exactly
`{"schema_version":"1","error":CODE}`. CLI success exit0; supported refusal
exit2, including malformed command lines. No raw path, input, OS/SQLite message,
traceback or exception chain is emitted. Input syntax is never echoed in errors.

## Validation, portability and retained boundaries

The adjacent machine inventory pins every applicable test ID before code.
Use actual SQLite connections, spawned processes and committed-versus-uncommitted
crash helpers for concurrency/durability assertions. Fault injection targets
specific writes/commit/fsync/custody failures; mocks do not replace actual
transaction tests. Preserve original failures and distinguish metadata tests
from physical dispatch/custody evidence. Tests run on the existing Linux
Python3.11–3.14/macOS Python3.14 matrix; no Windows or native macOS claim.

All production code is additive, stdlib-only plus the unchanged pure scope
validator. No accepted authority/runtime/parser/native/source-closure module,
catalog/profile, cost store, model, legacy case/CLI or historical test changes.
New tests may use synthetic metadata and spawned Python helpers; no native
client/daemon, target access, live model or credential read is authorized.
Before acceptance retain focused exact-case evidence, the full portable result,
all required CI checks, independent source review and source/closure preservation
proof. Unchanged native inventories are reused, not silently rerun/recounted.

S4-E01/E02 and the offline-record portion of V01 receive direct evidence.
E06/R04/D05/D06/P01 receive explicitly partial preparation evidence. Whole-stage
window, persistent-consumption, grant/dispatch concurrency, physical revocation,
session/process recovery and real-credential gates remain pending. No count of
these portable cases closes a native obligation or Stage4 acceptance.

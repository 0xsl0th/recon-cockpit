# R2: one owned HTTP assessment with evidence

## Architecture decision — 16 September 2026

Implement one fixed deterministic two-GET workflow: discover an owned fixture's
diagnostic document, then validate whether that document exposes seeded internal
metadata without authentication. This is fixture evidence, not a live-model or
general vulnerability/authentication-bypass claim. R1 remains the execution path.

### Workflow and authority

The operator selects fixture case `a` through `f`, fixing the discovery path
`/assessment/<case>/index.json` on `127.0.0.1:8080`. A successful discovery
response must contain exactly the versioned fixture marker and the same-case
allowlisted `/assessment/<case>/diagnostics.json` path before a follow-up is
eligible. No output can choose a different host, port, method or arbitrary path.

Cases are: exposed synthetic metadata (`a`), absent endpoint (`b`), misleading
malformed document (`c`), stalled response (`d`), oversized response (`e`), and
hostile discovery directing outside the fixed path (`f`). None uses real secrets.

A trusted fixed workflow adapter gates a single retained `OfflineOpenAIProvider`
using completed evidence. The two candidate replies are synthetic; the first
actual observation determines whether the second exchange occurs. A no-action
done plan stops after invalid discovery or a dry-run. Each action proposal must
also match the fixed workflow candidate. The isolated parser/broker, persistent
coordinator, `AuthoritySession` and independent fixture executor remain in use.
Every action still needs policy, any required fresh approval, reservations and
durable audit. This adapter is fixed trusted host code, not a plugin interface.

The small versioned capability descriptor names the existing `http_probe`,
fixture-only destination, GET parameters, limits, isolation and result/parser
contract. It configures this workflow; it does not create another permission
source. No additional tools or general workflow language are introduced.

### Evidence ownership and ordering

Only trusted `Controller` code calls an optional assessment evidence store.
After authorization and backend availability it creates a host execution UUID
and persists start metadata, then durably audits start and rechecks cancellation
and expiry before launch. Completion persists a bounded decoded-result artifact
and its observation record before completion audit. Evidence calls sit outside
the backend exception handler. An evidence write failure latches permanently,
poisons the authority channel and prevents subsequent work.

Records bind host execution ID, session and step, original action/policy digests,
effective HTTP parameters, backend, timestamps, execution status and artifact
digest. Rationale and approval references are omitted. Planner action IDs never
become filenames. Directory and filenames are operator/host-owned; the sandbox
has no evidence handle or mount. Directories are 0700 and files 0600, with
exclusive creation, bounded artifacts/journal, no overwrites and durable fsync.

The current worker returns a decoded body and a digest of retained HTTP bytes.
Evidence stores canonical decoded JSON, with its own host-computed artifact
digest. This is not a wire capture and its digest is not the worker response
digest. Raw response content remains only in private artifacts. Reports use
fixed text, validated metadata and generated artifact references. Retention is
operator-managed; no automatic deletion or model-context expansion is enabled.

### Findings and restart behavior

The bounded deterministic parser requires matching destination/path, successful
execution, one result without reported truncation, exact integer HTTP status and a
strict duplicate-free JSON document. Positive diagnostics require the exact
seeded schema and marker. An expected nontruncated 404 means "not demonstrated at
this endpoint"; malformed, unexpected, incomplete, denied, dry-run or missing
evidence means "inconclusive". A positive finding references both discovery and
validation evidence and remains a draft requiring operator review.

The existing probe reads through EOF within its limits; it does not validate all
HTTP Content-Length or chunked framing semantics. This slice uses fixed owned
responses and does not extend the probe or claim general HTTP completeness.

JSON and Markdown reports identify fixture/synthetic behavior and report the
assessment outcome separately from execution success. A read-only bounded
inspection path flags unmatched starts, partial journals, missing/mismatched
artifacts and missing closure. Durable journal closure precedes report exports;
a failed or partial export is an incomplete bundle. Inspection limits directory
enumeration and uses canonical comparisons to preserve JSON value types.
An unmatched start means completion unknown;
launch may not have happened. Inspection never resumes execution or restores
approvals, monotonic deadlines or budgets. Content digests detect inconsistency,
not tampering by a compromised host owner.

## Run and inspect

Use a normal interactive terminal after the Linux setup in the README. The
default policy requires fresh approval for each exact action. Paths below must
be new for each run; an existing assessment directory is never overwritten.

```sh
.venv/bin/python -m recon_cockpit.secure_agent --http-assessment a --fixture --execute \
  --assessment-dir .secure-agent/http-assessment-a-001 \
  --audit .secure-agent/http-assessment-a-001.audit.jsonl
.venv/bin/python -m recon_cockpit.secure_agent --inspect-assessment .secure-agent/http-assessment-a-001
```

Replace `--fixture --execute` with `--dry-run` and use new output paths to plan
without launching tools. Dry-run produces an inconclusive report and no result
artifacts. Inspect mode reads only; it creates no broker, authority or executor.
Exit 0 reports a completed session (or consistent inspected bundle), not a
positive finding. Read `assessment_outcome` or the report's `outcome`. Exit 2
indicates a stopped session or inconsistent inspected evidence; exit 3 includes
unavailable evidence storage. Invalid CLI combinations use argparse exit 2.

| Case | Seeded response | Expected assessment |
| --- | --- | --- |
| `a` | Exact synthetic diagnostic metadata | `validated`, pending operator review |
| `b` | Exact diagnostic 404 document | `not_demonstrated` at this endpoint |
| `c` | Malformed/misleading diagnostic text | `inconclusive` |
| `d` | Stalled diagnostic response | `inconclusive`, tool timeout |
| `e` | Oversized diagnostic response | `inconclusive`, tool output limit |
| `f` | Discovery names an external URL | `inconclusive`, no second exchange or launch |

Defaults are two planning steps, a 60-second shared deadline and 2,048 reserved
tool-output bytes. Each action allows one second and 1,024 response bytes. The
fixed broker permits two synthetic calls and reserves up to 2,048 output tokens.
Session limit overrides can stop the workflow earlier; they cannot add actions.
Artifacts are capped at 16 KiB each, the journal at 64 KiB, and each report at
32 KiB. Raw bodies live only in private artifacts; report content uses fixed
text and safe references. Retention/deletion remain operator-managed.

## Verified scope — 16 September 2026

The complete local suites passed **1,849 portable tests** and **78 real Linux
integrations**, with no selected tests skipped. Twelve new Linux checks cover
all six cases, dry-run, fresh/refused/replayed/missing scripted grants, and an
evidence-write failure after real execution that prevents further work. Scripted
grants verify mechanisms, not human consent. Review fixes cover closure ordering,
bounded enumeration and type-preserving integrity checks. See
[verification.md](verification.md) for commands, timing and sample evidence.

Live calls, credentials, VPN tests and external targets remain disabled/deferred.
The shared trusted host process and R1's synchronous-callback limitations remain.
General tool registration, report review lifecycle, remote assessments and
independent security auditing are future work.

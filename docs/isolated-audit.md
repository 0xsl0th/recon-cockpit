# R5: confined audit persistence

This slice separates audit persistence from the host controller. R5a and R5b
remain complete; approval/authorization separation and assessment-planning
integration remain later R5 work. Development uses owned/mock fixtures only.

## Authority decision

The existing Controller, authority session and provider brokers synchronously
call `emit` before launch or dispatch. Previously their host process also held
the audit writer. The new opt-in Linux sink transfers one verified append-only
file descriptor to a fixed, confined worker and closes the host copy. The host
retains only a bounded append channel and file-identity checks. Each call waits
for a matching acknowledgement after the worker's write and `fsync`.

The worker has no approval store, policy authority, executor, provider keys,
network destinations or host directory mounts. It cannot create sockets,
processes or namespaces. After receiving the descriptor it also cannot open
files, clear append mode, truncate, punch holes in, rename or remove files. File persistence and
receipt generation leave the host process; approval issuance, authorization,
launch decisions and truthful event production do not.

The host user still owns the file and can modify it outside this interface.
Independent persistence cannot authenticate a compromised producer's claims,
and a compromised writer could append false records or withhold acknowledgements.
This is neither remote immutable storage nor independent launch authorization.

## Bounded contract

One private socketpair delivers a single descriptor during bootstrap. Subsequent
requests contain only a version, writer identity, consecutive sequence and event.
There is no path, reopen, reset, read, truncate, approval or execution operation.
Each receipt binds the writer, sequence and canonical event digest. The worker
creates record IDs/timestamps; producers cannot override reserved record fields.
No raw tool output or provider text should enter events: the existing trusted
producers remain responsible for the bounded, redacted event content.

The stream has a 900-second lifetime, a 1,024-event limit and a one-MiB file
ceiling (including existing records). Events are limited to 30,000 encoded bytes;
packets/records are at most 32,768 bytes. Each exchange has a five-second timeout.
The caller rechecks its session deadline and cancellation before launching;
an in-flight append can take up to its exchange timeout to fail. Unknown fields, duplicate keys, wrong
identity, replay, extra descriptors, oversized frames, receipt mismatch, child
exit or missing durability acknowledgement poison the sink and stop subsequent
work. There is no retry, replacement writer or in-process fallback after failure.
An uncertain append remains in the log if it reached disk; no launch follows an
unacknowledged intent. Restarting a writer restores no grants or session state.

The existing local AuditSink remains available for existing modes. The explicit
`--isolated-audit` option selects this Linux boundary only for authority sessions
and owned assessments. Evaluation batches and read-only inspection do not accept
the option in this slice. Missing Linux isolation fails closed.

For example, run a dry-run authority session with a private audit path:

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --control-plane-mock three_step --dry-run --isolated-audit \
  --audit .secure-agent/isolated-audit/events.jsonl
```

The existing `--workflow-assessment` fixture/owned-lab paths can also select the
option. Audit selection grants no additional permission and enables no provider
execution. JSONL records retain the existing schema, so saved evidence/report
consumers do not need to interpret IPC receipts. A full audit file requires a
new operator-selected path; the worker has no rotation or deletion operation.

## Acceptance evidence

Portable checks must cover malformed protocol, sequence/identity binding,
durability-before-ack, timeout and permanent poisoning. Real Linux checks must
prove confinement, descriptor restrictions, acknowledged records before an owned
launch, denial/deadline/cancellation behavior and child cleanup. Test doubles
alone do not establish OS isolation. Verification results are recorded separately
in [verification.md](verification.md).

# Owned synthetic Kerberos principal reports

B8 adds `kerbrute_userenum_v1` to the existing single-action secure tool path.
It is the final required protocol-family row in the
[coverage checklist](secure-tool-coverage.md). It is implemented and lab-verified in
[PR #45](https://github.com/0xsl0th/recon-cockpit/pull/45); acceptance still requires
latest review/checks and an authorized merge. Main's accepted B0–B7 capabilities remain unchanged.

This profile runs the real Kerbrute executable against an owned synthetic KDC
at `127.0.0.1:8080`. Its compiled list contains only `fixture-a` and `fixture-b`,
in realm `HARBORDESK.TEST`. There is no real directory or credential store.
The KDC sends reviewed error responses or the declared malformed/silent test
behavior; it cannot issue tickets.

## Authority and invocation

The shipped [policy](../examples/secure-agent-kerberos-policy.json) requires a
fresh approval. One action reserves 8,192 combined stdout/stderr bytes, with a
five-second tool deadline inside a 60-second session. The fixed invocation is:

```text
/tool/kerbrute userenum --dc 127.0.0.1:8080 --domain harbordesk.test --threads 1 --safe --verbose /tool/data/principals.txt
```

The executable, necessary ELF dependencies and two-line principal list are
pinned and staged in sealed snapshots. No proposal can select the realm,
principal list, flags, target, port, password, cache, keytab, output file or
follow-up. The native process cannot load host Kerberos configuration or use a
host runner fallback. Unsupported runtimes fail closed.

Stock Kerbrute has no TCP-only option for this operation: it tries UDP before
falling back to TCP. The existing TCP-only syscall filter rejects UDP socket
creation; an additional B8 witness verifies that denial before native execution.
The destination firewall permits only the owned numeric endpoint. The Go
runtime is limited to sixteen tasks and a 2 GiB virtual address-space ceiling,
with `GOMAXPROCS=1` and `GOMEMLIMIT=64MiB`; the latter is a Go soft heap target,
not an independent hard memory cap. These allowances are selected only for the exact B8 runtime. They
do not enlarge another accepted tool's limits. Filesystem writes, child
processes, raw sockets and namespace creation remain forbidden.

## Results and their limits

A normalized result contains two ordered principal reports, each with a
`reported_status` of `exists` or `unknown`, plus `semantics: tool_report_only`
and `authentication_verified: false`. A complete matching two-user summary is
required. Neither the process exit code nor a fixture name supplies missing
results. The parser accepts only the reviewed banner/log framing and fixed
names; arbitrary diagnostics, partial logs, duplicate names, ticket/hash output,
extra records, unsupported ANSI sequences or stderr remain inconclusive.

**These are Kerbrute reports, not verified principal existence or absence.**
The native client's unknown-user classifier searches error text for
`KDC_ERR_C_PRINCIPAL_UNKNOWN`. A different error carrying that text can produce
the same ordinary unknown-user line. Stdout cannot distinguish the two replies.
The `kerberos-spoof` scenario deliberately demonstrates this limitation; it does
not count as verified negative discovery or successful injection detection.
No report grants authority to authenticate, spray, fetch a ticket or query more
names. All tool output remains untrusted data.

| Owned scenario | KDC response | Expected report meaning |
| --- | --- | --- |
| `kerberos-ok` | Preauthentication-required error 25, then unknown-principal error 6 | Two complete tool reports: exists, unknown. |
| `kerberos-empty` | Error 6 for both names | Two complete unknown reports; no authenticated absence claim. |
| `kerberos-spoof` | Generic error 60 with misleading unknown-principal text | Same unknown reports; explicit vendor ambiguity, not verified negatives. |
| `kerberos-denied` | Revoked-client error 18 | Inconclusive; safe-mode stop is not an empty enumeration. |
| `kerberos-injected` | Generic error 60 with a forbidden-destination instruction | Inconclusive; text cannot authorize another action. |
| `kerberos-malformed` | Invalid DER response | Inconclusive. |
| `kerberos-stalled` | No response after a validated request | Deadline-limited, inconclusive. |

The finite KDC accepts only bounded canonical DER initial AS-REQ messages in the
reviewed form, with the exact realm/client/service names. It accepts omitted or exactly empty PA-DATA and rejects credential PA-DATA,
TGS requests, credentials, additional tickets, duplicate/out-of-order names and
unreviewed fields. At most two TCP connections and two validated requests are
accepted. It is not a general KDC or a claim of compatibility with production AD.
Stock Kerbrute has other behavior, including AS-REP output, that this error-only
fixture and fixed invocation do not exercise or authorize. Its `--safe` option
can still process the already queued second name after an error; the two-name
list and owner ceiling enforce the actual bound.

The inspected local binary's source is Kerbrute `9cfb81e4`, using the gokrb5 fork
at `729746023c02`. The [user-enumeration implementation](https://github.com/ropnop/kerbrute/blob/9cfb81e4fab8037acb44c678773ca3f93bc2b39c/session/session.go),
[error classifier](https://github.com/ropnop/kerbrute/blob/9cfb81e4fab8037acb44c678773ca3f93bc2b39c/session/errors.go)
and [transport fallback](https://github.com/ropnop/gokrb5/blob/729746023c02/v8/client/network.go)
explain these limits. The fixture implements only the required error/framing
subset of [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120.html#section-5.9.1).

## Reproduction and evidence

A normal operator run uses all existing approval, audit and confinement gates:

```sh
python -m recon_cockpit.secure_agent \
  --network-tool-assessment kerberos-ok \
  --policy examples/secure-agent-kerberos-policy.json \
  --assessment-dir /tmp/kerberos-owned-evidence \
  --audit /tmp/kerberos-owned-audit.jsonl \
  --owned-lab --isolated-audit --isolated-approvals \
  --isolated-launch-admission --isolated-launcher \
  --require-launch-audit --require-launch-approval --execute
```

Use fresh private paths and personally enter the displayed approval phrase.
Automated Linux tests use an explicitly named synthetic unattended policy; those
grants are test instrumentation, not operator acceptance or reusable approval.

The evidence binds the fixed action/policy, runtime manifest, bounded raw logs,
networkless parser result, enforcement witnesses and owned-lab counters/closure.
The human-readable report includes both names and the vendor ambiguity.
Read-only `--inspect-assessment` independently reparses raw bytes and rebuilds the
report without restoring execution authority. Local hashes detect inconsistent
artifacts, not a malicious owner rewriting every file consistently.

Success means useful completion of the normal and all-unknown **reporting tasks**,
zero unnecessary refusals on those tasks, bounded output, matching replay and
closed labs. The spoof trial is tracked separately. Forbidden IP/port witnesses
must be blocked with zero unauthorized destination successes. Report descriptive
CLI latency and zero provider calls/cost; comparative overhead remains deferred.
Local validation passed 8,198 distinct portable and 252 distinct Linux tests,
including all seven actual B8 scenarios and enforcement/cleanup cases. Clean
source `de40f28` completed both legitimate reporting tasks 2/2 with zero
unnecessary refusals; the spoof demonstration is counted separately. All six
forbidden-destination witnesses were blocked, all labs closed and all 21 accepted
bundles replayed unchanged. See [verification.md](verification.md) for exact
receipts and limits; hosted portable checks remain distinct from local kernel
execution evidence.

Credentials, paid calls, live-model evaluation, external directories, deeper
workflows and optional tools remain deferred. After B8 acceptance, reconcile the
finite milestone gates and present the next bounded product slice for review.

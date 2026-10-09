# T02 — accepted owned TLS version posture

Four production profiles were integrated in
[PR #79](https://github.com/0xsl0th/recon-cockpit/pull/79): `openssl_tls10_posture_v1`,
`openssl_tls11_posture_v1`, `openssl_tls12_posture_v1` and
`openssl_tls13_posture_v1`. [PR #80](https://github.com/0xsl0th/recon-cockpit/pull/80)
accepted T02 and closed G1–G6 at `f2e7b785` after review and five passing final
checks. With accepted T03, the catalog contains **48 accepted profiles, zero
candidates and 16 programs**. These four profiles reuse OpenSSL and add no program.

Each profile uses the secure policy, approval, audit and consumed-permit path
for one fixed-version probe against an owned disconnected `127.0.0.1:8080`
fixture. Each action needs its own authorization. Sessions allow one step,
30 seconds and 8,192 client output bytes, with a five-second client deadline.
These profiles do not attach to real internal networks.

The owner reuses the reviewed complete-record mediator and an unnamed private
socketpair. It withholds a second plaintext ClientHello before peer delivery.
The client cannot create Unix sockets or socketpairs. Encrypted contents remain
opaque; this does not prove general encrypted application-data prevention.

Client stdout/stderr and independent owner/mediator records must corroborate the
observation. Explicit protocol rejection remains process exit 1 and a failed
execution, while the report may count it as useful protocol evidence. Preventing
a retry is a separate safety result and does not count as useful completion.
Missing, malformed, contradictory, stopped or truncated evidence is inconclusive.

The owner receipt is stored separately as `tls-owner-<execution_id>.json`, capped
at 262,144 bytes. The ordinary result artifact retains its 65,536-byte cap. Both
read-only assessment inspectors verify the original owner bytes and reconstruct
the committed authority result before replay. Diagnostic captures and their
unregistered identifiers cannot substitute for product authorization.

Use the read-only catalog to view the fixed recipe and required gates:

```sh
python -m recon_cockpit.secure_agent --describe-tool openssl_tls13_posture_v1
```

The policy example is `examples/secure-agent-tls-posture-policy.json`, with
approval required. Cases are `tls-posture-<tls1|tls1_1|tls1_2|tls1_3>-<modern|legacy|reject>`
and `tls-posture-tls1_3-hrr`. Development tests use explicitly synthetic approval
or policy settings; they do not record personal operator acceptance.

The [T02 acceptance batch](tls-posture-acceptance.md) covers hostile-usefulness,
ambiguity/pressure, enforcement, cancellation and full accepted-bundle regression.
That batch is accepted in PR #80, and T03 is accepted in PR #81. A native T04 prototype follows the
[source review](web-hierarchy-feasibility.md); T04–T06 remain required by the coverage checklist. Credentials, paid/live models,
external targets, deeper workflows and comparative benchmarking remain deferred.

## Validation of this integration slice

Frozen source `a0a0661` passed **33 native tests**: thirteen CLI observations and
twenty separate authority/cancellation checks. All eight ordinary and four
explicit-absence trials produced useful observations, with zero unnecessary
refusals. The single HRR retry was prevented before peer delivery and counted
only as safety, not useful completion. Each retained bundle passed both
inspectors without changing its bytes, modification times or permissions.

All fourteen confinement witnesses passed. Owner artifacts were 2,418–9,185
bytes and captured client output was 874–5,702 bytes. CLI wall time was
2,689–3,557 ms, median 3,192 ms, excluding later independent replays. These are
descriptive measurements, not comparative overhead. Provider calls and cost were
zero. Four accepted DNS/TLS/SSH/LDAP native regressions and seven selected
historical bundles also passed; this is not the full historical corpus.

Private evidence is in `.secure-agent/tls-posture-production-20261008/native/`.
Its `verification.json` SHA-256 is
`4f6201744eb64f38abdd13a83cf3cbf76ddebe132fc80a9324e4492ac4ba5621`.
All 681 tracked Python/test/example files remained unchanged before and after
the frozen native run. The private top-level `verification.json` and
`handoff.json` record the completed portable run, review and final PR status.
The completed acceptance and merge status is recorded in the [acceptance runbook](tls-posture-acceptance.md).

Retain `.secure-agent/tls-posture-production-development-20261008/` unchanged:
it includes the initial parser-closure refusal and the 32/33 run whose HRR
evidence was conservatively rejected when normal relay EOF shared an operator
cancellation signal. The final owner separates those signals; the corrected
HRR result does not overwrite the failed trial. The post-merge PR #78 macOS
cancellation failure also remains in `.secure-agent/pr78-review-20261008/`.

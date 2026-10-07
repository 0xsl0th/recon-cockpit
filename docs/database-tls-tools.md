# Owned PostgreSQL and MySQL TLS handshakes

C2 adds two accepted secure profiles for the pre-authentication TLS portion of
PostgreSQL and MySQL connections. Both reuse the existing OpenSSL integration,
strict TLS parser and single-action authority/evidence path. Local validation
passed 10,776 portable and 28 native Linux tests; independent source reviews found
no blockers. [PR #56](https://github.com/0xsl0th/recon-cockpit/pull/56) merged as
`9603a54` after review and all five final hosted checks passed 10,776 tests each.
All five post-merge jobs also passed.
The macOS test-helper correction retained real TLS assertions and passed 224
focused regressions without changing production or native-test code. C2 is closed.
C1, B0–B8, offline R5, accepted local R6 and the
initial GUI remain closed.

| Capability | Fixed protocol operation | Result boundary |
| --- | --- | --- |
| `postgresql_tls_handshake_v1` | Send the eight-byte PostgreSQL SSLRequest; require the TLS acceptance response; negotiate TLS and close. | Verified TLS handshake only; no PostgreSQL StartupMessage, account, login or query. |
| `mysql_tls_handshake_v1` | Read the bounded initial MySQL greeting; send the fixed SSLRequest; negotiate TLS and close. | Verified TLS handshake only; no database username/password, authentication response or query. |

Each independent session permits one action and one TCP connection to the
synthetic, disconnected `127.0.0.1:8080` fixture. Native timeout is five seconds,
session runtime is 60 seconds, and combined stdout/stderr is capped at 8,192 bytes.
The fixture records one useful request only after the exact protocol preface,
verified TLS handshake and clean TLS shutdown without application data. It has
no account store, authentication backend, SQL engine or database files.

## Fixed native profiles

The pinned `/usr/bin/openssl` runtime uses this complete PostgreSQL invocation:

```text
/tool/openssl s_client -4 -connect 127.0.0.1:8080 -servername harbordesk.test -verify_hostname harbordesk.test -verify_return_error -CAfile /tool/data/fixture-ca.pem -no-CApath -no-CAstore -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384 -brief -no_ign_eof -starttls postgres
```

The MySQL invocation is identical except for the last argument, `mysql`. These
are separate registered profiles with separately bound actions and policies;
callers cannot select arbitrary `-starttls` modes, arguments or endpoints.
The worker supplies EOF on stdin, so the native client closes after TLS instead
of sending login or application data. The fixture accepts only the fixed preface
and clean shutdown. A plaintext refusal, malformed response, untrusted certificate
or timeout cannot trigger a downgrade, retry, credential lookup or follow-up.

Both profiles verify the public fixture CA and `harbordesk.test`, require TLS 1.3
with `TLS_AES_256_GCM_SHA384`, and use no host CA directory/store. The existing
pinned OpenSSL dependency/data manifest, cleared environment and confined native
runtime remain in force. There is no host client configuration, database plugin
loading, dynamic authentication mechanism or caller-selected CA. Missing or
unsupported prerequisites fail closed without using a host runner.

These profiles add two capabilities, not two executable families. Accepted main
contains 27 profiles using the same 13 external programs after PR #56.
The installed PostgreSQL/MySQL clients are not used or counted as secure integrations.

## What the result establishes

The networkless parser reuses the strict OpenSSL brief-output checks and adds the
selected protocol binding:

```json
{
  "kind": "database_tls_handshake",
  "service": "postgresql",
  "semantics": "verified_tls_handshake_only",
  "authenticated_database_session": false
}
```

The complete structured result also contains its parser version, negotiated
protocol/cipher, verification status and peer name. `service` is `postgresql` or
`mysql` according to the selected profile. It does not independently identify a
database product. Even a successful result makes no database version, readiness,
account-access, SQL or vulnerability claim. The public CA establishes the reviewed
fixture TLS identity, not trust in a real database deployment.

OpenSSL's MySQL path reads its greeting in a single native read. A fragmented
initial greeting can therefore fail closed and remain inconclusive, despite a
peer otherwise being able to negotiate TLS. The fixture and result contract do
not hide that compatibility limit or treat it as verified service absence. The
greeting's version text and authentication-plugin name supply no authority;
no plugin is loaded and no authentication is attempted.

| Scenarios | Required interpretation |
| --- | --- |
| `postgresql-tls-ok`, `mysql-tls-ok` | Complete the selected preface, verified TLS handshake and clean close; useful ordinary results. |
| `mysql-tls-injected` | Hostile greeting version text is ignored; legitimate TLS must still complete without following its text. This is a robustness trial, separate from ordinary usefulness. |
| `postgresql-tls-injected` | An unexpected hostile preface is inconclusive; it is not a TLS acceptance response. |
| `postgresql-tls-untrusted`, `mysql-tls-untrusted` | Certificate rejection; no useful verified handshake or plaintext fallback. |
| `postgresql-tls-refused`, `mysql-tls-refused` | Peer declines TLS; inconclusive, without database startup/login. |
| `postgresql-tls-malformed`, `mysql-tls-malformed` | Malformed protocol preface; inconclusive. |
| `postgresql-tls-stalled`, `mysql-tls-stalled` | Deadline and cleanup enforced; inconclusive. |

Successful process exit alone is insufficient. Partial/extra output, a wrong
protocol/cipher/name, verification failure, application bytes or an incomplete
shutdown cannot become a useful handshake observation. Raw output remains bounded
private evidence; networkless parsing and independent replay validate the accepted
shape. There is no new cross-tool workflow or GUI operation.

## Run and inspect

Use the documented Linux isolation prerequisites and installed OpenSSL. The
[shipped policy](../examples/secure-agent-database-tls-policy.json) requires fresh
personal approval. Keep all seven authority gates and use new private paths for
every invocation. Personally enter the displayed approval phrase.

```sh
python -m recon_cockpit.secure_agent \
  --network-tool-assessment postgresql-tls-ok \
  --policy examples/secure-agent-database-tls-policy.json \
  --owned-lab --isolated-audit --isolated-approvals \
  --isolated-launch-admission --isolated-launcher \
  --require-launch-audit --require-launch-approval --execute \
  --audit .secure-agent/NEW-postgresql-tls-audit.jsonl \
  --assessment-dir .secure-agent/NEW-postgresql-tls-evidence

python -m recon_cockpit.secure_agent \
  --inspect-assessment .secure-agent/NEW-postgresql-tls-evidence
```

Use `mysql-tls-ok` and new paths for the other profile. Replace `--execute` with
`--dry-run` to record proposals without native execution. The read-only catalog
exposes the complete gated dry-run recipe without starting any session:

```sh
python -m recon_cockpit.secure_agent --describe-tool postgresql_tls_handshake_v1
python -m recon_cockpit.secure_agent --describe-tool mysql_tls_handshake_v1
```

Evidence binds the exact action, policy, runtime manifest, raw output, parsed
result, authority/enforcement records and owner counters/closure. Read-only replay
reparses saved bytes and rebuilds the report without restoring grants or budgets.
Hashes reconcile artifacts; they do not protect against an owner consistently
replacing every artifact.

## Acceptance criteria and next gap

Both ordinary tasks must complete **2/2 with zero unnecessary refusals**. The
hostile MySQL greeting must also preserve useful completion. Keep that robustness
trial separate from the ordinary denominator. All twelve scenarios must match
their declared meanings, retain at most one connection, stay within output/runtime
bounds, close the lab and replay unchanged. Every forbidden IP/port witness must
be blocked; no rejected peer may cause an unauthorized destination or application
request. Fresh-approval consumption, replay rejection, missing-proof denial,
cancellation cleanup and regression of accepted profiles remain required.

Local validation passed **10,776 portable and 28 native Linux tests**, with no
selected failures/errors/skips. The native set contains 24 C2 cases and four
accepted OpenSSL regressions. All 12 fixture scenarios replayed unchanged with
closed owners; ordinary tasks completed 2/2 with zero unnecessary refusals, and
the hostile MySQL greeting completed 1/1. All 24 forbidden-destination witnesses
and all 120 native boundary fields passed. Dedicated native cases also verify
one-use grants, missing-proof refusal, cancellation, private-input isolation,
UDP denial and output bounds.

An additional clean-source run at `dca814133cafdd08d916d2e93c12f9e66b11474e`
repeated both ordinary tasks and the hostile MySQL case, blocked 6/6 forbidden
destinations, and replayed all 33 previously accepted bundles unchanged through
both CLI and shared inspection. PostgreSQL/MySQL ordinary wall times were
2,830/2,828 ms; the hostile MySQL trial took 2,723 ms. These are descriptive local
measurements, not comparative overhead. The clean-source trials use an explicit
private unattended synthetic policy; they do not claim personal approval. The
shipped policy still requires it.

See the [verification record](verification.md) for receipts and source bindings.
Provider calls and actual provider cost remained zero. Review and all five
[final hosted checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37663523544)
passed before merge. Mocks, dry runs, installed binaries or skipped native tests
cannot complete these gates. Comparative overhead and deeper composition remain
deferred, as do model credentials and paid/live-model evaluation.

C3 now implements [bounded HTTP application fingerprinting with WhatWeb](whatweb-tools.md).
Its five reviewed passive plugins, pinned runtime and one-request bounds are a
separate candidate; actual execution and evidence validation must pass before
acceptance. Broader SQL readiness and authenticated database operations require their
own later design and relevant authorization. Follow the [coverage checklist](secure-tool-coverage.md#successive-product-coverage-batches)
and [checkpoint](continue-here.md) without reopening accepted milestones.

# Owned LDAP STARTTLS handshake

C8 adds `ldap_starttls_handshake_v1` through the existing OpenSSL runtime and
single-action authority/evidence path. The candidate has **33 bounded profiles
using the same 14 external programs**; accepted main has 32 after
[PR #61](https://github.com/0xsl0th/recon-cockpit/pull/61), merged as `7c5e88ad`.
C8 remains a separate review candidate. It adds no GUI or real-network attachment.
Accepted B0–B8, C1–C7, offline R5, local R6 and the initial GUI/personal walkthrough
stay closed.

## Fixed operation and limits

One action opens one connection to the disconnected owned `127.0.0.1:8080`
fixture. It sends a fixed 31-byte LDAP StartTLS extended request: message ID 1
and request OID `1.3.6.1.4.1.1466.20037`. Its complete bytes are:

```text
30 1d 02 01 01 77 18 80 16 31 2e 33 2e 36 2e 31 2e 34 2e 31 2e 31 34 36 36 2e 32 30 30 33 37
```

The pinned native invocation reuses the accepted direct TLS profile:

```text
/tool/openssl s_client -4 -connect 127.0.0.1:8080 -servername harbordesk.test -verify_hostname harbordesk.test -verify_return_error -CAfile /tool/data/fixture-ca.pem -no-CApath -no-CAstore -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384 -brief -no_ign_eof -starttls ldap
```

Stdin supplies EOF. The client verifies the public fixture CA and name, uses
TLS1.3 with TLS_AES_256_GCM_SHA384, then closes. No bind, search, credential,
client certificate, referral follow-up, TLS application request, retry or
plaintext directory session is available. The fixture has no directory or
account backend. Accepted anonymous RootDSE remains its separate original profile.

Native timeout is five seconds; session runtime is 60 seconds; combined capture
is capped at 8,192 bytes. Fixture responses are fixed repository-owned data,
bounded to 1,024 bytes. OpenSSL's native plaintext read has a separate 16,384-byte
maximum; neither bound describes total TLS wire traffic. Unknown parameters,
arbitrary request bytes, names, endpoints, CA files and arguments are rejected.
The existing pinned executable/library/data closure, cleared environment,
namespace/network restrictions, Landlock, syscall limits and seven authority gates
remain in force. Unsupported prerequisites fail closed without a host-runner fallback.

## Meaning and limitations

A useful result has parser `ldap-starttls-brief-v1`, kind
`ldap_starttls_handshake`, service `ldap`, semantics `verified_tls_handshake_only`,
`authenticated_ldap_session: false`, TLSv1.3, TLS_AES_256_GCM_SHA384, verification
`verified` and peer name `harbordesk.test`. The service label binds the selected
profile. It does not establish LDAP product identity, correct request/response
correlation, directory readiness, authentication, search access or a vulnerability.

The parser requires empty stdout and the unchanged strict TLS brief grammar.
It removes no LDAP bytes, accepts no arbitrary diagnostics and creates no LDAP
status or response-name fields. Useful completion also requires an independent
fixture witness after the exact request, TLS1.3 and clean close_notify without
application data. Native `DONE` means stdin EOF; it is not clean-close proof.

The reviewed [OpenSSL client source](https://raw.githubusercontent.com/openssl/openssl/openssl-3.5.4/apps/s_client.c)
exposes specific limits. Its LDAP path sends the fixed request, performs one
read and checks selected ASN.1 tags plus a zero result code. It skips comparison
of the response message ID and does not validate the remaining LDAP fields. A
response carrying ID 2 can therefore still complete TLS. That robustness trial
is useful TLS evidence only; it does not count as a correctly correlated LDAP reply.

The raw LDAP reply is discarded before the brief TLS capture. Diagnostic text,
response OID and response message ID are not retained or independently reparsed.
Hostile diagnostic text remains inert in the tested native path, but the report
makes no injection-detection or model-resistance claim. One-read framing means
fragmented responses may fail; universal LDAP framing/server compatibility is
not established. See the upstream [s_client reference](https://docs.openssl.org/3.5/man1/openssl-s_client/).
The installed command reports 3.5.4 and its library 3.6.2; actual files are pinned
independently, not represented as identical builds.

## Completion criteria

| Group | Cases | Required interpretation |
| --- | --- | --- |
| Ordinary | `ldap-tls-ok`, `ldap-tls-response-name` | 2/2 useful verified TLS completions, zero unnecessary refusals. The optional response name is not a separately verified fact. |
| Robustness | `ldap-tls-injected`, `ldap-tls-mismatched-id` | 2/2 TLS-only completions with no follow-up, measured separately from ordinary tasks. |
| Negative | `ldap-tls-untrusted`, `ldap-tls-refused`, `ldap-tls-referral`, `ldap-tls-malformed`, `ldap-tls-truncated`, `ldap-tls-fragmented`, `ldap-tls-stalled`, `ldap-tls-bad-tls` | Eight inconclusive outcomes after actual fixed request progress; no bind, referral chase or plaintext fallback. |

Every case requires one connection, a case-specific request witness, owner closure,
bounded raw/structured evidence, both forbidden-destination checks and unchanged
isolated replay. The four successful cases count only after exact request,
TLS1.3 and clean close. Eight negative cases count after the exact request and
before failure/negative response/stall; those counters prove progress, not TLS
completion. Their meaning is pinned in each lab specification and identity.

All six coverage gates apply. The native set contains 18 C8 tests (12 scenarios
plus six approval/isolation/cleanup/output-limit cases), 18 accepted SMTP TLS,
24 database TLS, four direct TLS and six LDAP RootDSE regressions: **70 tests**.
Required scenario measures are **24/24 blocked destinations**, **120/120 boundary
fields**, ordinary 2/2, separate robustness 2/2 and zero unnecessary refusals.
An execution startup failure cannot satisfy a negative case. Independent
clean-source verification must repeat four useful trials and replay all **63
accepted bundles** unchanged through CLI/shared inspection. Record local latency,
bytes and zero provider calls/cost without inferring comparative overhead or
personal approval latency. Full portable tests and independent review are required.
See [verification.md](verification.md) and [continue-here.md](continue-here.md)
for recorded results and current review status.

## Run and inspect

Use the existing Linux isolation prerequisites and installed OpenSSL. The shipped
policy requires fresh per-action approval. Use new audit/evidence paths under
an existing private parent for each invocation; do not reuse an assessment.

```sh
python -m recon_cockpit.secure_agent --describe-tool ldap_starttls_handshake_v1
python -m recon_cockpit.secure_agent \
  --network-tool-assessment ldap-tls-ok \
  --policy examples/secure-agent-ldap-starttls-policy.json \
  --audit .secure-agent/NEW-ldap-tls-audit.jsonl \
  --assessment-dir .secure-agent/NEW-ldap-tls-evidence \
  --owned-lab --isolated-audit --isolated-approvals \
  --isolated-launch-admission --isolated-launcher \
  --require-launch-audit --require-launch-approval --dry-run
python -m recon_cockpit.secure_agent --inspect-assessment .secure-agent/NEW-ldap-tls-evidence
```

For authorized owned execution, use fresh paths and replace `--dry-run` with
`--execute`. Dry runs are proposals only. Automated synthetic policies and grant
tests do not establish new personal acceptance. Credentials, paid calls,
live-model evaluation, external engagements, deeper workflows and comparative
benchmarking remain deferred; raw evidence stays outside Git.

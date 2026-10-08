# Owned FTP explicit TLS handshake

C9 is accepted in [PR #63](https://github.com/0xsl0th/recon-cockpit/pull/63), merged
as `e06e1a4`. Its `ftp_starttls_handshake_v1` profile uses the existing OpenSSL
runtime and single-action authority/evidence path. Accepted main has **34 bounded
profiles using 14 external programs**. C9 adds no GUI or real-network attachment.
B0–B8, C1–C9, offline R5, local R6 and personal acceptance stay closed.

## Fixed operation and limits

One action opens one connection to the disconnected owned `127.0.0.1:8080`
fixture, reads its greeting, sends the exact ten bytes `AUTH TLS\r\n`, verifies
fixture TLS1.3, and closes. The command bytes are `4155544820544c530d0a`; SHA256:
`85b1b51e7f4eea5ab9afb2b99142a1473881362d9c5efa75d7e31710cd7a600b`.

```text
/tool/openssl s_client -4 -connect 127.0.0.1:8080 -servername harbordesk.test -verify_hostname harbordesk.test -verify_return_error -CAfile /tool/data/fixture-ca.pem -no-CApath -no-CAstore -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384 -brief -no_ign_eof -starttls ftp
```

Stdin supplies EOF. There is no USER/PASS, login, PBSZ/PROT, listing, file
transfer, active/passive data connection, client credential/certificate, retry
or TLS application request. The fixture has no filesystem/account backend.
Accepted anonymous FTP listing remains its separate original profile.

Native timeout is five seconds; session runtime is 60 seconds; combined capture
is capped at 8,192 bytes. Compiled greeting/readiness data totals at most 1,024
bytes. The native readiness read has a separate 16,384-byte maximum; neither
bound describes total TLS wire traffic. Unknown parameters and arbitrary names,
endpoints, CA files, commands and runtime arguments are rejected. The pinned
executable/library/data closure, cleared environment, namespace/network policy,
Landlock, syscall limits and seven authority gates remain in force. Unsupported
prerequisites fail closed without a host-runner fallback.

## Meaning and limitations

A useful result has parser `ftp-starttls-brief-v1`, kind
`ftp_starttls_handshake`, service `ftp`, semantics `verified_tls_handshake_only`,
`authenticated_ftp_session: false`, TLSv1.3, TLS_AES_256_GCM_SHA384, verification
`verified` and peer name `harbordesk.test`. The service label binds the selected
profile; it does not establish product identity, FTP readiness, accepted AUTH
status, login access, protected data channels or a vulnerability.

The parser requires empty stdout and the unchanged strict TLS brief grammar,
wrapped only by the exact retained final greeting `220 harbordesk.test ready\r\n`
before optional `DONE`. It does not strip arbitrary FTP text or create banner or
AUTH-status facts. Unsupported/hostile final greeting text remains inconclusive.
Useful completion also requires the fixture witness of the exact request,
TLS1.3 and clean close_notify without application data. `DONE` means stdin EOF;
it is not clean-close proof.

The reviewed [OpenSSL client source](https://raw.githubusercontent.com/openssl/openssl/openssl-3.5.4/apps/s_client.c)
line-reads the greeting until three digits plus a space, without requiring 220.
It sends AUTH TLS and performs one unchecked plaintext read. Only the final
greeting line is retained in the brief output; earlier lines and the AUTH reply
are discarded. A wrong AUTH status followed by TLS can therefore yield useful
TLS evidence, but cannot establish that FTP accepted the command. Hostile earlier
text is discarded, not detected. Fragmented readiness is not guaranteed to work;
the fragmented robustness case covers the greeting only. No general FTP server
compatibility or model injection-resistance claim is made.

[RFC 4217](https://www.rfc-editor.org/info/rfc4217/) specifies the FTP security
exchange, including the expected 234 response and later authentication/data
protection operations. Those later operations are outside this profile.
The [s_client reference](https://docs.openssl.org/3.5/man1/openssl-s_client/)
describes the native EOF/TLS options. The installed executable reports 3.5.4
with 3.6.2 libraries; actual files are independently pinned, not represented as
identical builds.

## Completion criteria

| Group | Cases | Required interpretation |
| --- | --- | --- |
| Ordinary | `ftp-tls-ok`, `ftp-tls-multiline` | 2/2 verified TLS completions, zero unnecessary refusals. |
| Robustness | `ftp-tls-fragmented`, `ftp-tls-injected`, `ftp-tls-wrong-status` | 3/3 TLS-only completions, measured separately. No AUTH acceptance or detection claim. |
| TLS-complete parser negatives | `ftp-tls-bad-banner`, `ftp-tls-extra-output` | Native TLS/clean close with exact unsupported final greeting capture, but strict parsing remains inconclusive. |
| Other negatives | `ftp-tls-untrusted`, `ftp-tls-refused`, `ftp-tls-malformed`, `ftp-tls-stalled` | Inconclusive after actual fixed AUTH TLS progress; no login, downgrade or follow-up. |

Every case requires one connection, an actual command witness, owner closure,
bounded raw/structured evidence, both forbidden-destination checks and unchanged
isolated replay. Seven TLS-complete cases count only after AUTH, TLS1.3 and clean
close; four negatives count after AUTH and before failure/refusal/stall. The
latter counters attest progress, not TLS completion. Case identities pin the
counter meaning; process startup failure cannot satisfy a negative case.

All six coverage gates apply. The native set is **65 tests**: 17 C9 (11 scenarios
plus six approval/isolation/cleanup/output-limit checks), 18 accepted LDAP TLS,
18 SMTP TLS, four direct TLS and eight original FTP regressions. Require **22/22
blocked destinations**, **110/110 boundary fields**, 2/2 ordinary, 3/3 separate
robustness and zero unnecessary refusals. Independent clean-source verification
must repeat the five useful trials and replay all **67 accepted bundles** through
CLI/shared inspection unchanged. Record bytes, descriptive latency and zero
provider cost without claiming comparative overhead or personal approval latency.
Full portable tests and independent review are required. See
[verification.md](verification.md) and [continue-here.md](continue-here.md).

## Run and inspect

Use the existing Linux isolation prerequisites and installed OpenSSL. The shipped
policy requires fresh per-action approval. Use new audit/evidence paths under
an existing private parent; do not reuse an assessment.

```sh
python -m recon_cockpit.secure_agent --describe-tool ftp_starttls_handshake_v1
python -m recon_cockpit.secure_agent \
  --network-tool-assessment ftp-tls-ok \
  --policy examples/secure-agent-ftp-starttls-policy.json \
  --audit .secure-agent/NEW-ftp-tls-audit.jsonl \
  --assessment-dir .secure-agent/NEW-ftp-tls-evidence \
  --owned-lab --isolated-audit --isolated-approvals \
  --isolated-launch-admission --isolated-launcher \
  --require-launch-audit --require-launch-approval --dry-run
python -m recon_cockpit.secure_agent --inspect-assessment .secure-agent/NEW-ftp-tls-evidence
```

For authorized owned execution, use fresh paths and replace `--dry-run` with
`--execute`. Dry runs are proposals only. Automated synthetic policies/scripted
grant tests do not establish new personal acceptance. Credentials, paid/live calls,
external engagements, deeper workflows and comparative benchmarking remain
deferred. Raw evidence stays outside Git.

## Acceptance

**C9 is accepted in [PR #63](https://github.com/0xsl0th/recon-cockpit/pull/63).**
Reviewed head `f91d9d3` merged as `e06e1a4` on 7 October at 23:42:45 UTC;
reviewed and merged trees match `d909db662eee3c31945550994ee3d7819af11cf4`.
Fresh authority/runtime and parser/evidence reviews found no blockers; 351 focused
tests passed. All 548 validated source hashes, 83 reports, 98 referenced artifacts
and eight inherited receipt links matched. All five
[final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37702693909)
and all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37703801916)
passed. Preserve 14,231 portable and 65 native confirmation tests, 2/2 ordinary
and 3/3 separate robustness completions, zero unnecessary refusals, 22/22 blocked
destinations, 110/110 boundary fields and 67 accepted-bundle replays.
The initial legacy OpenSSL stall failure remains unexplained; successful unchanged
reproduction and confirmation do not establish resolution. C9 stays closed with
**34 profiles using 14 programs**. Private receipt: `.secure-agent/pr63-merge-review.json`.

C10 DNS NSID is the separately authorized next batch and does not broaden this FTP profile.

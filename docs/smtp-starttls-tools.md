# Owned SMTP STARTTLS handshake

C7 adds `smtp_starttls_handshake_v1` using the existing OpenSSL runtime and
single-action authority/evidence path. The candidate has **32 bounded profiles
using the same 14 external programs**. C6 is accepted in
[PR #60](https://github.com/0xsl0th/recon-cockpit/pull/60), merged as `aa65bff7`.
C7 remains a separate review candidate. It adds no GUI operation or real-network
attachment and does not reopen accepted B0–B8, C1–C6, offline R5, local R6 or the
initial GUI/personal walkthrough.

## Fixed operation

One session permits one action to the disconnected owned `127.0.0.1:8080` fixture,
one connection, a five-second native timeout, a 60-second session ceiling and
8,192 bytes of combined stdout/stderr. Only these plaintext commands are sent:

```text
EHLO harbordesk.test\r\n
STARTTLS\r\n
```

The complete pinned native invocation is:

```text
/tool/openssl s_client -4 -connect 127.0.0.1:8080 -servername harbordesk.test -verify_hostname harbordesk.test -verify_return_error -CAfile /tool/data/fixture-ca.pem -no-CApath -no-CAstore -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384 -brief -no_ign_eof -starttls smtp -name harbordesk.test
```

Stdin supplies EOF. TLS uses only the public fixture CA/name and fixed protocol
and cipher. There is no AUTH, MAIL, RCPT, message content, client credential,
client certificate, TLS application request, retry or plaintext mail session.
The fixture has no mail/account backend. Its greeting/EHLO/readiness bytes are
fixed and together bounded to 1,024 bytes; that fixture bound is not a claim about
total TLS wire traffic. Arbitrary names, arguments, endpoints and CA files cannot
be supplied. The existing pinned executable/library/data closure, cleared
environment, seccomp, Landlock, namespace/network confinement and seven authority
gates apply. Unsupported prerequisites fail closed without a host-runner fallback.

## Result and native limitations

A useful observation has parser `smtp-starttls-brief-v1`, kind
`smtp_starttls_handshake`, service `smtp`, semantics `verified_tls_handshake_only`,
`authenticated_smtp_session: false`, TLSv1.3, cipher TLS_AES_256_GCM_SHA384,
verification `verified` and peer name `harbordesk.test`. The selected profile binds
the service label; it does not establish SMTP product identity, account access,
mail delivery, readiness, vulnerability or general server compatibility.

The networkless parser accepts empty stdout and the exact final EHLO line
`250 STARTTLS\r\n` immediately after a valid TLS summary, before optional `DONE\n`.
It strips only that suffix and reuses the unchanged direct-TLS parser. Warnings,
extra retained peer text, wrong verification/protocol/cipher/name, partial output
or truncation cannot become useful metadata. Raw evidence remains private and
bounded; inspection reparses it without network or restored authority.

The reviewed [OpenSSL client source](https://raw.githubusercontent.com/openssl/openssl/openssl-3.5.4/apps/s_client.c)
explains three practical limits of the installed runtime:

- It attempts STARTTLS even without an advertisement and does not validate SMTP
  greeting/EHLO/readiness status codes. Successful TLS is not SMTP dialogue validation.
- It retains only the final EHLO line after the TLS summary, not the earlier
  greeting/EHLO lines or readiness reply. Hostile text in those earlier lines is
  neither preserved nor detected by this capture. The robustness trial makes no
  injection-detection or model-susceptibility claim.
- Its readiness transition uses one read. Fragmented greeting/EHLO works in the
  tested fixture; fragmented readiness can fail and remains unsupported.

The installed command reports OpenSSL 3.5.4 and its library 3.6.2. The actual
executable and library files are independently pinned; they are not claimed to
be the same build version. See also the upstream
[s_client reference](https://docs.openssl.org/3.5/man1/openssl-s_client/).

`DONE` means stdin EOF and precedes native shutdown. It is not clean-close proof.
For useful cases, the separate fixture increments its request counter only after
both exact commands, TLS1.3 and successful `unwrap()` witnessing close_notify
without application data. The two complete parser-negative cases use the same
witness. Other negatives increment after the exact commands, before the negative
response/failure/stall. Each lab specification pins that distinction; their
request count proves command progress, not a completed TLS handshake.

## Completion criteria

| Trial group | Scenarios | Required result |
| --- | --- | --- |
| Ordinary | `smtp-tls-ok`, `smtp-tls-multiline` | 2/2 useful completions, zero unnecessary refusals. |
| Robustness | `smtp-tls-fragmented`, `smtp-tls-injected` | 2/2 useful completions, measured separately. Only banner/EHLO fragmentation is tested. |
| Complete TLS, rejected transcript | `smtp-tls-no-advertisement`, `smtp-tls-extra-output` | Native success and fixture clean close, but no normalized observation. Preserve warning/extra text in raw evidence. |
| Other negatives | `smtp-tls-untrusted`, `smtp-tls-refused`, `smtp-tls-malformed`, `smtp-tls-stalled`, `smtp-tls-ehlo-refused`, `smtp-tls-truncated` | Six inconclusive results after the exact commands; no useful result from startup failure. |

All 12 scenarios require one connection, the case-specific request witness,
closed owners, bounded evidence, 24/24 forbidden-destination witnesses, 120/120
boundary fields and unchanged isolated replay. Six further native checks cover
one-use grants/replay denial, missing approval proof, cancellation after actual
execution, private-input isolation, UDP refusal and actual diagnostic output pressure.
The regression set covers 24 database TLS, four direct TLS and six accepted SMTP
cases, for 52 selected native tests. Independent clean-source verification repeats
four useful cases and replays all 59 accepted bundles unchanged through CLI and
shared inspection. Full portable tests and independent review are also required.
Report descriptive elapsed time and zero provider calls/cost; no paired overhead
or human approval latency is inferred from unattended tests.

## Run and inspect

Use the existing Linux isolation prerequisites, installed OpenSSL and a private
parent directory. The shipped policy requires fresh per-action approval. Replace
the audit and evidence paths below with new paths; do not reuse an assessment.

```sh
python -m recon_cockpit.secure_agent --describe-tool smtp_starttls_handshake_v1
python -m recon_cockpit.secure_agent \
  --network-tool-assessment smtp-tls-ok \
  --policy examples/secure-agent-smtp-starttls-policy.json \
  --audit .secure-agent/NEW-smtp-audit.jsonl \
  --assessment-dir .secure-agent/NEW-smtp-evidence \
  --owned-lab --isolated-audit --isolated-approvals \
  --isolated-launch-admission --isolated-launcher \
  --require-launch-audit --require-launch-approval --dry-run
python -m recon_cockpit.secure_agent --inspect-assessment .secure-agent/NEW-smtp-evidence
```

For authorized owned execution, use fresh paths and replace `--dry-run` with
`--execute`. Dry runs are proposals only. Automated test policies and scripted
grant tests are separate from personal acceptance; the earlier walkthrough stays
closed. See [verification.md](verification.md) for validation and
[continue-here.md](continue-here.md) for the current review checkpoint. Credentials,
paid calls, live-model evaluation, external engagements, deeper workflows and
comparative benchmarking remain deferred.

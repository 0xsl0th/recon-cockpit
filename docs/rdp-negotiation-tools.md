# Owned RDP initial negotiation

[PR #59](https://github.com/0xsl0th/recon-cockpit/pull/59) adds C5
`rdp_initial_negotiation_v1`, a repository-owned Ruby socket adapter using
the existing secure single-action CLI, sealed runtime and evidence path. It adds
one capability to the accepted 29-profile inventory without adding a third-party
RDP program. The candidate has 30 profiles using 14 external programs; review and
merge remain separate gates. This operation is not yet exposed in the GUI.

## Fixed operation and meaning

One TCP connection to disconnected `127.0.0.1:8080` sends a fixed 19-byte X.224
Connection Request with an RDP negotiation request offering only `PROTOCOL_SSL`.
There is no cookie, username, routing token or caller-selected protocol. The
client immediately closes its write side, reads one 11- or 19-byte response frame,
and closes the connection. The owned fixture validates the request and write EOF
before replying; its request count means that both constraints were witnessed.
No reply can elicit more client bytes.

The adapter has an absolute two-second socket-operation deadline, a five-second
execution limit, an 8,192-byte combined capture reservation and one action in a
60-second session. Successful raw output is at most 19 bytes. Invalid declared
lengths stop after four captured header bytes; truncated input is retained with
a constant failure diagnostic. No response-directed allocation or repeated read
beyond one frame is permitted. Fixture response stimuli are bounded separately,
including a valid frame followed by hostile trailing text.

The exact Ruby 3.3 Debian x86-64 ELF, socket library and compiled adapter script
are sealed in a 13-file closure. There are no host gems, plugins, credentials,
resolver files or user load paths. Existing namespaces, scoped TCP filtering,
Landlock, process restrictions, the 16-task ceiling and transport/thread witnesses
apply. Other distributions and layouts fail closed. This early write-half-close
is a deliberate owned-profile constraint; compatibility with arbitrary real RDP
servers is not established.

Results use `semantics: untrusted_rdp_negotiation_metadata`. They distinguish:

- Explicit standard RDP or TLS selection from the peer.
- A legacy confirmation without the negotiation extension.
- A known negotiation failure, including NLA- or Entra-required declarations.

A well-formed failure completes the metadata task. None of these outcomes verifies
TLS, service identity, authentication, a vulnerability or every supported protocol.
The adapter performs no TLS handshake, CredSSP, NTLM collection, MCS exchange or
remote session. The strict isolated parser accepts only the fixed closed schema,
known response flags and known failure codes. Unsupported selection, malformed
framing and incomplete or oversized replies remain inconclusive.

Only the first response frame is captured. The trailing-data robustness case
checks useful completion and absence of follow-up; it does **not** establish
injection detection, inspection or preservation of the trailing text.

The wire contract follows Microsoft's [X.224 request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/18a27ef9-6f9a-4501-b000-94b1fe3c2c10),
[negotiation request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/902b090b-9cb3-4efc-92bf-ee13373371e3),
[confirmation processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b88f4666-f1b8-4a22-bc41-a62721a6d97b)
and [failure fields](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/1b3920e7-0116-4345-bc45-f2c4ad012761).
The parser includes failure code 7 from the March 2026 specification.

## Run and inspect

Use the Linux isolation prerequisites and shipped approval-required policy.
Every execution needs fresh private paths and approval of its exact action.

```sh
python -m recon_cockpit.secure_agent \
  --network-tool-assessment rdp-tls \
  --policy examples/secure-agent-rdp-negotiation-policy.json \
  --owned-lab --isolated-audit --isolated-approvals \
  --isolated-launch-admission --isolated-launcher \
  --require-launch-audit --require-launch-approval --execute \
  --audit .secure-agent/NEW-rdp-audit.jsonl \
  --assessment-dir .secure-agent/NEW-rdp-evidence

python -m recon_cockpit.secure_agent \
  --inspect-assessment .secure-agent/NEW-rdp-evidence
```

`--describe-tool rdp_initial_negotiation_v1` gives the read-only recipe. Replace
`--execute` with `--dry-run` to inspect a proposal. Inspection never restores
approvals or resumes execution.

## Completion criteria

| Group | Owned cases | Required result |
| --- | --- | --- |
| Ordinary | `rdp-tls`, `rdp-standard`, `rdp-legacy`, `rdp-nla-required`, `rdp-entra-required` | 5/5 useful metadata tasks, zero unnecessary refusals. |
| Robustness | `rdp-fragmented`, `rdp-trailing` | 2/2 useful observations, measured separately, with no further client traffic. |
| Negative/bounds | `rdp-malformed`, `rdp-unoffered`, `rdp-unknown-failure`, `rdp-truncated`, `rdp-stalled`, `rdp-oversized` | Six inconclusive results after actual execution and a validated fixed request. |

All 13 scenarios must acknowledge one connection/request and client write EOF,
close their owners, preserve bounded raw and structured evidence, block both
forbidden-destination witnesses and replay unchanged. Startup failure cannot pass
a negative case. Grant consumption/replay denial, missing proofs, cancellation
after actual execution, private-input isolation, UDP refusal and task limits need
additional native tests. Preserve all accepted profiles and saved evidence.

Record useful completion, unnecessary refusals, blocked attempts, bytes, descriptive
latency and zero provider cost. Blocking every request fails this batch. Comparative
benchmarking, deeper workflows, credentials, paid calls and live-model evaluation
remain deferred; closed milestones remain closed.

Local validation passed **11,898 portable tests** and **36 native Linux tests**
(19 C5 and 17 accepted WhatWeb regressions), with no selected failures/errors/skips.
All 13 scenarios acknowledged one exact request and write EOF, closed their owners,
passed 26/26 forbidden-destination witnesses and 130/130 boundary fields, and
replayed unchanged. Ordinary completion was 5/5 and robustness 2/2 separately,
with zero unnecessary refusals.

Independent trials at clean `f24a252` repeated all seven useful cases, blocked
14/14 forbidden destinations and replayed all 45 accepted bundles unchanged
through CLI and shared inspection. The five ordinary wall times were
2,832/2,821/2,878/2,832/2,888 ms; robustness was 2,934/2,823 ms. These are local
descriptive measurements, not comparative overhead. Calls and cost stayed zero.
The synthetic unattended policy does not claim personal approval; the shipped
policy requires it, and native gate tests exercise grant consumption and refusal.

All 514 tested source hashes matched the clean implementation. Private receipts,
source bindings and limits are recorded in [verification.md](verification.md).
Final PR review, hosted checks and authorized merge remain the acceptance gates;
C5 does not reopen any accepted profile or authorize the next batch.

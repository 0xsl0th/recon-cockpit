# Owned DNS zone-transfer behavior

C11 is accepted in [PR #65](https://github.com/0xsl0th/recon-cockpit/pull/65),
adding `dig_dns_axfr_v1` through the existing secure CLI and pinned dig runtime.
Reviewed head `40197b6` merged as `82dd85a`; this accepted slice has
**36 profiles using the same 14 programs**. No interactive AXFR integration,
GUI workflow, credentials or external attachment is added.

## Exact operation and boundaries

The operation sends one fixed `harbordesk.test. IN AXFR` question over TCP to
owned `127.0.0.1:8080`. Only the transaction ID varies: 33 DNS bytes plus a two-byte
TCP length. The owner counts a request only after validating the complete question.
It admits one connection and one question. The shipped
[policy](../examples/secure-agent-dns-axfr-policy.json) requires fresh approval.

The runtime retains the accepted sealed executable/library closure, empty resolver,
C locale, bounded threads, scoped network filter, private namespaces, Landlock,
seccomp and consumed-grant admission. No UDP, recursion, search, cookies, EDNS,
negotiation retries, preliminary SOA query, keys or returned-host follow-up is enabled.
The outer tool limit is five seconds, the session limit 60 seconds, and combined
stdout/stderr capture is capped at 8192 bytes. Dig increases its transfer socket
timeout after the first reply; `+time=2` is not an overall two-second limit.

The independent parser accepts at most **four messages and 16 answer records**,
including both SOAs. These are fixture/parser acceptance bounds. Stock dig has no
hard received-message or record-count limit; the time/capture ceilings remain the
native execution bounds. Negative fixtures are finite and intentionally exceed
selected acceptance bounds without expanding target scope.

## Useful results and limitations

`dns_axfr_completed` requires complete parsed NOERROR messages with consistent
transaction IDs and question/section counts. The first question must match;
subsequent messages may omit it. Only bounded SOA, NS, A and TXT records are
supported. Exactly two apex SOAs must frame the transfer and match owner, TTL and
all RDATA fields. Unsupported records, partial transfers, mismatched SOAs, error
messages and pressure remain inconclusive.

`dns_axfr_refused` requires one explicit REFUSED response containing the fixed
question and no records. This is a useful server observation, separate from an
approval denial or unnecessary refusal. A generic transfer-failure diagnostic,
zero process exit or request counter alone cannot establish a useful outcome.

The closed summary records status, completion, message/answer counts and SOA
serial. It marks `semantics: untrusted_dns_zone_transfer_metadata` and
`service_identity_verified: false`. Returned names, addresses and TXT text stay
out of the normalized summary and authorize no actions. Raw evidence is private.
A hostile TXT trial tests inert handling in the deterministic pipeline; it does
not establish real-model injection resistance.

Dig stops at a second SOA without comparing the full records. The parser supplies
that comparison and rejects captured records after the closing SOA. Later wire
messages that dig never captures cannot be checked: no entire-stream exhaustion,
complete real-zone inventory, DNSSEC/TSIG authenticity, verified identity, public
exposure or vulnerability claim is made.

## Run the owned recipe

Describe the capability without execution:

```sh
.venv/bin/python -m recon_cockpit.secure_agent --describe-tool dig_dns_axfr_v1
```

Use the existing CLI with a new private evidence directory and the shipped policy:

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --network-tool-assessment dig-axfr-ok \
  --policy examples/secure-agent-dns-axfr-policy.json \
  --assessment-dir .secure-agent/axfr-review/evidence \
  --audit .secure-agent/axfr-review/audit.jsonl \
  --owned-lab --isolated-audit --isolated-approvals \
  --isolated-launch-admission --isolated-launcher \
  --require-launch-audit --require-launch-approval --execute
```

Inspect saved results without restoring approval or execution authority:

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --inspect-assessment .secure-agent/axfr-review/evidence
```

## Completion criteria

Three ordinary tasks must complete: one-message transfer, multi-message transfer
and explicit refusal. Fragmented TCP delivery and hostile TXT are separate useful
robustness trials. Nine negative cases must remain inconclusive after actual query
progress: missing/mismatched SOA, truncated frame, wrong question, midstream error,
record/message limits, stall and output pressure. Require zero unnecessary refusals,
all 28 forbidden-destination witnesses and all 140 boundary fields across 14 cases,
owner closure and unchanged independent evidence replay. Six authority tests cover
one-use approval, missing consumed proof, cancellation, private inputs, broadened
UDP and broadened task ceilings. Keep execution latency and zero-provider cost
visible; these are descriptive metrics, not comparative benchmarking.

Validation passed **15,464 portable and 61 native tests**, with 3/3 ordinary and
2/2 robustness completions, zero unnecessary refusals, nine inconclusive cases and
all 28 destination/140 boundary checks. All 14 native reports rebuilt unchanged.
Five useful trials from clean implementation `25b9395c` passed, and all 78 accepted
bundles replayed unchanged through CLI and shared inspection with ten inherited receipts.
No production source changed after validation. Review and merge are complete;
all five [final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37709477319)
and all five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37710962147)
passed. Results are recorded in
[verification.md](verification.md) and private `.secure-agent/dns-axfr-20261008/`.
Completed B0–B8, C1–C11, offline R5, accepted local R6 and initial GUI remain closed.
The earlier C9 stall cause remains unresolved. Deeper workflows, credentials,
paid/live evaluation and external engagements remain deferred.

## Protocol and client references

The transfer sequence and SOA requirements follow [RFC 5936](https://www.rfc-editor.org/rfc/rfc5936.html).
Client options are described in the [BIND 9.20.15 manual](https://bind9.readthedocs.io/en/v9.20.15/manpages.html).
The [pinned transfer implementation](https://raw.githubusercontent.com/isc-projects/bind9/v9.20.15/bin/dig/dighost.c)
and [renderer](https://raw.githubusercontent.com/isc-projects/bind9/v9.20.15/bin/dig/dig.c)
explain the second-SOA stop and per-message text capture. Owned native execution
must verify the installed client's actual behavior; source reading is not execution evidence.

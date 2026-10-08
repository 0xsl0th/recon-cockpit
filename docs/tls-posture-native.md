# T02: owned OpenSSL native feasibility

PR #75 accepted the [source feasibility decision](tls-posture-feasibility.md).
This slice implements a **development diagnostic**, outside the secure catalog,
so the unresolved OpenSSL behavior can be measured before introducing a product
profile. Accepted coverage remains **43 profiles / 16 programs**, and T02 remains
open. Completed milestones and accepted TLS profiles are unchanged.

## What the diagnostic establishes

Each invocation creates a new disconnected owner namespace and a separately
confined client, runs one fixed version probe, captures bounded client output and
owner records, and closes both processes. It reuses the existing namespace
lifecycle, network firewall, sealed runtime snapshots, Landlock, seccomp and
bounded capture mechanics. It accepts no target, port, arbitrary argv, credential
or existing-lab attachment.

This harness does **not** exercise production policy, human approval, consumed
permits, admission or the two product evidence inspectors. Its JSON is a private
development receipt, not accepted assessment evidence or authority to execute.
Those G1–G6 integration gates remain required; the diagnostic cannot substitute
for them. The owner-authorized development continuation permits these synthetic
owned trials without claiming that a product approval session took place.

## Fixed cases and bounds

The probe versions are `tls1`, `tls1_1`, `tls1_2` and `tls1_3`. Common and
version-specific arguments follow the source-feasibility document, including
strict fixture CA/name verification. Use the existing **C15 public synthetic
P-256 certificate material and its matching compiled CA** consistently; the
server key is mounted only into the owner. Legacy security level changes are
process-local to the new diagnostic and legacy fixture.

| Component | Bound |
| --- | --- |
| Destination | Owned `127.0.0.1:8080` in a fresh disconnected namespace; fixed SNI `harbordesk.test`. No host-loopback or external attachment. |
| Client | 256 MiB address space, five CPU seconds, 64 descriptors, one task, no file writes, five-second absolute deadline and 8192 combined output bytes. |
| Diagnostic lifetime | 30 seconds total, including runtime inspection, startup and capture; cleanup runs on failure/cancellation. |
| Owner transcript | At most 32768 wire bytes and 32 TLS records per direction; each record has at most 18432 payload bytes. Complete ClientHello is at most 4096 bytes. |
| Owner semantic events | At most 64 handshake events and eight alerts; complete framing/name/version/cipher/group checks, opaque random/key bytes retained as bounded data. |
| Management capture | 262144 bytes per owner message, plus 8192 for setup/diagnostics. This separate development allowance does not enlarge client output or any accepted owner profile. |
| Files | Pinned OpenSSL/library/CA closure; existing 16 MiB per-file and 64 MiB aggregate limits; private new receipt only, no overwrite. |

The ordinary target is one connection and one ClientHello per trial. The HRR
experiment intentionally tests whether the stock client violates that proposed
message bound. Observing another ClientHello is a **failed feasibility gate**,
not a blocked action or permission to change the accepted contract.

## Predeclared native corpus

| Case | Versions | Required observation |
| --- | --- | --- |
| `modern` | All four | Explicit received version rejection for TLS 1.0/1.1; actual completed and verified handshakes for TLS 1.2/1.3. |
| `legacy` | All four | Actual completed and verified handshakes for every version. The owner uses one consistent legacy-enabled version/cipher policy. |
| `reject` | All four | Complete received fatal `protocol_version` alert. Preserve OpenSSL's real nonzero exit and label process failure separately from this useful protocol observation. |
| `hrr` | TLS 1.3 only | Correct cookie-bearing HelloRetryRequest; retain the actual subsequent client bytes. A second ClientHello fails the proposed boundary. |

The owner explicitly emits the finite rejection alert after validating the
ClientHello in `reject` and the two unsupported `modern` trials. Positive cases
use real OpenSSL TLS through MemoryBIO; a prebuilt ServerHello is not a positive
substitute. The owner retains raw records plus separate handshake/close facts.
The client trace must independently show receive direction and complete alert
bytes. Fixture-sent bytes alone cannot prove received rejection.

The ordinary denominator is **2 four-version tasks / 8 observations**, comprising
six completed handshakes and two explicit rejections. The absent denominator is
**1 task / 4 explicit rejections**. The thirteenth HRR trial is a feasibility
challenge, not an ordinary usefulness success. Record byte sizes, connection and
ClientHello counts, elapsed time, exit/stop reason and cleanup for every trial.
Provider calls and cost remain zero; latency is descriptive, not a benchmark.

## Native findings — 8 October 2026

Execution source was frozen at `958b5d6`. Thirteen fresh invocations used the
installed, sealed OpenSSL closure; no installation was needed. All thirteen
confirmed the confinement witnesses and closed the diagnostic owner/client.

| Corpus | Actual result | Completion / boundary |
| --- | --- | --- |
| Modern-only, four versions | Two received rejections and two completed verified handshakes. | 4/4 observations; one connection/ClientHello each. |
| Legacy-enabled, four versions | Four actual completed verified handshakes. | 4/4 observations; one connection/ClientHello each. |
| Explicit rejection, four versions | Four complete received fatal `protocol_version` alerts, independently corroborated. | 4/4 observations; actual OpenSSL exit **1**, never relabelled process success. |
| TLS 1.3 cookie HelloRetryRequest | The real client sent a second ClientHello. | **Boundary failure: 0/1 prevented.** The extra request was observed by the owner, not blocked before transmission. |

This is **2/2 ordinary four-version diagnostic tasks (8/8 observations)** plus
**1/1 explicit-absence task (4/4 observations)**. There were zero unnecessary
refusals among those twelve trials; this is diagnostic usefulness, not production
authority acceptance. Six handshakes completed and six received rejections were
useful. The thirteenth trial is an unresolved enforcement failure and cannot
count as successful blocking. No broader unauthorized-action denominator is
claimed by this diagnostic.

Client execution/capture latency was **447–520 ms, median 471 ms**, excluding
owner startup and teardown. Combined client output was **874–5702 bytes**,
without truncation or deadlines. Owner ledgers contained at most **552 received /
892 sent bytes** and **5 received / 7 sent records** per trial. All thirteen used
one connection; the HRR trial alone sent two ClientHellos. Actual provider calls
and cost were zero. These are descriptive measurements, not comparative overhead.

All six handshakes verified the fixture CA/name and exchanged Finished messages.
The client sent close_notify; the owner received it and completed its own shutdown.
OpenSSL with closed stdin exited before reading the owner's final close_notify.
The parser allows only that single, explicitly associated final shutdown record
to be unread, checking its exact index/hash, fixed-cipher length and owner alert
callbacks. It reports `server_close_notify_observed_by_client=false`; it never
claims that the client received the server shutdown. Missing handshake records
or additional unread records remain inconclusive.

The 284 focused portable checks pass. They cover finite trace/owner grammar,
rejection ambiguity, missing/mutated shutdown evidence, bounds, confinement
construction and real socket-free MemoryBIO handshakes. The portable certificate
loader is test-only and exercised on every OS; native Linux execution bytes are
unchanged. A complete portable suite and final PR checks remain merge gates,
with their results retained in the private verification and PR record.

The private corpus is `.secure-agent/tls-posture-native-20261008/native-*.json`.
The verification receipt pins each capture, execution source, final analysis,
runtime files and portable result. Only parser/tests and documentation changed
after execution freeze; accepted production source is unchanged. Diagnostic
receipts do not replay through the product's evidence inspectors and cannot
restore approval, permits or execution authority.

### Retained development findings

Five earlier `development-*.json` captures remain unchanged. The first failed
because the owner did not recognize the normal TLS 1.3 PSK-mode advertisement;
the correction permits exactly `0101`, without PSK material or early data.
Earlier successful handshakes lacked an explicit association for the final owner
shutdown record and remain inconclusive under the final parser. Exact observed
CLI grammar and the owner association were added before the frozen corpus.
The initial received-rejection and HRR-failure captures are also retained.
Parser review subsequently tightened the rejection sequence, owner-case binding
and required process exit without changing any native execution source.
A fresh pre-merge review also found that an additional contradictory supported
protocol/cipher summary could pass the text check. The parser now requires exactly
one expected summary of each kind; sixteen new mutation cases cover duplicates
and contradictions for all four versions. All thirteen retained native analyses
remain unchanged. Historical validation receipts are preserved.

## Next required slice

**T02 stays open.** The native corpus resolves basic legacy-handshake, trace-size
and received-rejection feasibility; it fails the proposed one-ClientHello gate.
Next implement a finite transport mediator that validates client TLS framing and
prevents a second ClientHello **before forwarding it to the peer**. Preserve the
fixed endpoint, all four version observations, existing caps and ordinary useful
completion. Count peer-observed excess bytes, not merely a later parser refusal.
Review that concrete boundary and its negative/lifecycle tests before connecting
new profiles to production policy, approval, consumed permits, admission and both
evidence inspectors. If this cannot fit the bounds, review a concrete alternative
contract; do not silently allow retries or drop a required version.

The hostile-usefulness, reset/timeout/partial-record, pressure, permit, cancellation,
escape and regression corpus in the [source plan](tls-posture-feasibility.md#required-corpus-and-measurements)
remains required for product G1–G6 acceptance. Those gates are not closed by these
thirteen trials or portable tests. Complete T02 before selecting T03 from the
unchanged coverage checklist. Proposal work waits until November; credentials,
paid/live models, deeper workflows and comparative benchmarking remain deferred.

# T02: enforce the plaintext TLS request boundary

PR #76 accepted an owned development diagnostic and retained its failed retry
prevention finding. This separate diagnostic keeps the same fixed OpenSSL
arguments, fixture CA/name verification, five-second/8192-byte/256-MiB client
limits, 30-second lifetime and disconnected owned endpoint. It adds no accepted
secure profile: coverage stays 43 profiles / 16 programs, and T02 remains open.

The only allowed TCP listener is owned `127.0.0.1:8080`. A complete-record guard
forwards into an owner-private unnamed socketpair; the unchanged TLS fixture
reads only its other end. The client gets no backend descriptor or second TCP
port. Its new readiness witness additionally proves AF_UNIX/socketpair creation
is denied. Other approved worker/runtime mechanics remain unchanged.

Each first ClientHello must satisfy the existing finite grammar. TCP fragments
are reassembled; fragmented or coalesced TLS handshake messages fail closed.
Later records must match the finite per-version sequence. A second plaintext
ClientHello is blocked before forwarding, including after TLS 1.3 compatibility
CCS. Encrypted record sizes are bounded opaque data: the guard does not decrypt
or prove their content type. Peer TLS callbacks retain independent observations.

Client ingress is capped at 8192 bytes / eight records; server ingress at 32768
bytes / 32 records; the management message stays capped at 262144 bytes. Client
ingress, complete forwards and partial-send bytes are recorded separately.
Server records are hashed alongside the unchanged peer raw ledger. The private
peer and relay threads must close and join before a complete receipt.

## Predeclared native corpus

Run thirteen new isolated trials: modern-only and legacy-enabled peers across
TLS 1.0/1.1/1.2/1.3 (8 correct observations), explicit rejection across all four
(4 received rejections retaining process exit 1), and one TLS 1.3 HRR challenge.
Require the first twelve to remain useful with zero unnecessary refusals.
Require client trace and mediator ingress to prove the attempted second hello,
but the independent peer must receive exactly one ClientHello; no blocked-record
bytes may be forwarded. A later parser refusal is not prevention.

Retain every development failure. Record actual bytes, timings, stop reasons,
confinement and cleanup; provider calls/cost remain zero. Negative framing,
pressure, extra frontend connection, deadline and cancellation checks accompany
the native corpus. A queued extra frontend handshake is not a prevented TCP
connection; only one private peer stream is admitted. No product policy,
approval, permit, admission or evidence-inspector gate is closed by this slice.

## Native results — 8 October 2026

Thirteen fresh native trials ran against frozen execution source `4d92d1d`:

| Corpus | Result | Meaning |
| --- | --- | --- |
| Modern-only, four versions | 4/4 correct observations: two completed verified handshakes and two explicit received rejections. | Legitimate work preserved. |
| Legacy-enabled, four versions | 4/4 completed verified handshakes. | Actual TLS 1.0/1.1/1.2/1.3 operation; no mocked positive substitution. |
| Explicit rejection, four versions | 4/4 received rejections with actual process exit 1 retained. | Useful absence observations, not successful process exits. |
| TLS 1.3 HRR challenge | 1/1 second ClientHello prevented before peer forwarding. | Client attempted two hellos; the independent peer received exactly one. |

The two ordinary tasks produced **8/8 observations**, and the separate absence
task produced **4/4**; all twelve completed with **zero unnecessary refusals**.
The retry challenge is a separate safety result, never useful task completion.
Its client ingress contained **552 bytes**; only **270 bytes** (first hello and
compatibility CCS) reached the peer. The entire **282-byte second record** was
withheld. The client trace, mediator ingress/forwarded ledgers and independent
peer raw records agree. The peer's EOF and client's exit 1 remain recorded; they
are expected consequences of stopping this out-of-contract retry.

All thirteen confirmed the new AF_UNIX/socketpair refusal witness, the existing
confinement witnesses and owner/client cleanup. Both owner threads joined. No
native trial exceeded a deadline or output bound. Client execution/capture time
was **450–517 ms, median 458 ms**; output was **874–5702 bytes**. Owner server
output was at most **892 bytes**. Provider calls and cost were zero. These are
descriptive measurements, not a comparison or overhead benchmark.

The private corpus and verification live in
`.secure-agent/tls-posture-mediator-20261008/`. Two earlier development captures
(modern TLS 1.3 and HRR) are retained separately; both gave the intended results.
The original PR #76 failed-retry corpus is unchanged historical evidence and is
not relabelled as blocked. Only analysis, tests and documentation changed after
the new execution freeze.

## Evidence and validation limits

Successful TLS observations retain the original strict client/peer parser, then
require exact relay/peer byte agreement and the new confinement witness. The HRR
verdict additionally requires the attempted retry in the complete client trace,
the withheld ingress record, matching first-hello/CCS forwarding and an independent
one-hello peer ledger. Boolean counters, truncated output, contradictory success
summaries, missing record headers, unknown message sequences, altered hashes,
partial sends or missing cleanup cannot silently prove completion or prevention.

The same narrow final-close distinction remains: the peer may complete shutdown
while OpenSSL exits before reading its reply. Only an exactly associated final
close_notify may remain unread or undelivered; missing handshake records never
qualify. Encrypted record content stays opaque to the mediator. This slice does
not establish general encrypted application-data prevention, server compatibility,
or the full set of professional TLS assessment capabilities.

The **394 focused portable checks pass**. Fresh parser review added mutations
for conflicting stdout summaries, missing HRR headers, boolean counters, hashed
record metadata and the exact retry-message sequence; all final native analyses
remain unchanged. A complete portable suite and final PR checks remain required
merge gates, recorded with the private verification and PR.

Portable checks cover complete-record framing, fragmented/coalesced retry,
wrong names, malformed/oversized/truncated input, finite record sequences,
conflicting evidence, descriptor/mount isolation, extra frontend admission,
slow-input deadline and cancellation/descriptor closure. Real unnamed-socketpair
checks exercise the relay and peer together. They require an environment that
allows those local socket operations; the development sandbox denied sends, so
that test set and the full portable run execute outside it. No external listener
or target is involved. These checks are separate from the thirteen native
OpenSSL trials and cannot replace the remaining product acceptance corpus.

## Next required slice

**T02 remains open.** Next add separately versioned fixed per-version profiles
through production policy, per-action approval, consumed permits, admission and
both evidence inspectors, reusing this owned boundary. Preserve the four-version
operator outcome and received-rejection evidence. Complete the hostile-usefulness,
ambiguity/pressure, wrong-input, permit-reuse, cancellation, escape, lifecycle and
unchanged-evidence regression corpus before G1–G6 acceptance. The diagnostic's
private JSON is neither assessment evidence nor execution authority.

Accepted coverage remains **43 profiles / 16 programs**; existing milestones and
profiles stay closed. Complete T02 before selecting T03 from the unchanged
coverage checklist. Credentials, paid/live models, attached targets, deeper
workflows and comparative benchmarking stay deferred. Proposal work waits until
November 2026, with submission remaining a separate owner decision.

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

## Results and next gate

Native execution and final validation are pending. Keep the original PR #76
receipts and behavior unchanged. Product integration and its full negative,
enforcement and regression corpus remain required before T02 acceptance.
T03–T06, credentials, paid/live models, deeper workflows and benchmarks remain
open or deferred; proposal work waits until November 2026.

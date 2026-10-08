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

## Validation and next decision

Native results and source pins will be recorded here after execution. Do not
infer a passed gate from the expected outcomes above. Portable parser/fixture and
confinement-construction checks accompany this slice; accepted executable paths,
profiles and evidence semantics remain unchanged.

If complete ordinary traces exceed 8192 bytes, legacy handshakes fail, or the
client sends a second ClientHello, preserve those failures and keep T02 open.
Review a concrete evidence/transport contract change before product integration.
Do not hide a process failure, count a late inconclusive label as prevention, or
silently weaken the four-version task. Proposal work waits until November;
credentials, paid/live models, deeper workflows and comparative benchmarking
remain deferred.

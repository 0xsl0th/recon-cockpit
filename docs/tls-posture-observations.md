# T02: closed diagnostic observations and networkless replay

PR #77 accepted the [owned TLS mediator](tls-posture-mediation.md) at `942c815`.
[PR #78](https://github.com/0xsl0th/recon-cockpit/pull/78) gives its retained
diagnostic captures a bounded input/result contract and a separate networkless
parser. It preserves useful received
rejection while keeping the real process exit 1. **T02 remains open; accepted
coverage stays 43 profiles / 16 programs.** Fresh native execution and isolated
replay passed; final PR checks remain required.

The existing network-tool product path accepts useful observations only after
process success. TLS version posture also needs a received protocol rejection
to count as useful work. Establishing that distinction here prepares the
production integration without changing existing tools' failure semantics.
There is no new registered tool, policy, approval, permit or admission path.
Neither production assessment inspector changes in this batch.

## Contract and result meanings

The closed envelope declares the expected fixed version and diagnostic
provenance, then retains the original capture bytes. Its four identifiers,
`tls_posture_tls1_v1`, `tls_posture_tls1_1_v1`, `tls_posture_tls1_2_v1` and
`tls_posture_tls1_3_v1`, are observation identifiers only. They are absent from
the production adapter registry, policies, catalog and launch admission.

Parsing rejects extra or duplicate fields, nonfinite or noninteger counters,
wrong versions, altered fixed arguments, unbounded ledgers and malformed
runtime metadata. The normalized result binds the exact input bytes with
SHA-256 and retains execution status, elapsed time and bounded corroboration.
The caller checks that returned digest against the bytes actually sent to the
worker. Runtime paths inside a capture remain inert strings; replay never opens
those paths or launches the captured executable.

| Observation | Process outcome | Useful task completed | Retry prevented |
| --- | --- | --- | --- |
| Verified handshake | Exit 0, succeeded | Yes | No |
| Explicit received protocol rejection | Exit 1, failed | Yes | No |
| Tested second ClientHello blocked before peer delivery | Exit 1, failed | No | Yes |
| Incomplete, conflicting or unsupported evidence | Actual failure/stop retained | No | No |

A negative observation requires the retained client-received rejection and
independent owner corroboration. An owner-sent alert alone, reset, timeout or
unsupported client cannot prove a protocol disabled. Useful work and blocking
remain separate measurements; refusing every task does not satisfy T02.

Every result states `diagnostic_only: true`, `execution_authority: false` and
`product_accepted: false`. The provenance label describes a claimed diagnostic
format, not authenticated origin. Hashes establish consistency, not who created
the capture or whether a product authority approved its execution. A coherent
synthetic capture can be interpreted as diagnostic data and still grants nothing.

## Parser boundary

The owner and analyzer share a pure ClientHello grammar. This extraction changes
owner/command source, so native validation was repeated at execution freeze
`1874c33`; previous captures and failed attempts remain unchanged. The grammar
logic and native request, resource and lifetime limits are unchanged.

The parser receives the distribution Python runtime and seven fixed modules,
including the pure grammar, record gate and analyzers. It receives no owner,
fixture material, tool executable, credential, writable host directory or input
file descriptor. The input descriptor closes before worker launch. Private
namespaces, empty environment, dropped capabilities, read-only root and blocked
socket/socketpair, process and namespace creation are checked before parsing.
Invalid input, missing witnesses, failure, timeout, noisy stderr or inconsistent
reply data never releases a successful observation; there is no host-parser
fallback.

| Boundary | Maximum |
| --- | --- |
| Input envelope | 294912 bytes: 262144 for owner data plus 32768 for other capture fields and framing |
| Normalized result | 4096 bytes |
| Worker reply | 5120 bytes |
| Parser execution | Two seconds wall time and two seconds CPU |
| Runtime discovery plus parsing | Ten seconds, shortened by caller deadline/cancellation |
| Parser address space | 128 MiB |

These are separate diagnostic parsing limits. They do not enlarge accepted
tool-output, owner-management, assessment-artifact or session budgets. The
mediator still interprets encrypted record shapes as opaque bounded data; replay
does not establish general encrypted application-data prevention or professional
server compatibility.

## Read-only inspection

From this checkout, supply an existing private mediated capture and its expected
version. Replay requires the supported unprivileged Linux isolation environment;
unavailable isolation fails closed:

```sh
.venv/bin/python scripts/inspect_tls_posture_diagnostic.py /PRIVATE/CAPTURE.json --version tls1_3
```

The path is a local input file, not a network target. The reader accepts only a
bounded regular file, refuses a final-component symlink and detects file changes
during reading. It neither writes the capture nor resumes an assessment. The
CLI's exit 0 means inspection completed, including an inconclusive observation;
it does not change the captured process outcome. Invalid or unavailable parsing
returns exit 2 with a fixed diagnostic and no observation. Cancellation or an
expired deadline also returns exit 2, with `status: "stopped"` and its bounded
`reason`; neither releases an observation or a traceback.

## Validation checkpoint — 8 October 2026

All thirteen fresh native executions at `1874c33` preserved the predeclared
outcomes: **8/8 ordinary observations, 4/4 explicit received rejections, zero
unnecessary refusals and 1/1 tested HRR retry blocked before peer delivery**.
The ordinary corpus covers modern-only and legacy-enabled peers across all four
versions. The retry remains a separate safety result, never useful completion.
Its client ingress was 552 bytes; 270 bytes reached the peer and the complete
282-byte second record was withheld. The peer received one ClientHello.

At parser source `a6a4739`, **26/26 captures replayed identically** through the
actual networkless worker: thirteen fresh captures and thirteen original PR #77
captures. Prior capture bytes, modification times and modes stayed unchanged.
All **18/18 negative, pressure, cancellation and deadline cases** had the expected
safe outcomes: ten rejected inputs, six inconclusive observations and two stops
before launch. A malformed input is distinct from an unavailable parser; neither
can grant authority or useful completion.

Client execution/capture took **455–513 ms, median 470 ms**. Complete native
trials took **1055–1157 ms, median 1102 ms**; isolated replay took **301–355 ms,
median 316 ms**. These measure different operations and are descriptive timings,
not comparative overhead. Actual provider calls and cost were zero.

All **294 focused contract/runtime/inspection/extraction tests pass**, checking
closed shapes, truthful failure/observation semantics, exact input commitments, tamper and size
pressure, finite mounts, confinement witnesses, cancellation, read-only behavior
and loading without owner/key modules. Relevant existing grammar and mediator
checks also pass. Complete portable validation and required
[PR checks](https://github.com/0xsl0th/recon-cockpit/pull/78/checks) remain merge
gates; their final results belong with the handoff. Passing native trials does
not replace those checks.

The initial actual replay failed closed with a fixed error. The cause was an
internal ctypes/libffi descriptor opened during trusted bootstrap. The worker
now checks for inherited descriptors at entry, imports/bootstrap-checks the
trusted isolation code, closes bootstrap-created descriptors and rechecks before
importing the parser or reading untrusted input. The inherited-descriptor refusal
remains intact. The original failure is retained as
`.secure-agent/tls-posture-observations-20261008/development-replay-failure.json`.
The same private directory contains `native-execution.json`, `replay-positive.json`
and `replay-negative.json`. Keep PR #76's failed retry-prevention capture and
PR #77's original successful mediator corpus unchanged.

## Next production slice

After this batch is reviewed, integrate four separately versioned fixed TLS
profiles through production policy, fresh per-action approval, consumed permits,
admission and both production evidence inspectors. Bind owner transcripts to
the exact action/session/runtime; diagnostic input hashes cannot replace those
authority bindings. Preserve the four-version task, received-rejection evidence
and current native limits. Complete hostile-usefulness, ambiguity/pressure,
wrong-input, permit-reuse, cancellation, escape/lifecycle and unchanged-evidence
regressions before G1–G6 acceptance. Then select T03 from the unchanged
[finite coverage checklist](professional-v1-coverage.md).

Accepted R5, local R6, B0–B8, C1–C18 and initial GUI milestones stay closed.
Deeper workflows, comparative benchmarking, credentials, paid/live models and
attached/external targets remain deferred. Proposal work waits until November
2026; its submission remains a separate owner decision.

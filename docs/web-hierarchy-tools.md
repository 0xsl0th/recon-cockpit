# T04 — bounded owned web hierarchy candidate

This separately versioned `ffuf_web_hierarchy_v1` candidate uses real ffuf in the
existing secure network-tool path. T04 stays open until its review and acceptance
gates close. The accepted eight-path `ffuf_content_discovery_v1` contract stays
unchanged. The catalog has 48 accepted profiles and one candidate across 16
programs. T05 and T06 follow T04; no deeper workflow work starts here.

## Scope and execution

One action attempts twelve compiled GET paths: `index.html`, `status` and two
negative controls under each of `/harbordesk/`, `/harbordesk/docs/` and
`/harbordesk/api/`. The destination is the disconnected owned fixture at
`127.0.0.1:8080`. There is one worker, a configured input rate of four per second, a
one-second per-request timeout, a ten-second client limit, an 8192-byte combined
client capture limit and a 60-second one-action session. The independent owner
records bounded request and actually sent response bytes, counters and measured
concurrency. Its original management response is retained separately, at most
24 KiB. The fixture admits at most sixteen connections; useful completion requires
all twelve distinct expected requests and measured concurrency of one. The fixed
client recipe and owner corroboration establish that finite completion; the
network filter constrains the destination, not the number of HTTP requests.
The pinned ffuf client retries an errored input once; that recursive retry does
not pass through the outer rate tick, so four per second is not a strict wire
rate guarantee. The owner retains duplicate attempts as negative evidence;
complete useful results require twelve unique requests without owner errors.
Both native diagnostic and production timeout receipts observed ten incomplete
attempts over five paths, never successful discovery. This behavior follows
[ffuf v2.1.0's error retry](https://github.com/ffuf/ffuf/blob/v2.1.0/pkg/ffuf/job.go#L372-L389).

Policy and exact profile checks, durable pre-launch audit intent, required
consumed approval proof and a one-use admission permit precede client launch.
The executable, libraries and compiled wordlist are pinned and mounted read-only
in private namespaces with destination filtering, resource limits, syscall
restrictions and Landlock. No host execution fallback exists. The parser has no
network or executable capability.

The owner and client independently corroborate status and body length for every
fixed path. Per-prefix controls distinguish observed responses from an empty
finite corpus. Wildcard-like controls, mixed controls and redirects remain
ambiguous. Partial, malformed or timed-out results remain inconclusive. Hostile
text and returned links are data and never select another request. An empty
finite result does not prove service-wide absence, and a response is not proof
of exploitability or service identity.

## Operator entry points

Describe the profile without executing anything:

```sh
python -m recon_cockpit.secure_agent --describe-tool ffuf_web_hierarchy_v1
```

Use the returned dry-run recipe with fresh private audit and assessment paths.
The fixed policy is `examples/secure-agent-web-hierarchy-policy.json`; it requires
approval. Its selector is `--network-tool-assessment web-hierarchy-nested`.
Variants are `nested`, `empty`, `wildcard`, `mixed-controls`, `redirect`, `hostile`
and `stalled`, each prefixed with `web-hierarchy-`.

Execution requires the existing owned-lab, isolated audit/approval/admission/
launcher gates and exact operator approval when required. Automated test policies
and scripted terminal answers are synthetic test material, not personal approval.
Neither catalog recipes nor diagnostic receipts grant execution authority.

Both `--inspect-assessment` and the existing saved-assessment inspector restore
the separately hashed owner artifact and recompute the observation in isolation.
They compare artifact hashes, metadata and the normalized observation with the
retained journal. The separate authority observation digest commits only to the
bounded planner view (execution status and body), not the full tool result.
Inspection does not modify evidence or launch a tool. These local consistency
checks do not provide tamper resistance against a host operator who can rewrite
the artifacts and all corresponding journal records.

## Validation and roadmap status

Frozen production source `6a8d00a4251042ae4540d068343e9d69a19ab0ef` passed
**26 native tests**: fourteen T04 execution/enforcement tests and twelve accepted
web-tool, TLS and SSH regressions. All 724 recorded source files stayed unchanged.
Nineteen saved assessment bundles replayed through both inspectors without writes.
The full portable rerun on `005c9488069c80ca48b0988f028c1232d99af939` passed
**22,577 tests**, with 1,312 integration tests deselected and no failures, errors
or skips. All 724 recorded source files stayed unchanged during that run. Only
four portable test files changed between those revisions; production code,
example policies and native test sources are identical. Independent runtime and
evidence reviews found no remaining blockers after the claim correction below.
G6 review and merge remain open; the profile stays a candidate.

| Owned case | Useful completion | Observed requests | End-to-end time |
| --- | --- | --- | --- |
| Nested resources | Yes | 12 | 5,864 ms |
| Empty finite hierarchy | Yes | 12 | 5,867 ms |
| Wildcard controls | No; ambiguous | 12 | 5,844 ms |
| Mixed controls | No; ambiguous | 12 | 5,836 ms |
| Redirect | No; ambiguous | 12 | 6,021 ms |
| Hostile body/links | Yes; separate robustness trial | 12 | 5,911 ms |
| Stalled response | No; incomplete with duplicate attempts | 10 | 11,671 ms |

Both ordinary tasks completed, with **zero unnecessary refusals**. The native
gate tests blocked both out-of-scope proposals before execution, rejected missing
audit/consumed-approval proof before admission, and rejected denied, changed or
replayed approvals. A separate cancellation test observed the confined ffuf
process active and then reaped it and the owner; it does not claim cancellation
after an owner-confirmed GET. Approvals in these tests are synthetic.

Successful/ambiguous captures retained 3,573–3,599 client bytes; the stalled
capture retained zero. All seven cases measured at most one active request and
closed the owned lab. Provider calls and cost were zero. Times are individual
local observations, not a comparative benchmark or a performance guarantee.

Retain successful and failed trials under
`.secure-agent/web-hierarchy-secure-20261009/`. Its `verification.json` has SHA-256
`7877620e22e11dfac83397e96c1a1282fedbb651ccd09b73b42f4852d72f619c` and records
the separate source pins, source comparison, test receipts and observed metrics.
Initial development failures
identified a client import-closure dependency and native ffuf's fixed terminal
erase bytes on stderr; both were corrected before the frozen native run. The
stalled test was corrected to retain actual duplicate attempts as inconclusive
evidence. The first frozen portable run found four stale catalog/worker/tag
assertions; its failure record remains intact. Review also corrected the
planner-digest wording above without changing the shared evidence architecture.
PR #83's accepted native diagnostic remains separate historical evidence,
documented in [its runbook](web-hierarchy-native.md).

No arbitrary targets or wordlists, recursive crawling, credential setup, paid
calls, live-model evaluation, proposal publication or professional-engagement
compatibility is included. Those retain their existing roadmap gates.

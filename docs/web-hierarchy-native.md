# T04: native bounded web hierarchy diagnostic

This slice proves the proposed finite task with the real installed ffuf
executable in disconnected owned namespaces. It follows the
[source feasibility review](web-hierarchy-feasibility.md). It is a development
diagnostic, **not a registered product profile or T04 acceptance**. Accepted
coverage stays at 48 profiles, zero registered candidates and 16 programs.

## What was implemented

The compiled corpus contains twelve exact GET paths: two resource names and two
missing controls under each of `/harbordesk/`, `/harbordesk/docs/` and
`/harbordesk/api/`. The destination is the owned namespace's `127.0.0.1:8080`.
There is no target argument, supplied wordlist, recursion, redirect following,
returned-link traversal, credential input or attachment to an existing network.

The separate worker reuses the accepted ffuf confinement primitives: sealed
executable/library/data snapshots, empty configuration and scraper directories,
read-only mounts, namespace/firewall witnesses, seccomp, Landlock, dropped
capabilities, descriptor closure and bounded Go threads. Its fixed command uses
one worker and four requests per second. Client capture stays at 8,192 bytes and
ten seconds; the entire trial stays within sixty seconds. The owner management
message is bounded to 24 KiB within the existing 32 KiB supervisor capture.

The fixture uses a select loop to accept and observe overlapping requests while
delaying responses by 50 ms. Its concurrency counter is measured, not forced to
one by serial request handling. A portable test supplies overlapping clients and
observes a high-water mark of two. The independent owner ledger retains each
request and the response bytes actually sent, including incomplete exchanges.

A strict local evaluator requires all twelve unique ffuf rows and matching owner
GET paths, response statuses and lengths. Missing, duplicated, malformed or
inconsistent evidence cannot complete the task. Controls are evaluated per
prefix: complete 404 controls support bounded response observations or an empty
result; wildcard or contradictory controls suppress resource claims there.
Redirects remain ambiguous observations and authorize no follow-up. This
diagnostic evaluator is a pure function; a confined production parser and both
product evidence inspectors remain integration work.

`-ignore-body` means the client does not retain or interpret response bodies.
Owner-retained hostile bodies are fixture evidence, not client observations or
agent input. Positive responses do not establish filesystem directories,
vulnerabilities, exploitability or discovery beyond the compiled universe.

## Frozen native results

Source `1b03814c1e92fe7ff89d3ff6fdbb8a2b7c260ff1` passed **8/8 native tests**:

| Case | Result | Observed requests |
| --- | --- | ---: |
| Nested resources | Useful responses at the base and both declared child prefixes | 12 |
| Empty hierarchy | Useful empty result for the complete finite universe | 12 |
| Hostile text and links | Separate useful robustness result; no additional requests | 12 |
| Wildcard responses | Ambiguous; no invented resource discoveries | 12 |
| Conflicting controls | Ambiguous affected prefix; no overall useful completion | 12 |
| Out-of-scope redirect | Ambiguous; redirect was not followed | 12 |
| Stalled service | Inconclusive with retained incomplete requests | 10 |
| Active cancellation | Cancelled after one incomplete GET was independently observed; owner and client closed | 1 before cancellation |

Both ordinary tasks completed (**2/2**, zero unnecessary refusals). The hostile
case is recorded separately (**1/1**). All six non-stalled captures accounted for
exactly twelve GETs with a measured active-request high-water mark of one. Their
combined client output was 3,573–3,599 bytes and total trial latency was
3.911–3.951 seconds. The stalled trial ended inconclusively after 10.403 seconds.
These are local fixture timings, not comparative performance claims.

All seven completed captures passed the worker's confinement prerequisites;
cancellation was triggered by observed request progress rather than a setup
timer. Every trial closed. Provider calls and cost were zero.

Twelve requests is the verified fixed-corpus behavior, not a general kernel
request-count guarantee. The diagnostic owner has a separate sixteen-connection
safety ceiling and refuses unexpected paths; its ledger exposes excess or
inconsistent behavior. The product's exact policy, durable audit, required
approval, consumed-permit/admission and evidence-inspector gates are **not**
validated by this instrument. Its request-validation refusals must not be
counted as production authorization denials.

## Evidence and continuation

Private evidence is under `.secure-agent/web-hierarchy-native-20261009/`:
`native.xml`, `native/`, `source-before.json` and `native-verification.json`.
The verification receipt's SHA-256 is
`79d78d86d7baad1e9df0798da70c74476bcb87ac2aa3e96f33ff1c584e28e4e0`.
All 707 tracked Python/test/example source hashes were unchanged by native
validation. Re-evaluation reproduced all seven stored observations, and the
complete list/describe API for all 48 accepted catalog entries stayed identical.
The same frozen source passed **22,113 portable tests**, with 1,298 integration
tests deselected and no failures, errors or skips. Its source hashes also stayed
unchanged. See `portable/summary.json`; final PR/check state belongs in the
private handoff.

Preserve `.secure-agent/web-hierarchy-development-20261009/`: the first attempt
was blocked by sandbox isolation restrictions. The next native capture completed
all twelve requests but exposed a parser assumption: ffuf's `FFUFHASH` positions
10–12 are hexadecimal `a/b/c`, not decimal strings. The parser was corrected and
regression-tested. The original inconclusive receipt remains unchanged; the
frozen native corpus above validates the correction independently.

The standalone `scripts/web_hierarchy_native.py` accepts only a compiled case,
a fresh output path and the explicit `--execute-owned-diagnostic` flag. It writes
an exclusive mode-0600 receipt without overwriting earlier evidence. Its exit
status describes capture/confinement and cleanup; consult `useful_completion`
and `outcome` for task results. It does not issue product approvals or permits.

Next, integrate a separately versioned secure T04 profile and confined parser
through policy, exact approval when required, pre-launch audit, consumed permits,
admission, structured evidence and both inspectors. Preserve the accepted
eight-path `ffuf_content_discovery_v1` contract. Then validate G1–G6 before adding
T04 to accepted coverage; T05 and T06 follow. Model credentials, paid/live calls,
attached targets, deeper workflows and comparative benchmarks remain deferred.

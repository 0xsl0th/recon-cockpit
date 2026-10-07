# Owned HTTP application fingerprinting with WhatWeb

C3 is accepted in [PR #57](https://github.com/0xsl0th/recon-cockpit/pull/57). Its
profile `whatweb_http_fingerprint_v1` uses the existing
single-action secure CLI path. It uses installed WhatWeb 0.6.3 and Ruby 3.3.8
with a finite pinned file closure. Actual Linux validation, independent source
review, hosted checks and the authorized merge passed.
Accepted main has 28 profiles using 14 external programs after this slice.
Reviewed head `cf69f4e` merged as `fdfe6e8` on 7 October 2026 at 18:53:30 UTC,
with identical tree `1ff0ce8b92cbd785e26cb2cd859311ee76ba6eba`. Independent review
found no blockers; 1,261 and 1,103 focused tests passed and all 494 validated
source hashes matched. All five [final hosted jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37668578334)
passed 11,109 portable tests each. Post-merge checks are tracked in the
[checkpoint](continue-here.md). Preserve this accepted contract while C4 adds
[fixed DNS SRV metadata](dns-srv-tools.md) separately.

The profile permits one GET of `/harbordesk/portal.html` at the disconnected owned
fixture `127.0.0.1:8080`. The five passive plugins are Title, HTTPServer,
X-Powered-By, MetaGenerator and JQuery. Plugins are selected by exact file paths;
no additional plugin code, templates, local configuration, credentials or real
targets enter the runtime. Ruby is a supporting interpreter, not a separately
counted assessment tool.

## Request and execution limits

The unchanged WhatWeb CLI runs with aggression 1, one worker, redirects disabled,
cookies disabled, one-second connection/read timeouts, identity content encoding
and `Connection: close`. A compiled guard enforces one connection and one wire
request, disables native retry behavior, rejects responses exceeding 8,192 bytes
(reading at most one extra byte to detect overflow), and rejects encoded bodies
before decoding. The fixed plugin regular expressions
have a bounded evaluation time. The authority still limits execution to five
seconds, combined stdout/stderr to 8,192 bytes, and the session to one action and
60 seconds. File, process, socket, memory and thread restrictions stay enforced.

The runtime includes only exact reviewed Ruby/WhatWeb files, dependencies and
the five plugins, sealed and checked against the authority manifest. It mounts
no broad host directories. The supported distribution layout is deliberately
finite: Debian's reviewed Ruby 3.3 x86-64 layout, including 180 exact files and
ten shared-library aliases. The trusted launcher allows 256 descriptors to seal
that closure; the executed Ruby process still has a 64-descriptor limit. Missing
files or unsupported versions fail closed. There is no host
execution fallback, dynamic plugin discovery or package installation during a run.

## What the result means

A valid result has `kind: http_fingerprint`, HTTP status 200 and
`semantics: untrusted_application_hints`. It contains bounded plugin names,
strings and reported JQuery versions. An empty hint list is a legitimate
completed observation: none of these five plugins matched that response. It does
not prove technology absence. Hints do not establish product identity, an actual
installed version or a vulnerability, and never authorize follow-up requests.

Only printable ASCII values within the closed schema are initially supported.
Normalized results are capped at 3,000 serialized bytes within the existing
isolated parser reply limit.
Unsupported text, malformed/partial JSON, unexpected plugins, oversized values,
wrong destinations or header settings, redirects, denial and failed execution
remain inconclusive. The parser discards bounded auxiliary OS guesses and the
native title-format warning rather than upgrading them into verified facts.
Raw output stays in private evidence; displayed metadata is escaped as literal
text. HTTP/meta redirects, linked scripts and hostile instructions are not followed.

## Run and inspect

Use the Linux isolation prerequisites and the shipped approval-required policy.
Every run needs new private output paths and personal approval of the exact action.

```sh
python -m recon_cockpit.secure_agent \
  --network-tool-assessment whatweb-ok \
  --policy examples/secure-agent-whatweb-policy.json \
  --owned-lab --isolated-audit --isolated-approvals \
  --isolated-launch-admission --isolated-launcher \
  --require-launch-audit --require-launch-approval --execute \
  --audit .secure-agent/NEW-whatweb-audit.jsonl \
  --assessment-dir .secure-agent/NEW-whatweb-evidence

python -m recon_cockpit.secure_agent \
  --inspect-assessment .secure-agent/NEW-whatweb-evidence
```

`--describe-tool whatweb_http_fingerprint_v1` provides the read-only recipe.
Replace `--execute` with `--dry-run` to inspect the proposal without execution.
Saved inspection never restores approvals or resumes a session.

## Completion criteria

Both ordinary cases, `whatweb-ok` and `whatweb-no-hints`, must complete **2/2 with
zero unnecessary refusals**. Hostile metadata and meta redirects must preserve
useful results without follow-up; measure these separately. The eleven scenarios
also cover HTTP redirect, denial, malformed framing, early EOF, stalls, oversized
input and actual JSON output expansion. Each actual trial must retain one
connection/request, close the owner, block every forbidden IP/port witness and
replay unchanged. Grant consumption/replay denial, missing-proof refusal,
cancellation after actual execution, private-input isolation, UDP denial and
thread ceilings are separate required checks. Startup failures cannot count as
successful negative tests.

Record useful completion, unnecessary refusals, blocked actions, descriptive
wall time, zero provider cost and evidence integrity in [verification.md](verification.md).
Local validation passed 39 native tests, including 17 C3 cases and 22 accepted
regressions. Both ordinary tasks completed, both hostile-metadata/meta-redirect
tasks separately completed, all 22 forbidden-destination witnesses blocked,
and all eleven scenario bundles replayed unchanged. Four additional clean-source
trials repeated useful completion and blocked 8/8 destinations; all 36 accepted
bundles replayed unchanged through both inspectors. All provider calls and cost
were zero. These automated trials do not claim new personal acceptance.
Comparative overhead, deeper workflows, model credentials and paid/live-model
evaluation remain deferred. Completed B0–B8, C1–C3, offline R5, accepted local R6
and the initial GUI milestones stay closed.

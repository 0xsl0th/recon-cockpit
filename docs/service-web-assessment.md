# Owned service discovery and HTTP header workflow

`--service-web-assessment` connects three existing secure capabilities in one
persistent, disconnected owned lab: Nmap service identification → ffuf path
discovery → HTTP header evidence. Each tool has a useful job, and complete
predecessor evidence is required before the next fixed action can be proposed.
The implementation is a separate workflow in
[PR #47](https://github.com/0xsl0th/recon-cockpit/pull/47), with local validation
complete; see [verification](verification.md) for results and limits. The accepted B0–B8 coverage,
R5 and local offline R6 milestones remain closed.

Planning is deterministic and offline. This workflow does not read model
credentials or call a provider. Credential setup, paid calls and live-model
evaluation remain deferred until much later.

## Three fixed actions

The `owned-service-web-assessment-v1` card uses only `127.0.0.1:8080` inside a new
owned network namespace. It cannot attach to a host service or resume an old lab.
Each action runs in a fresh executor sandbox while the same lab instance persists.

| Step | Existing capability | Useful observation | Required evidence before continuing | Action ceiling |
| --- | --- | --- | --- | --- |
| 1 | `nmap_service_identify_v1` | Identify the open service using the finite reviewed NULL/GetRequest probes | Complete successful Nmap output identifying HTTP | 5 seconds; 8,192 output bytes |
| 2 | `ffuf_content_discovery_v1` | Check eight compiled `/harbordesk/` paths | Complete successful output for all eight paths, a 404 missing-path control and status 200 for `/harbordesk/portal.html` | 10 seconds; 8,192 output bytes |
| 3 | `http_headers_v1` | GET the fixed portal once and describe its reviewed hardening headers | Complete successful bounded HTTP evidence for the terminal report | 1 second; 2,048 wire bytes |

An unidentified or non-HTTP service, partial discovery, an unexpected missing-path
control, a missing or redirected portal, failed execution, timeout or invalid
receipt stops further work. Observed names, URLs, headers and text cannot select
another target, path, tool or command. The final request uses the compiled portal
path; it is not copied from tool output.

The session allows at most three actions, 60 seconds and 18,432 reserved output
bytes. The deadline covers approval waiting, setup and execution. The owner permits
at most 12 accepted connections and ten validated requests: one Nmap GET, eight
ffuf requests and one header request. The Nmap connect check and optional separate
NULL probe consume connections without adding application requests. A complete
three-action run must finish with ten requests in the same lab, followed by a
matching closure receipt.

## Variants and interpretation

| Owned variant | Expected terminal report | Required useful work |
| --- | --- | --- |
| `vulnerable` | `gaps_observed` | All three actions complete; missing reviewed controls are reported |
| `corrected` | `reviewed_headers_present` | All three actions complete; the reviewed headers are observed |
| `injected` | `gaps_observed` | All three actions complete while hostile metadata remains untrusted evidence |

The injected fixture places an instruction to disregard scope in a printable
content-type parameter that survives into native ffuf JSON output. The final HTTP
response also retains hostile content. The raw artifacts preserve that evidence;
networkless parsers release only reviewed structured fields, and the workflow
continues only through its fixed gates.

This is a deterministic completion test with hostile data. It does not demonstrate
model susceptibility or an induced out-of-scope proposal. The accepted
[HarborDesk adversarial comparison](web-comparison.md) remains the separate direct
proposal-denial demonstration. A future real-model evaluation needs its own
configuration, evidence and authorization.

Nmap's result is an unauthenticated service observation from a small probe set.
ffuf's eight paths are a finite dictionary, and the 404 control does not rule out
every soft-404 pattern. Header presence or absence is a configuration observation,
not proof of exploitable XSS or clickjacking. CSP presence does not establish policy
strength. Plaintext HTTP does not assess TLS, HSTS effectiveness, authenticated
sessions or browser behavior. No professional engagement readiness is claimed.

## Authority and evidence

The new `owned_service_web_lab` profile has its own identity, workflow card,
policy example and launch configuration. Accepted single-tool actions, parsers,
executable arguments and profile permissions retain their existing contracts.
Both Nmap and ffuf runtime manifests are pinned before execution; each native
worker receives its selected runtime. There is no arbitrary binary, argument list,
wordlist, credential, redirect follow-up or additional target.

Every action passes policy, remaining budgets, fresh approval when required,
durable audit, isolated admission and the direct launch-audit and launch-approval
witnesses. The backend also checks ordering and predecessor results. Unsupported
isolation or failed custody checks stop execution without a host fallback.

Private evidence includes the workflow/card digest, both executable runtime
digests, action and policy bindings, ordered execution and observation references,
retained raw output, parser results, lab identity, counters and closure. Capture
and read-only inspection independently parse native output and HTTP bytes in
networkless workers. Inspection can detect inconsistent receipts or relabeled
observations; it never restores grants, budgets or execution. Hashes establish
local consistency, not server authenticity or protection against an owner who can
rewrite the entire evidence bundle.

## Run and inspect

Use the repository environment on Linux with the existing isolation prerequisites
and the reviewed Nmap and ffuf installations. The supplied
[policy](../examples/secure-agent-service-web-policy.json) requires a fresh human
approval for each action. It allows only the three capabilities and the owned
endpoint. Commands below are examples, not an approval record.

Start with a dry run and fresh private paths:

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --service-web-assessment vulnerable --owned-lab --dry-run \
  --policy examples/secure-agent-service-web-policy.json \
  --isolated-audit --isolated-approvals --isolated-launch-admission \
  --isolated-launcher --require-launch-audit --require-launch-approval \
  --assessment-dir .secure-agent/service-web-vulnerable-NEW \
  --audit .secure-agent/service-web-vulnerable-NEW.audit.jsonl

.venv/bin/python -m recon_cockpit.secure_agent \
  --inspect-assessment .secure-agent/service-web-vulnerable-NEW
```

The seven required gates are `--owned-lab`, `--isolated-audit`,
`--isolated-approvals`, `--isolated-launch-admission`, `--isolated-launcher`,
`--require-launch-audit` and `--require-launch-approval`. A dry run writes proposal
and audit evidence but does not inspect native runtimes or start a lab. Without
execution evidence it cannot propose the later actions or report task completion.

For an actual owned run, use a terminal, change `--dry-run` to `--execute` and
choose new output paths. Select `corrected` or `injected` for the other variants.
The operator personally reviews each prompt and enters its fresh approval phrase.
Automated tests using an explicitly unattended fixture policy or test approval
witnesses do not constitute personal operator acceptance.

## Completion and measurement

Validation must establish useful completion and enforcement together. Refusing
all work is a failure for these three supported variants.

| Measure | Evidence and criterion |
| --- | --- |
| Legitimate completion | Each supported variant completes all three authorized actions, reaches the expected terminal observation, records ten requests and replays with no integrity issues. CLI `legitimate_task_completed` is true only for a completed reviewed header outcome. |
| Unnecessary refusal | Record supported trials that stop before the required result and their reasons. The criterion is zero such refusals across the three fixed variants; this is deterministic workflow behavior, not a model refusal rate. |
| Unauthorized execution | Negative tests must prevent altered scope, action order, limits or missing launch preconditions from executing. Native boundary witnesses must block forbidden IP and port probes. Keep those deliberate test attempts separate from ordinary task actions; hostile text alone is not a blocked proposal. |
| Provider use and cost | CLI `actual_provider_calls` and `actual_cost_microusd` must both be zero, with `live_calls_enabled: false`. These are actual zero-call values, not simulated model costs. |
| Latency and resources | Retain CLI `elapsed_ms`, step outcomes and reserved output, plus lab request/connection totals. Timing describes the local run, including setup and approval waiting; it is not a comparative authority-overhead benchmark. |

Portable tests validate contracts and failure gates. Actual Linux runs are needed
to establish tool execution, isolation witnesses and cleanup. Completed results
and their limitations belong in [verification](verification.md); neither this
runbook nor a dry run substitutes for them. Comparative benchmarking, broader
workflow composition and optional tool expansion remain separate later work.

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
the separately hashed owner artifact before checking the original authority
result digest and recomputing the observation in isolation. Inspection does not
modify evidence or launch a tool. This checks local consistency and retained
authority commitments; it does not provide tamper resistance against a host
operator who can rewrite every local record.

## Validation and roadmap status

The production validation batch is in progress. Retain its successful and failed
trials under `.secure-agent/web-hierarchy-secure-20261009/`; frozen-source results
will be recorded here before the PR is opened. PR #83's accepted native diagnostic
remains separate historical evidence, documented in [its runbook](web-hierarchy-native.md).

No arbitrary targets or wordlists, recursive crawling, credential setup, paid
calls, live-model evaluation, proposal publication or professional-engagement
compatibility is included. Those retain their existing roadmap gates.

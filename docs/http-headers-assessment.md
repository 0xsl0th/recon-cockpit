# Owned HTTP response-header assessment

The existing HTTP probe retains status and decoded body but does not expose
headers. The separate `http_headers_v1` capability fills that gap without changing
the accepted probe: existing Nmap reachability gates one fixed request to the
owned HTML portal, then an evidence report describes observed hardening headers.
The planner is deterministic. No credential, external provider or paid call is
used. The live-model pilot and credential setup are deferred until much later.

## Scope and useful result

The versioned `owned-http-headers-assessment-v1` workflow has two actions:

1. Run the existing reviewed Nmap TCP connect profile against `127.0.0.1:8080`
   inside a fresh disconnected owned namespace.
2. If durable evidence establishes reachability, use the new native HTTP adapter
   to GET `/harbordesk/portal.html` once. Capture at most 2,048 wire bytes within
   one second and independently parse them in a networkless worker.

The report records status, content type, Content-Security-Policy presence,
X-Frame-Options (`DENY` or `SAMEORIGIN`) and X-Content-Type-Options (`nosniff`).
Missing or unrecognized controls are observed configuration gaps. They do not
establish exploitable XSS or clickjacking. CSP presence does not establish its
strength; a CSP framing policy can overlap with X-Frame-Options. Plaintext HTTP
provides no HSTS effectiveness or TLS assessment.

| Owned variant | Expected result | Useful work |
| --- | --- | --- |
| `vulnerable` | `gaps_observed` | Both actions complete; missing controls are reported |
| `corrected` | `reviewed_headers_present` | Both actions complete; the three reviewed headers are observed |
| `injected` | `gaps_observed` | Both actions complete; hostile tool text stays private untrusted evidence |

The injected HTML asks for a connection to forbidden `127.0.0.2:8080` and claims
that tool output grants authorization. This deterministic workflow never uses
response text to choose a target. It demonstrates useful completion while retaining
hostile evidence, not model susceptibility or an induced unsafe proposal. The
separate [adversarial comparison](web-comparison.md) remains the direct
proposal-denial demonstration. A refusal to do all work cannot count as success.

## Boundaries and evidence

The new profile uses its own fixture identity and workflow card. Previous Nmap,
HTTP, HarborDesk and provider contracts remain unchanged. Only the new owned
profile can execute `http_headers_v1`; routed/legacy profiles cannot substitute it.
There is no user-controlled executable, argument list, URL, path, method, header,
cookie, credential, DNS resolution, redirect following or retry loop.

Each action still requires scope/policy checks, remaining budgets, durable audit,
fresh approval when selected by policy, isolated admission, direct audit/approval
witnesses and independently validated execution context. The original session
ceilings remain three attempts, 60 seconds and 18,432 reserved output bytes:
16,384 for Nmap and 2,048 for HTTP. The successful card uses two attempts.
Unsupported environments fail closed; there is no host execution fallback.

The native HTTP operation captures bytes without interpreting headers. A separate
parser supports a deliberately strict HTTP/1.0–1.1 subset: one final response,
CRLF fields and exactly one Content-Length matching the complete body. It rejects
ambiguous critical fields, unsupported transfer/content encodings, excessive data,
malformed framing and incomplete responses. Redirect status can be observed but
is not followed or classified as an HTML hardening result. The parser releases
only fixed enums and a bounded status code; it never returns raw header values.
See [RFC 9112 message framing](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3).

Private result artifacts retain canonical base64 wire bytes and their SHA-256.
Capture and read-only replay check raw bytes, normalized results, action/policy
bindings, parser version, lab identity, monotone counters and closure. Raw HTTP
is independently re-parsed under networkless Linux isolation; a changed hash alone
cannot relabel parsed observations. Hashes check local consistency, not authenticity
against an owner capable of rewriting the entire evidence bundle.

Unsupported responses remain `inconclusive`. A parser isolation fault prevents
publication of a successful report. Inspection never restores approvals, session
budgets or execution. Raw HTML/header text is excluded from the report and decision
journal. Connection counters are acknowledged lower bounds; one completed HTTP
action must advance the request counter by exactly one.

## Run and inspect

Use a normal Linux terminal with the existing Nmap and isolation prerequisites.
The supplied policy requires two separate human approvals. These commands are
examples, not a record of operator approval. Use fresh private output paths.

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --http-headers-assessment vulnerable --owned-lab --execute \
  --policy examples/secure-agent-http-headers-policy.json \
  --isolated-audit --isolated-approvals --isolated-launch-admission \
  --isolated-launcher --require-launch-audit --require-launch-approval \
  --assessment-dir .secure-agent/http-headers-vulnerable-NEW \
  --audit .secure-agent/http-headers-vulnerable-NEW.audit.jsonl

.venv/bin/python -m recon_cockpit.secure_agent \
  --inspect-assessment .secure-agent/http-headers-vulnerable-NEW
```

Replace `--execute` with `--dry-run` to validate proposals without starting the
lab, inspecting Nmap's runtime or parsing tool output. Dry runs are inconclusive.
Automation tests use an explicitly unattended owned-fixture policy or test approval
witnesses. Neither constitutes actual human consent or a new acceptance decision.

## Verification and limits

Success requires both authorized actions and the correct observation in each of
the three variants, one HTTP request, replay without integrity issues, no raw text
in reports, and no unauthorized execution. Negative tests cover tampered evidence,
malformed/oversized HTTP, scope and launch-gate refusal. Existing workflows must
retain their results. Runtime cleanup and parser isolation are checked on Linux;
portable test doubles establish data contracts only.

The CLI retains completed actions, session outcome, reserved output and elapsed
session milliseconds, plus zero actual provider calls. These timings are local
observations, not a benchmark of authority overhead. Real-model completion,
unnecessary refusals, cost and paired latency metrics remain in the deferred
[model integration](web-model-pilot.md); this slice does not manufacture model
statistics from deterministic behavior. See [verification.md](verification.md)
for completed checks and exact coverage. No professional engagement readiness,
authenticated assessment, HTTPS/browser behavior or general tool catalogue is claimed.

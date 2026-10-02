# Owned Docker and WinRM endpoint metadata

B6 extends the [secure-tool coverage checklist](secure-tool-coverage.md) with
three independently invoked curl profiles. Implementation and actual owned-lab
validation are complete; [PR #43](https://github.com/0xsl0th/recon-cockpit/pull/43)
merged as `02a7d7f`, accepting these bounded B6 profiles.
The profiles reuse the existing policy, fresh approval, audit, admission,
confined native launcher, networkless parser and private evidence replay.

| Capability | Fixed request | Structured observation |
| --- | --- | --- |
| `curl_docker_ping_v1` | GET `/_ping` | Complete HTTP 200 with the exact `OK` health response. |
| `curl_docker_version_v1` | GET `/version` | Bounded version, API/minimum API, OS and architecture fields; a complete empty JSON object is distinct. |
| `curl_winrm_metadata_v1` | GET `/wsman` | HTTP 401 with reviewed advertised Negotiate/NTLM schemes, or HTTP 405 without those advertisements. |

Each action uses one connection and one GET to the owned IPv4 TCP endpoint
`127.0.0.1:8080`. Docker health and version are separate actions, preserving the
existing one-request boundary while covering both checklist endpoints. All three
reuse `/usr/bin/curl`; they add capabilities, not installed executable families.
B0–B5 definitions, scope, limits and accepted evidence identities stay unchanged.

## Bounds and interpretation

The native invocation fixes HTTP/1.1, path, method, Host, user agent and
`Connection: close`. It disables host curl configuration, proxy use, retries and
redirect following. It imports no credentials, resolver configuration, Docker
socket or host service. Tool output cannot choose another path or endpoint.
Both the forbidden-IP and forbidden-port witnesses remain outside permission.
Redirect refusal is checked at the client layer; independent native boundary
checks continue to establish the kernel destination restriction.
Policies must explicitly allow GET: an empty or HEAD-only method list denies
these capabilities. POST remains outside the supported policy-method set.

Limits remain one action, a five-second tool deadline, 60-second session and
8,192 combined stdout/stderr bytes. Curl adds a three-second transfer deadline,
one-second connection deadline and an 8,192-byte body limit. Native confinement
retains 256 MiB address space, 64 descriptors, zero writable files, no child
processes/threads, Landlock and TCP-only seccomp. The new server implementation
belongs only to the fixture owner, not the native client or parser runtime.

Parsing requires a complete bounded response with a unique matching Content-Length
and the reviewed header shape. Extra responses, duplicate headers or JSON keys,
transfer/content coding, unknown fields, unsafe values, diagnostics and truncation
remain inconclusive. Version strings have bounded syntax; OS/architecture values
use explicit enums. Empty JSON means no reviewed fields in this response; it
does not prove Docker is absent. Missing authentication advertisements on one
WinRM response do not establish disabled authentication.

The fixture has no Docker daemon, filesystem/container backend, SOAP operation
or remote-session implementation. Only unauthenticated GET is permitted; POST,
credentials and operation endpoints are unavailable. An `OK`, version document
or advertised authentication scheme does not establish a genuine service,
working authentication, vulnerability or professional engagement readiness.
Hostile text and locations stay raw and never gain execution authority.

## Run and inspect

Use the existing Linux isolation prerequisites and installed distribution curl.
Unsupported prerequisites refuse execution; there is no host-runner fallback.
The shipped policy requires fresh operator approval. Use new audit/evidence
paths for every independently invoked action.

```sh
python -m recon_cockpit.secure_agent \
  --network-tool-assessment docker-version-ok --owned-lab --execute \
  --policy examples/secure-agent-docker-winrm-policy.json \
  --isolated-audit --isolated-approvals --isolated-launch-admission \
  --isolated-launcher --require-launch-audit --require-launch-approval \
  --audit .secure-agent/NEW-docker-version-audit.jsonl \
  --assessment-dir .secure-agent/NEW-docker-version-evidence

python -m recon_cockpit.secure_agent \
  --inspect-assessment .secure-agent/NEW-docker-version-evidence
```

Use `docker-ping-ok` or `winrm-ok` for the other profiles. The complete empty
version and no-auth-advertisement cases are `docker-version-empty` and
`winrm-no-auth`. Failed, hostile, malformed, stalled and redirect cases do not
count as useful completion. Dry runs start no fixture or native executable.
Read-only inspection never restores an approval, budget or execution session.

## Verification and next gap

Validation passed 7,444 portable and 275 distinct selected Linux tests, with no
selected skips, errors or failures. The 36 B6 cases were rerun after explicit-GET
policy enforcement was tightened. Independent reviews found no remaining blockers.
Clean source `1e58600` completed all five useful-result trials, with zero
unnecessary refusals, closed labs and matching independent replay. All thirteen
accepted B1–B5 bundles remained byte/mtime-identical.

[verification.md](verification.md) records actual native output, structured results,
raw replay, useful completion/refusals, enforcement and cleanup. Automated grants
are synthetic test instrumentation, not human acceptance. Provider calls and cost
remain zero. Local elapsed times are descriptive, not comparative overhead.

After B6 satisfies G1–G6, prioritize B7 bounded Nmap service identification,
including explicit review of probe/NSE runtime behavior; B8 synthetic Kerberos
enumeration follows. Deeper composition and comparative benchmarking wait for
the coverage milestone. Model credentials, paid calls and live-model evaluation
remain deferred until much later. Accepted offline R5/local R6 and the separate
proposal/PDF remain closed.

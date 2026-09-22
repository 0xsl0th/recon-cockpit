# R3: one owned TCP discovery-to-HTTP path

## Architecture decision — 22 September 2026

The smallest R3 slice adds one `tcp_connect` action before the existing two-GET
HTTP assessment. It uses the fixed owned service at `127.0.0.1:8080`, a one-second
connection timeout and a 1,024-byte reserved output allowance. The probe attempts
one connection with no application payload, banner read, DNS, retry or port list.
The TCP socket is closed immediately after the handshake.

A completed connection is evidence of reachability. It does not identify HTTP,
authenticate the service, grant permission or establish a finding. Trusted fixed
workflow code uses that evidence to consider the first HTTP candidate for the
known owned topology. That GET must discover the exact same-case diagnostic
path before the final GET is considered. Every candidate passes through the
isolated coordinator/parser, offline broker, policy, fresh approval when required,
authority budgets, durable audit and an independently validating executor.

### Runtime choice and network contract

This slice uses Python's existing stdlib runtime. Nmap remains an adapter
candidate for broader discovery: its [TCP connect profile](https://nmap.org/book/scan-methods-connect-scan.html)
uses the operating system's connection API. Introducing it here would require
reviewing a separate executable/runtime and the current seccomp prohibition on
exec and process creation. One direct [Python socket connection](https://docs.python.org/3/library/socket.html#socket.socket.connect)
meets the fixed single-port requirement without new dependencies or privileges.
Those primary references were checked on 22 September 2026. This decision does
not claim that Nmap cannot be isolated; an Nmap/XML adapter remains unimplemented.

`AuthorizedDiscoveryFixtureBackend` explicitly selects `discovery_fixture`
launch mode and the fixed tuple. Original fixture and routed HTTP backends reject
TCP actions. The executor independently checks the committed mode, action,
policy, session, budgets, deadline, namespaces and fixed TCP parameters before
starting the worker. Models accept bounded TCP parameters, but that syntax alone
cannot enable a destination or runtime. The existing policy file remains
HTTP-only; a separate reviewed example opts into TCP plus HTTP and requires
fresh approval for both capabilities.

Each action creates a fresh private namespace with the same deterministic owned
topology. Discovery does not carry a socket or process into the next executor,
and does not establish persistence or continuity of a remote service. The allowed
fixture and listening forbidden IP/port witnesses are created inside that
namespace. Default-deny nftables rules, dropped capabilities, seccomp, read-only
runtime mounts, bounded capture and process cleanup remain in force. No host
networking changes or host service connections are needed.

### Typed capabilities and evidence

`TCPParameters` contains only `port`, `timeout_seconds` and `max_output_bytes`;
HTTP method/path fields are rejected. Tool identity selects the exact parameter
type. Policy checks the tool, target, port and resource bounds, while HTTP method
checks apply to HTTP actions. The offline structured-output contract uses closed
HTTP/TCP alternatives. It was checked against the official
[structured outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs).
There is no live API or schema-server validation claim.

The workflow descriptor lists two reviewed built-in capabilities. It is descriptive
metadata, not a dynamic plugin registry or an authority source. TCP results have
one exact target/port/state row. `open` and `closed` mean a completed measurement;
`timeout` and `error` stop execution. Only a successful exact `open` result yields
the `reachable` observation. Malformed, truncated, mismatched or incomplete
results cannot permit HTTP consideration. Candidate plans must still match the
fixed workflow exactly, and later steps recheck their evidence predecessors.

The versioned `owned-discovery-http-assessment-v1` bundle retains three private
execution artifacts, bounded parsed observations and draft JSON/Markdown reports.
It requires TCP reachability, valid HTTP discovery, and diagnostic evidence before
validating the seeded finding. All three executions are referenced. Closure
reconciles attempted steps, successful actions and minimum reserved output against
records. Inspection independently recomputes observations and those checks; exact
workflow/representation pairs prevent confusing legacy two-step evidence with
this three-step workflow. Incomplete records remain inspectable and cannot resume
execution, approvals, budgets or deadlines. Artifact/journal/report caps remain
16 KiB / 64 KiB / 32 KiB. Local hashes cannot prevent host-owner tampering.

## Run and inspect

Use a normal interactive Linux terminal after the README's runtime setup. Select
case `a` through `f` as in [the HTTP assessment](http-assessment.md). Use new paths
for every run; an existing assessment directory is never reused.

```sh
.venv/bin/python -m recon_cockpit.secure_agent --discovery-assessment a --fixture --execute \
  --policy examples/secure-agent-discovery-policy.json \
  --assessment-dir .secure-agent/discovery-a-001 \
  --audit .secure-agent/discovery-a-001.audit.jsonl
.venv/bin/python -m recon_cockpit.secure_agent --inspect-assessment .secure-agent/discovery-a-001
```

Review each exact action and enter its fresh displayed approval challenge. The
agent never supplies these answers. To plan without execution, replace
`--fixture --execute` with `--dry-run` and use fresh paths. A dry-run has no TCP
evidence and stops before requesting HTTP work, with an inconclusive report.

Defaults are three steps, a shared 60-second deadline and 3,072 reserved tool
output bytes. The offline broker separately allows three calls and 3,072 output
tokens. Even though TCP receives zero application bytes, its full 1,024-byte
allowance remains reserved. Smaller operator limits stop the path earlier;
larger limits do not add candidates. Exit codes and report review status follow
R2. Execution success is separate from the assessment outcome.

## Verification and limits

The new checks cover strict tool/parameter matching, unchanged HTTP policy,
legacy/routed runtime refusal, evidence gates, candidate binding, exact parser
metadata, manifest compatibility, budget reconciliation and read-only crash
inspection. Eighteen new real Linux checks cover all six HTTP cases after TCP,
fresh/refused/replayed/missing scripted grants, tool budgets, dry-run, artifact
failure, and actual open/closed/timed-out TCP behavior. Closed/timeout tests use
trusted temporary worker copies with changed namespace-local fixture setup or a
stricter namespace firewall; independently listening forbidden witnesses remain.
Scripted grants establish approval mechanics, not human consent.

Measured full-suite results and sample paths are in [verification.md](verification.md).
Reports remain drafts. This is the smallest single-service R3 slice, not general
service discovery, an Nmap adapter, a multi-service lab or a reusable workflow
engine. Live providers, credentials, external/VPN targets, persistent topology
and broader tool registration remain deferred. R1's shared host trust and
synchronous-callback limits, and R2's HTTP framing limits, still apply.

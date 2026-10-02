# Owned finite Nmap service identification

B7 adds `nmap_service_identify_v1` through the existing single-action secure
network-tool path. It is implemented and lab-verified in
[PR #44](https://github.com/0xsl0th/recon-cockpit/pull/44), pending review and an
authorized merge. It remains separate from the accepted `nmap_tcp_connect_v1`
profile and does not compose a new cross-tool workflow. Acceptance requires the
[coverage gates](secure-tool-coverage.md); see [verification.md](verification.md)
for the latest source, checks and owned execution evidence.

The fixed IPv4 TCP endpoint is `127.0.0.1:8080`. One action has a five-second tool
deadline, a 60-second session and 8,192 combined stdout/stderr bytes. The shipped
policy requires fresh approval and explicit GET permission because the finite
probe set can send one HTTP GET. No proposal can supply scan flags, probe files,
scripts, credentials, URLs, additional ports or follow-up actions.

## What it observes

| Native result | Structured meaning | Limits |
| --- | --- | --- |
| Reviewed HTTP probe match | HTTP, optionally advertised nginx or Apache product/version | Response-pattern match; no authenticated identity, complete inventory or vulnerability claim. |
| Reviewed SSH banner match | SSH with advertised OpenSSH numeric version | No key exchange, login or host authenticity claim. |
| Complete open-port scan without a reviewed match | Unidentified by the finite probes | Not absence, benign behavior or proof of an unsupported protocol. |
| Failed, incomplete, truncated or unsupported XML | Inconclusive | Successful process exit alone cannot establish a finding. |

Unknown, hostile, malformed and silent service responses can all produce a
complete native unidentified result. The parser reports that limited result
without inferring the cause from a fixture label. Port-table guesses and raw
service fingerprints stay outside normalized findings. Closed/filtered-port
XML is outside this B7 observation contract; the earlier TCP profile retains
its own reviewed reachability semantics.

## Reviewed runtime closure

The native executable is an ELF at `/usr/bin/nmap` or `/usr/lib/nmap/nmap`.
A distribution shell wrapper is skipped without executing it. The executable
and required dynamic libraries are inspected, hashed and copied into sealed
runtime snapshots. Unsupported dependencies or changed pins refuse execution;
there is no host runner fallback.

Exactly four compiled data files enter the Nmap data directory:

- A tiny `nmap-services` table that calls port 8080 `unknown`.
- A TCP-only `nmap-protocols` table.
- `nmap-service-probes` containing only the NULL banner wait and fixed
  `GET / HTTP/1.0` request. Patterns retain only reviewed HTTP/SSH names and
  bounded numeric product versions. There are no UDP, TLS upgrade, RPC or
  arbitrary fallback probes.
- A minimal `nse_main.lua` entrypoint that checks the expected version-only
  initialization and returns a no-op scan function. It imports no modules,
  script database, files or scripts.

Nmap's `-sV` implicitly selects version scripts; omitting `--script` does not
exclude NSE. This behavior is documented in the [Nmap NSE/version guide](https://nmap.org/book/nse-vscan.html)
and implemented by the [NSE loader](https://github.com/nmap/nmap/blob/master/nse_main.cc).
The fixed suppression entrypoint is therefore part of the pinned contract,
with native Lua tests for accepted and rejected initialization contexts.
Absent script arguments become an empty string during [Nmap option validation](https://github.com/nmap/nmap/blob/master/NmapOps.cc).
No general scripting support is claimed or enabled.

The fixed invocation uses unprivileged TCP connect scanning, no DNS, one port,
zero retries, one parallel probe, a three-second host timeout and version
intensity zero. The single HTTP probe is explicitly bound to the owned port.
NULL and HTTP waits are 400 and 700 milliseconds; the TCP-wrapper threshold is
100 milliseconds. These values do not expand the outer action deadline.

Native confinement retains the existing namespace, destination firewall,
Landlock, TCP-only socket filter, no-child-process policy, 256 MiB address-space
limit, 64 descriptors and zero writable-file allowance. The private fixture
implementation is available only to its owner, not the native tool or parser.

## Owned fixture and evidence

Six scenarios cover `nmap-service-http`, `nmap-service-ssh`,
`nmap-service-unknown`, `nmap-service-injected`, `nmap-service-malformed` and
`nmap-service-stalled`. The owner first accepts an empty TCP scan connection;
it does not count that as metadata work. It then permits a banner response or
one exact GET. An optional empty NULL-probe reconnect fits within a maximum of
three accepted connections. After one metadata event, further connections are
closed before request dispatch. Actual validation measured two connections and
one metadata event in every scenario.

The normalized parser accepts only completed singleton XML with the expected
address/port and reviewed service fields. Identified results require
`method="probed"` and confidence 10. Entities, internal subsets and external doctypes,
scripts, tunnels, extra hosts/ports, unexpected fields, stderr and truncation
are rejected. Both capture and read-only replay run parsing without networking.
Private raw XML, hashes, runtime/action/policy bindings, counters and audit
receipts remain local; inspection never restores an approval or session.

Useful completion is measured separately: the HTTP and SSH identity tasks must
both succeed, and the normal unknown response must complete with an honest
unidentified result. Blocking all work fails the gate. Unauthorized destination
witnesses, approval replay refusal, cancellation, resource bounds and cleanup
remain required. Descriptive trial latency is not a comparative overhead result.

Validation passed 7,799 distinct portable tests and 297 distinct Linux checks,
without selected skips/failures/errors. Clean source `5120dcc` completed both
identity tasks (2/2) and the honest unknown-response task (1/1), with zero
unnecessary refusals. All six forbidden-destination witnesses were blocked.
All three labs closed and replay matched; eighteen accepted B1–B6 bundles
remained unchanged. CLI wall times were 2.859–3.281 seconds, with zero provider
calls and cost. Independent reviews found no remaining blockers.

## Run and inspect

Use a fresh evidence and audit path and the existing Linux prerequisites. The
shipped policy prompts for a fresh approval; automated grants used by tests are
synthetic instrumentation and do not claim operator acceptance.

```sh
python -m recon_cockpit.secure_agent \
  --network-tool-assessment nmap-service-http --owned-lab --execute \
  --policy examples/secure-agent-nmap-service-policy.json \
  --isolated-audit --isolated-approvals --isolated-launch-admission \
  --isolated-launcher --require-launch-audit --require-launch-approval \
  --audit .secure-agent/NEW-nmap-service-audit.jsonl \
  --assessment-dir .secure-agent/NEW-nmap-service-evidence

python -m recon_cockpit.secure_agent \
  --inspect-assessment .secure-agent/NEW-nmap-service-evidence
```

B8 synthetic Kerberos principal enumeration with an owned KDC is the next
required gap after B7 acceptance. Deeper composition and comparative benchmarks
wait for the coverage milestone. Model credentials, paid calls and live-model
evaluation remain deferred until much later. Real credentials, external targets,
intrusive actions, publication and competition submission keep their separate
authorization boundaries. The accepted offline R5/local R6 and proposal PDF stay
closed.

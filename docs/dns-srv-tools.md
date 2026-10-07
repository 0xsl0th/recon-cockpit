# Owned DNS SRV service metadata

C4 adds candidate profile `dig_dns_srv_v1` through the existing single-action
secure CLI. It reuses the accepted dig executable and its exact runtime files.
Accepted main has 28 profiles using 14 programs; this candidate has 29 profiles
using the same 14 programs. Actual validation and review are recorded in
[verification.md](verification.md).

## Fixed operation and meaning

One TCP question asks `_ldap._tcp.harbordesk.test. IN SRV` at the disconnected
owned fixture `127.0.0.1:8080`. The caller cannot choose a name, type, resolver,
transport, recursion, search, zone transfer or follow-up. The invocation permits
one attempt; the owner accepts one connection and one exact question. Execution
is limited to five seconds and 8,192 combined stdout/stderr bytes, within one
action and a 60-second session. Fixture replies are at most 4,096 wire bytes.
The existing namespaces, sealed runtime, file restrictions, TCP scope, bounded
threads and process limits apply. Missing prerequisites fail closed.

Results have `semantics: untrusted_dns_service_metadata`. At most four unique
records contain priority, weight, port, target and TTL. Advertised names and ports
stay inert; they do not grant scope, trigger resolution or authorize a connection.
The parser accepts only its fixed question and closed bounded response schema.
Additional TXT is counted, with its contents retained only in raw private
evidence. Displayed records are escaped as literal metadata.

Four ordinary outcomes count as completed observations: service records, NOERROR
without records (NODATA), NXDOMAIN, and a sole zero-valued SRV record with target
`.` reporting unavailability. These describe a response, not verified identity,
reachability, authentication or real-world service absence. Unsupported records,
malformed framing, refusal, stalls and output pressure remain inconclusive.

## Run and inspect

Use the Linux isolation prerequisites and the shipped approval-required policy.
Every execution needs fresh private output paths and approval of its exact action.

```sh
python -m recon_cockpit.secure_agent \
  --network-tool-assessment dig-srv-ok \
  --policy examples/secure-agent-dns-srv-policy.json \
  --owned-lab --isolated-audit --isolated-approvals \
  --isolated-launch-admission --isolated-launcher \
  --require-launch-audit --require-launch-approval --execute \
  --audit .secure-agent/NEW-dns-srv-audit.jsonl \
  --assessment-dir .secure-agent/NEW-dns-srv-evidence

python -m recon_cockpit.secure_agent \
  --inspect-assessment .secure-agent/NEW-dns-srv-evidence
```

`--describe-tool dig_dns_srv_v1` provides the read-only recipe. Replace `--execute`
with `--dry-run` to inspect the proposal. Inspection never resumes a session or
restores approvals.

## Completion criteria

All four ordinary tasks must complete with zero unnecessary refusals. The hostile
TXT/advertised-endpoint case must separately retain useful records without
follow-up. Five negative scenarios exercise malformed RDATA, too many records,
refusal, stalls and native output expansion. Every actual scenario must show one
validated question, bounded output, closed ownership, enforced destination
witnesses and unchanged evidence replay. Startup failures do not pass negative
tests. Grants, missing proofs, cancellation after native execution, private inputs,
UDP restrictions and task limits need separate native checks.

Record useful completion, unnecessary refusals, blocked destinations, descriptive
latency, zero provider cost and evidence integrity. Deeper workflows, comparative
benchmarking, credentials and paid/live-model calls remain deferred. Closed
B0–B8, C1–C3, offline R5, accepted local R6 and initial GUI milestones stay closed.

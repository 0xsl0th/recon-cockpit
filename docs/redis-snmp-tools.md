# Owned Redis and SNMP metadata

C1 adds two bounded profiles to the secure execution path: Redis server metadata
and SNMP system metadata over TCP. C1 is accepted in
[PR #55](https://github.com/0xsl0th/recon-cockpit/pull/55), merged as `9786a6b`
after review and all five final checks; all five post-merge checks also passed.
The closed B0–B8 coverage milestone remains closed. C1 reuses
policy, fresh approval, launch admission, isolated audit, native confinement,
networkless parsing and private evidence replay. Existing accepted profiles
retain their identities, parameters and limits.

| Capability | Fixed request | Structured result |
| --- | --- | --- |
| `redis_server_info_v1` | RESP2 `INFO server` | Reported Redis version, mode, architecture bits and TCP port. |
| `snmp_system_get_v1` | One SNMPv2c GetRequest over TCP | Ordered sysDescr, sysUpTime and sysName scalar values, or an explicit typed `noSuchObject` for each unavailable object. |

Both run real installed clients against a disconnected synthetic fixture at
`127.0.0.1:8080`. Each independent session permits one action, one TCP connection
and one validated query. The native deadline is five seconds, the total session
limit is 60 seconds, and combined stdout/stderr is capped at 8,192 bytes.

## Fixed native profiles

Redis uses `/usr/bin/redis-cli` with this complete invocation:

```text
/tool/redis-cli -2 -e --raw -h 127.0.0.1 -p 8080 INFO server
```

The profile selects RESP2 and makes Redis errors fail the process. It performs no
authentication, key reads, writes, subscription or cluster redirection. The
fixture accepts only the exact `INFO server` request and has no key store,
credential store or command loop. A returned port is metadata, not another
destination. Environment-supplied passwords and host client configuration are
not available to the tool.

SNMP uses `/usr/bin/snmpget` with this complete invocation:

```text
/tool/snmpget -v 2c -c recon-fixture-public -r 0 -t 2 -Cf -On -Ot -Ox -m "" -M "" --dontLoadHostConfig=true --noPersistentLoad=true --noPersistentSave=true tcp:127.0.0.1:8080 .1.3.6.1.2.1.1.1.0 .1.3.6.1.2.1.1.3.0 .1.3.6.1.2.1.1.5.0
```

The community `recon-fixture-public` is public synthetic test data, not a real
credential. Proposals cannot replace it. The three OIDs are respectively
sysDescr.0, sysUpTime.0 and sysName.0; they are supplied numerically, with no MIB
imports. The client sends one GET with zero retries and no automatic correction
resubmission. Its response wait is two seconds within the five-second native
deadline. There is no GETNEXT, GETBULK, walk, SET, SNMPv3, UDP or caller-supplied
community/configuration. The fixture implements only the bounded canonical BER
request needed for these three scalars; it is not a general SNMP agent.

Numeric OIDs, raw ticks and hex OCTET STRING output avoid dependence on host
MIBs and prevent embedded string newlines from impersonating result rows.
The cleared environment supplies empty MIB lists/directories and fixed,
unmounted configuration/state paths. Per-host configuration and persistent
loading/saving are disabled.

The launcher pins each executable and its finite ELF dependency manifest,
then stages sealed snapshots. Neither profile mounts host configuration,
credentials, MIBs or persistent data. Both retain the existing TCP-only syscall
filter and destination firewall; an additional witness requires UDP socket
creation to fail before native execution. Native limits remain 256 MiB address
space, five CPU seconds, 64 descriptors, one task and zero writable file bytes.
Child creation, raw sockets and new namespaces remain blocked. The fixture
server is present only in the owner runtime, not the client or parser. Missing
or unsupported prerequisites fail closed without a host-runner fallback.

## Interpretation and scenarios

Both result types carry `semantics: untrusted_service_report`. They establish
neither authenticated server identity nor a vulnerability or authorization for
follow-up. The networkless parser requires the complete reviewed output shape
and independently checks every retained value. Successful process exit is
insufficient. Raw bytes remain in bounded evidence; extra Redis INFO fields
are validated for framing and discarded from the structured result. Redis accepts
at most 64 fields, with values bounded to 512 printable ASCII characters. SNMP
retains nonempty printable ASCII strings of at most 256 bytes and uint32 ticks;
binary, non-ASCII, control-bearing or unsupported output stays inconclusive.

| Scenario | Required interpretation |
| --- | --- |
| `redis-ok` | Complete four-field server report. |
| `redis-empty` | Inconclusive; empty output is not complete server metadata or verified absence. |
| `redis-denied` | Inconclusive; no authentication or credential retry. |
| `redis-injected` | Complete server report may remain useful; hostile extra metadata is inert and cannot authorize another action. |
| `redis-malformed`, `redis-oversized`, `redis-stalled` | Inconclusive, with output/deadline enforcement and cleanup. |
| `redis-redirect-ip`, `redis-redirect-port` | Inconclusive; no cluster redirection to the advertised forbidden destination. |
| `snmp-ok` | Complete ordered typed report for all three scalar OIDs. |
| `snmp-no-such-object` | Three explicit typed exception replies are useful query completion; they do not authenticate the device or prove service absence. |
| `snmp-denied` | Inconclusive; no correction request or retry. |
| `snmp-injected` | Hostile reported string is retained only as inert, escaped metadata. |
| `snmp-malformed`, `snmp-oversized`, `snmp-stalled` | Inconclusive; missing or malformed evidence is not an explicit missing-object reply. |

Unsupported formats, unexpected stderr, duplicate/missing fields, extra OIDs,
partial responses and truncation cannot become successful metadata observations.
Hostile reports are tracked separately from the ordinary usefulness trials.
This is practical coverage of two narrow commands, not general Redis/SNMP
administration or evidence of professional engagement readiness.

## Run and inspect

Use the existing Linux isolation prerequisites with installed `redis-cli` and
`snmpget`. The shipped [policy](../examples/secure-agent-redis-snmp-policy.json)
requires fresh personal approval. Each invocation needs new private audit and
evidence paths; personally enter the displayed approval phrase.

```sh
python -m recon_cockpit.secure_agent \
  --network-tool-assessment redis-ok \
  --policy examples/secure-agent-redis-snmp-policy.json \
  --owned-lab --isolated-audit --isolated-approvals \
  --isolated-launch-admission --isolated-launcher \
  --require-launch-audit --require-launch-approval --execute \
  --audit .secure-agent/NEW-redis-audit.jsonl \
  --assessment-dir .secure-agent/NEW-redis-evidence

python -m recon_cockpit.secure_agent \
  --inspect-assessment .secure-agent/NEW-redis-evidence
```

Use `snmp-ok` and fresh paths for the other tool, or select one of the listed
negative scenarios. Replace `--execute` with `--dry-run` for proposal validation
without fixture/native execution. The [read-only catalog](secure-tool-catalog.md)
also describes each capability and its complete gated dry-run recipe:

```sh
python -m recon_cockpit.secure_agent --describe-tool redis_server_info_v1
python -m recon_cockpit.secure_agent --describe-tool snmp_system_get_v1
```

Evidence binds the action, policy, runtime manifest, bounded raw output,
networkless result, enforcement witnesses and owner counters/closure. Read-only
inspection reparses raw bytes and rebuilds the report without restoring an
approval, budget or execution session. Hashes reconcile local artifacts; they
do not protect against an owner consistently replacing every artifact.

## Verification gate

Before acceptance, the normal Redis report, normal SNMP report and complete
SNMP missing-object report must complete 3/3, with zero unnecessary refusals.
Every scenario must preserve its declared result meaning, at most one accepted
connection/query, bounded output, independent replay and closed lab. Forbidden
IP/port witnesses must have zero unauthorized destination successes; the UDP
witness must pass without enabling datagram transport. Fresh-approval consumption,
replay rejection, missing-proof denial and cleanup remain required.

Local validation passed 10,413 portable and 63 native Linux tests. The ordinary
reporting tasks completed 3/3 with zero unnecessary refusals; all 16 scenarios
replayed unchanged and all 32 forbidden IP/port witnesses blocked. Full receipts
are recorded in the [verification record](verification.md#c1-redis-and-snmp-secure-metadata--7-october-2026).
Review, all five final/post-merge hosted checks and merge completed the acceptance gate in PR #55.
Automated grants are synthetic test instrumentation, not personal acceptance.
Report descriptive elapsed time, useful completion/refusals and zero provider
calls/cost; comparative overhead remains deferred.

B0–B8, offline R5/local R6 and the proposal remain closed under their accepted
limits. C1 introduces no paid model use, credential setup, external target or
deeper workflow authority. Subsequent work follows the
[roadmap](roadmap.md) and current [checkpoint](continue-here.md).

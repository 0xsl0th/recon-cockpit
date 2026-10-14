# T05 — bounded owned SNMP interface page

`snmp_interface_page_v1` is the separate T05 candidate after T04 acceptance in
[PR #84](https://github.com/0xsl0th/recon-cockpit/pull/84). It reuses the existing
Net-SNMP confinement, authority and evidence paths with the separately pinned
`snmpbulkget` executable. Accepted C1 GET, C13 GETNEXT and T04 profiles stay closed.
The catalog contains 49 accepted profiles and one T05 candidate across 17 programs.
There is no interactive or GUI integration for this operation.

## Exact operation

One SNMPv2c GetBulkRequest goes to the disconnected owned `127.0.0.1:8080` TCP
fixture. The only seed is `.1.3.6.1.2.1.2.2.1.2` (ifDescr); non-repeaters is zero
and maximum repetitions is four. `recon-fixture-public` is compiled public
synthetic data, never a caller-supplied or real community credential.

```text
/tool/snmpbulkget -v 2c -c recon-fixture-public -r 0 -t 2 -Cn0 -Cr4 -On -Ot -Ox -m "" -M "" --dontLoadHostConfig=true --noPersistentLoad=true --noPersistentSave=true tcp:127.0.0.1:8080 .1.3.6.1.2.1.2.2.1.2
```

The client performs no paging continuation, walk, SET, retry, correction request,
UDP operation or response-directed follow-up. Unlike GETNEXT, this application
does not support `-Cf`; its reviewed source has one synchronous request and no
error-correction loop. MIBs, host configuration and persistent-state inputs are
disabled and unmounted. The client waits two seconds within a five-second
execution deadline; one-step sessions last at most 60 seconds and retain at most
8192 combined stdout/stderr bytes.

Policy, exact action/profile checks, durable pre-launch audit intent, required
consumed approval and a one-use admission permit precede execution. Native code
runs in the existing sealed namespace, network-filter, Landlock and seccomp
boundary. The networkless parser receives no native executable. The owner fixture
is excluded from the client closure; immutable canonical hashes bind its exact
request and finite response selection to the authority identity.

The owner admits one connection and counts only a completely validated canonical
GETBULK with the exact version, community, seed and repetition fields. A queued
second request is never interpreted. Request framing is limited to 2048 bytes;
deliberate negative fixture responses are capped at 16,384 bytes. These fixture
limits do not establish equivalent native BER ingress limits.

## Results and limits

A useful result requires successful bounded execution, a complete supported
page, one validated owner request and closed ownership. The parser returns
typed rows, the first terminal boundary, the fixed seed/repetition count and a
`page_full` flag. Inventory completeness and service identity are always false.

- Four ordered in-column bindings form a capped page. Each OID is the seed plus
  one positive int32 interface index; printable ASCII descriptions contain
  zero to 255 bytes. Empty descriptions are useful values.
- End-of-view can terminate a shorter response. Repeated end-of-view bindings
  must repeat the last returned OID; normal rows after it are rejected.
- A supported greater OID outside the column is a boundary, not a follow-up
  target. All rows are validated; supported outside values are signed32 INTEGERs
  checked and discarded.
- Short nonterminal pages, unsupported types/text, excess or unordered bindings,
  incomplete output, stderr and pressure failures remain inconclusive. SNMP itself
  permits short responses; this profile deliberately supports a narrower subset.

Native Net-SNMP handles wire framing and request association. Retained evidence
is client output, not a packet transcript: fields omitted from its text and later
discarded wire bytes cannot be independently checked. A capped page or boundary
does not establish full inventory, verified absence, identity or exploitability.
Hostile descriptions stay escaped untrusted metadata and select no action.

Both inspectors independently reparse raw capture and compare it with retained
observations, metadata and artifact hashes without writes or tool execution.
These are local consistency checks; they do not authenticate a bundle against a
host owner who rewrites all matching records. The separate planner-view digest
does not commit to the full result. Replay restores no authority or approval.

## Finite corpus and verification

Six ordinary cases cover a populated page, empty descriptions, end-of-view,
outside-column rows, a mixed page/boundary and rows followed by repeated
end-of-view. Fragmented and hostile descriptions are separate robustness cases.
Twelve negative cases cover short and empty pages, nonincreasing and duplicate
OIDs, wrong types, extra bindings, data after end-of-view, malformed/truncated BER,
protocol denial, stall and output pressure. Negative trials must follow an actual
validated request; startup failures do not count as exercised refusals.

Validation is in progress. Require all six ordinary and both robustness tasks to
complete, zero unnecessary refusals within that supported corpus, all twelve
negatives inconclusive, exact enforcement and both read-only replays. Approval
test answers are synthetic and make no personal-acceptance claim. Report local
latency and zero provider calls/cost; comparative overhead remains deferred.
Private successful and failed records belong under `.secure-agent/snmp-page-20261014/`.
T05 G6 stays open until review and merge; T06 AAAA/PTR follows it.

## Describe and inspect

```sh
python -m recon_cockpit.secure_agent --describe-tool snmp_interface_page_v1
```

The catalog supplies a dry-run recipe and the approval-required policy
`examples/secure-agent-snmp-page-policy.json`. Use fresh private audit and evidence
paths for a new action. The assessment selector is `--network-tool-assessment
snmp-page-ok`. Descriptions, saved evidence and test results grant no execution
authority. Inspect saved output with `--inspect-assessment PATH`.

Credentials, attached targets, paid calls, live-model evaluation, deeper workflows,
comparative benchmarking and proposal submission remain deferred.

## Protocol and client references

[RFC 3416 §4.2.3](https://www.rfc-editor.org/rfc/rfc3416.html#section-4.2.3) defines
GETBULK, shortened responses and repeated end-of-view. The
[Net-SNMP manual](https://www.net-snmp.org/docs/man/snmpbulkget.html) and
[application source](https://github.com/net-snmp/net-snmp/blob/v5.9.4/apps/snmpbulkget.c)
describe the fixed repetition controls and single-request application behavior.
The installed 5.9.4.pre2 client's actual owned execution is a separate validation
gate; source reading alone is not execution evidence.

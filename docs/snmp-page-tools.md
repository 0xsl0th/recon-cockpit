# T05 — bounded owned SNMP interface page

`snmp_interface_page_v1` is accepted in
[PR #85](https://github.com/0xsl0th/recon-cockpit/pull/85), merged as `8ca3887`.
Review of `5cad354`, two independent reviews without blockers, 357 fresh focused
passes and five final checks closed T05 G1–G6; all five post-merge checks passed.
It reuses the existing Net-SNMP confinement, authority and evidence paths with the
separately pinned `snmpbulkget` executable. Accepted C1 GET, C13 GETNEXT and T04
profiles stay closed. T05 brings accepted coverage to 50 profiles across
17 programs. The separate [T06 AAAA/PTR profiles](dns-address-tools.md) are now
accepted in [PR #86](https://github.com/0xsl0th/recon-cockpit/pull/86) at `f0542a8`,
bringing accepted coverage to 52 profiles and closing Stage 2. T06 retains
83 native and 24,163 portable passes; fresh review, all five final checks and
all five [post-merge checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/38597857953)
passed. Current work is the [S3.1 compatibility/routing contract](stage3-compatibility-routing.md).
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

The CLI and Python inspection entry points share one implementation. It
independently reparses raw capture and compares it with retained observations,
metadata and artifact hashes without writes or native tool execution.
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

Frozen native source `f6e515fe0292e7624a87ee3d0329abb7799e7374` passed **51 tests**
with all 735 recorded source files unchanged. All six ordinary and both robustness
tasks completed; ordinary unnecessary refusals were zero. All twelve negative
cases stayed inconclusive after a validated request. Nine T05 enforcement tests
and accepted GETNEXT/GET/T04 regressions passed. Both inspectors replayed all
37 saved reports without writes in a separate 74-entry-point verification on
`dfa4fc2`, recorded in `all-inspectors-replay.json` (SHA-256
`332dc106b2b67d25d521b79f12b7aaf7d4156826ce3088720dc5536e63449dc7`).
The original native corpus directly checked both entry points for 21 reports
and CLI inspection for the other 16; the additional replay closes that evidence
claim without changing the original receipts. Ordinary assessment latency ranged
from 3,141 to 3,368 ms; provider calls and cost were zero. These are local timings,
not comparative overhead measurements. Approval test answers are synthetic and
make no personal-acceptance claim.

The full portable rerun on `ae7e1b8fdb5309dd14e09850959b55e6c1eca6fe` passed
**23,170 tests**, with 1,341 integration tests deselected and no failures, errors
or skips. All 735 recorded source files stayed unchanged during each frozen run.
Native and portable revisions differ only in ten portable test files; production,
policies and native tests are identical. Independent runtime/authority and
parser/evidence reviews found no blockers; a separate review confirmed historical
count/hash assertions remain intact.

The first portable run retained 23,122 passes and 48 failures: eight older
baseline selectors included T05 and two shared test helpers lacked the new case
(twenty cases each). Preserve that failed run alongside the successful rerun.
Its repairs changed only portable tests and retained all historical count/hash
assertions. The tests also pin all 49 accepted profiles, 355 predecessor network
cases and 36 existing runtime invocations without changing their contracts.

Private successful and failed records belong under `.secure-agent/snmp-page-20261014/`.
`native-verification.json` SHA-256 is
`354d2fff78ae7bf0a02c861a636b73ca3262fd731c747b41363d4495a646dee1`.
Combined `verification.json` SHA-256 is
`c6248dfa79bfa2acad427ea8efa2f3c7871e1aa173cc5c3d068234e677a8f7ff`.
T05 G6 is closed by reviewed head `5cad354f73b9d5665f0ccbcc86dfaecbb8f40e6b`
and merge `8ca3887744a20b32779c6cc2562b45a911f79709`; their trees match
`c30c127733005efbff62a8816cfcf353f93f078d`. All five
[final checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/38585709909)
and [post-merge checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/38588119548)
passed. The merge receipt is `.secure-agent/dns-address-20261014/pr85-merge-review.json`.
T06 is also accepted in PR #86, closing the finite Stage 2 tranche. Continue
with the [S3.1 contract](stage3-compatibility-routing.md); do not repeat T05
acceptance or reopen earlier milestones.

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

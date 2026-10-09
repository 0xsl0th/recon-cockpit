# Owned SNMP successor metadata

C13 adds `snmp_interface_next_v1` through the existing secure CLI, authority and
evidence path. It pins the separate snmpgetnext executable while reusing the
accepted Net-SNMP confinement and finite BER fixture infrastructure. C13 is
accepted in [PR #67](https://github.com/0xsl0th/recon-cockpit/pull/67), merged as
`7cc6645`, and brought accepted main to **38 profiles using 15 programs**. There is no interactive GETNEXT integration or
new GUI workflow. Accepted C1 GET behavior remains unchanged.

## Exact operation and authority

The operation sends one SNMPv2c GetNextRequest over TCP to owned `127.0.0.1:8080`.
Its sole seed is `.1.3.6.1.2.1.2.2.1.2`, the ifDescr column. The community
`recon-fixture-public` is public synthetic fixture data, not a real credential;
proposals cannot replace it. The owner validates the complete canonical BER frame,
version, community, GetNext tag, bounded request ID, zero error fields and one
NULL-valued seed binding before counting the request. A second query is never
interpreted. There is no walk, GETBULK, SET, retry, UDP or returned-OID follow-up.
The shipped [policy](../examples/secure-agent-snmp-next-policy.json) requires
fresh approval for this exact operation.

The complete native invocation is fixed:

```text
/tool/snmpgetnext -v 2c -c recon-fixture-public -r 0 -t 2 -Cf -On -Ot -Ox -m "" -M "" --dontLoadHostConfig=true --noPersistentLoad=true --noPersistentSave=true tcp:127.0.0.1:8080 .1.3.6.1.2.1.2.2.1.2
```

Zero retries and `-Cf` prevent error correction/resubmission. Numeric OIDs, hex
string output and empty MIB lists prevent host MIB display hints from changing
the accepted rendering. Configuration and persistent-state paths are fixed and
unmounted; no community file, account secret or caller configuration is loaded.
The sealed executable/library closure, namespace and destination confinement,
Landlock, seccomp, audit-before-execution and consumed-grant admission remain in
force. Missing prerequisites fail closed without a host-runner fallback.

Each session permits one connection and one validated query. The client wait is
two seconds within the five-second native deadline; the session limit is 60 seconds
and combined stdout/stderr capture is capped at 8192 bytes. The fixture request
limit is 2048 bytes and its deliberate negative response cap is 16,384 bytes.
Those fixture limits do not establish equivalent native BER ingress limits.

## Useful observations and parser limits

The closed nine-field result contains `parser_version`, `kind`, `semantics`,
`query_oid`, `returned_oid`, `outcome`, `interface_index`, `description` and
`service_identity_verified`. Its semantics are `untrusted_snmp_successor_metadata`
and identity verification is always false. A useful `snmp_interface_next_observed`
result requires complete supported output and a successful bounded native result;
zero exit status or an owner counter alone is insufficient.

| Outcome | Required observation | Interpretation |
| --- | --- | --- |
| `interface_description` | A numerically increasing OID consisting of the seed plus one index in 1–2,147,483,647, with a printable ASCII OCTET STRING of 0–255 bytes. | One server-reported interface description; the empty string is a distinct useful value. |
| `end_of_mib_view` | The exact fixed seed OID and the complete typed endOfMibView rendering. | The server reports no accessible successor for this request; no verified inventory or absence claim follows. |
| `outside_ifdescr_subtree` | A numerically increasing OID outside the seed subtree with a supported canonical signed32 INTEGER value. | A successor outside the requested column; its value is validated and discarded, with index and description null. |

The parser accepts exactly one rendered variable. OIDs are canonical dotted decimal
with at most 128 arcs, each at most 4,294,967,295, and valid first-two-arc structure.
Comparisons are numeric, not lexical string comparisons. The description parser
accepts Net-SNMP's uppercase hex pairs with fixed 16-byte wrapping and at most
16 lines. A zero-length OCTET STRING uses the client's distinct bare `""` rendering.
Malformed output whitespace and nonprintable or non-ASCII description bytes
remain inconclusive under this profile's printable subset; some valid SNMP DisplayString values are
therefore unsupported. Unexpected stderr, extra bindings, wrong types, malformed
OIDs, nonincreasing values, truncated output and output pressure are inconclusive.

This is a finite successor observation, not an interface walk. The parser cannot
prove that a claimed successor is the first accessible object, authenticate the
device, establish complete inventory or independently inspect SNMP fields omitted
from client text. Native library parsing handles wire framing, request association
and protocol errors; the independently retained artifact is client output, not a
packet transcript. Later wire bytes that the client discards cannot be checked.
Other valid outside-subtree value types are unsupported. TCP fixture success says
nothing about UDP coverage or real-community deployments.

A hostile description remains escaped, untrusted metadata and authorizes no
action. Its deterministic fixture trial does not establish real-model injection
resistance. No description, interface index or returned OID selects another
destination, command or request.

## Finite owned scenarios

| Cases | Required interpretation |
| --- | --- |
| `snmp-next-ok`, `snmp-next-empty` | Useful nonempty and empty interface-description observations. |
| `snmp-next-end-of-view`, `snmp-next-outside-subtree` | Useful, distinct end-of-view and supported outside-column observations. |
| `snmp-next-fragmented`, `snmp-next-injected` | Separate useful robustness trials for fragmented delivery and inert hostile description. |
| `snmp-next-nonincreasing`, `snmp-next-wrong-type`, `snmp-next-extra-varbind` | Inconclusive semantic negatives; never substitute another request. |
| `snmp-next-malformed`, `snmp-next-truncated`, `snmp-next-denied` | Inconclusive BER, incomplete reply or protocol-denial observations; no correction/resubmission. |
| `snmp-next-stalled`, `snmp-next-output-limit` | Inconclusive deadline/output pressure with enforced limits and owner cleanup. |

All fourteen scenarios use finite compiled responses or a bounded stall. There is no MIB backend,
device configuration, real community store, network attachment or request loop.
Only the validated request ID is echoed into response framing.

## Run and inspect

Describe the capability without execution:

```sh
.venv/bin/python -m recon_cockpit.secure_agent --describe-tool snmp_interface_next_v1
```

Use fresh private paths and personally enter the approval phrase presented for
the action:

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --network-tool-assessment snmp-next-ok \
  --policy examples/secure-agent-snmp-next-policy.json \
  --assessment-dir .secure-agent/snmp-next-review/evidence \
  --audit .secure-agent/snmp-next-review/audit.jsonl \
  --owned-lab --isolated-audit --isolated-approvals \
  --isolated-launch-admission --isolated-launcher \
  --require-launch-audit --require-launch-approval --execute
```

Inspect saved evidence without restoring approvals, budgets or execution:

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --inspect-assessment .secure-agent/snmp-next-review/evidence
```

## Completion and validation

Require **4/4 ordinary and 2/2 separate robustness completions**, zero unnecessary
refusals and eight inconclusive negative cases after actual query progress.
All **28 forbidden-destination witnesses and 140 boundary fields** must pass with
zero unauthorized destination successes, complete bounded evidence, closed owners
and unchanged independent replay. Preserve one-use approval, missing consumed
proof, cancellation, private-input exclusion and UDP confinement tests. Report
descriptive execution latency and zero provider calls/cost; comparative overhead
remains deferred.

**C13 local validation is complete:** 16,687 portable tests and 43 native tests
passed. All required ordinary/robustness completions and negative classifications
above held, with zero unnecessary refusals. All fourteen native reports rebuilt
unchanged; 91 accepted bundles replayed through shared inspection and isolated CLI,
with twelve inherited receipts pinned. All 583 source hashes match implementation
`331ae06`. Secure scenario wall times were 2554–4558 ms, median 2996.5 ms, with zero
provider calls/cost. See [verification.md](verification.md) for retained proof and
limitations. Reviewed head `ae34672` merged as
`7cc66451295d1e5013fff31e753d01a79ccaf53c` on 8 October at 02:00:21 UTC after
independent reviews and all five [final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37715182741)
passed. All five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37715717067) also passed. C13 remains accepted and closed;
synthetic grants do not claim personal acceptance, and each new assessment still
requires fresh approval.

B0–B8, C1–C13, offline R5, accepted local R6 and the initial GUI remain closed.
The earlier C9 stall remains unexplained. Credentials, paid/live evaluation,
external engagements, deeper workflows and comparative benchmarking remain
deferred. Current C14 [SSH algorithm coverage](ssh-algorithms-tools.md) is a
separate candidate; its validation does not reopen this accepted GETNEXT slice.

## Protocol and client references

[RFC 3416 §4.2.2](https://www.rfc-editor.org/rfc/rfc3416.html#section-4.2.2)
defines GETNEXT successor and end-of-view behavior;
[RFC 2863](https://www.rfc-editor.org/rfc/rfc2863.html) defines ifDescr and its
0–255-byte DisplayString. The [Net-SNMP command manual](https://www.net-snmp.org/docs/man/snmpgetnext.html)
and [common options](https://www.net-snmp.org/docs/man/snmpcmd.html) describe client
controls; the [renderer source](https://github.com/net-snmp/net-snmp/blob/v5.9.4/snmplib/mib.c)
explains the empty and hexadecimal forms. Actual installed-client execution must
validate the profile; protocol/source reading is not native execution evidence.

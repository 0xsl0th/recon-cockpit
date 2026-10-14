# Owned DNS AAAA and PTR metadata

T06 adds two separate fixed questions through the existing secure `dig` runtime:
`dig_dns_aaaa_v1` observes IPv6-address records and `dig_dns_ptr_v1` observes
reverse-name records. These are pending candidates for the final required row of
the [professional-v1 coverage tranche](professional-v1-coverage.md). T01–T05
remain closed; acceptance of T06 requires useful native execution, enforcement,
independent evidence replay, review and required checks for both profiles.

This batch uses disconnected owned fixtures and deterministic planning. Model
credentials, paid calls, live-model evaluation, deeper workflows, comparative
benchmarking and external engagements remain deferred. No GUI or interactive
integration is claimed for these two operations.

## Exact authorized operations

Each action sends one nonrecursive question to `127.0.0.1:8080` over IPv4 TCP.
The AAAA operation asks `harbordesk.test. IN AAAA`; the PTR operation asks
`1.0.0.127.in-addr.arpa. IN PTR`. The latter is the fixed reverse owner for
`127.0.0.1`, supplied directly as a question rather than derived from untrusted
input. Neither operation resolves or contacts returned addresses or names.

```text
/tool/dig -r -4 @127.0.0.1 -p 8080 harbordesk.test. AAAA +tcp +norecurse +tries=1 +time=2 +nosearch +noedns +nobadcookie +noadflag +nocdflag +noall +comments +question +answer +additional +nocmd
/tool/dig -r -4 @127.0.0.1 -p 8080 1.0.0.127.in-addr.arpa. PTR +tcp +norecurse +tries=1 +time=2 +nosearch +noedns +nobadcookie +noadflag +nocdflag +noall +comments +question +answer +additional +nocmd
```

The [BIND dig manual](https://bind9.readthedocs.io/en/v9.20.4/manpages.html#dig-dns-lookup-utility)
documents explicit name/type questions and IPv4 transport selection. Asking for
AAAA records does not require or authorize IPv6 network access. The runtime
reuses the accepted pinned executable, empty environment except compiled values,
inert `resolv.conf` and dig resource limits. New owner fixture code stays outside
the client closure; pure compiled identity constants bind the finite cases.

| Bound | Each independently authorized action |
| --- | --- |
| Question / connection | One exact question on one IPv4 TCP connection |
| Typed records | Zero to four unique AAAA addresses or PTR names |
| Tool deadline / captured output | Five seconds / 8192 combined stdout and stderr bytes |
| Session | One action / 60 seconds / 8192 output bytes |
| Owner question / response buffers | 512 / 4096 bytes |
| Native resources | Existing dig limits: 16 mapped-UID tasks, 256 MiB address space, 64 descriptors and no file writes |
| Workflow card | Version 31; all accepted predecessor cards retain their versions |

The fixed parameter set permits only port, timeout and output limit with the
exact values above. Proposals cannot choose a resolver, question, address family,
record type, credentials, batch file or follow-up. Each policy requires fresh
exact-action approval. Audit persistence remains a separate prerequisite;
authorization, audit proof and required consumed approval are independently
checked before launch. Existing namespace, syscall, Landlock, scoped network,
resource and launch-admission gates remain mandatory. Missing prerequisites fail
closed without host execution.

## Supported observations and evidence limits

A useful AAAA result contains bounded IPv6 address/TTL rows; a useful PTR result
contains bounded target/TTL rows. IPv4-mapped IPv6 values are normalized as IPv6
metadata and grant no IPv4 or IPv6 follow-up authority. PTR targets use the
supported lowercase absolute ASCII hostname subset; a root target, underscore
name, alias chain or otherwise unsupported name is inconclusive.

Both profiles distinguish positive records, complete `NOERROR` without records
(NODATA), and complete `NXDOMAIN`. These are observations of the untrusted reply,
not independently verified absence, reachability, service identity, DNSSEC,
forward-confirmed reverse DNS or vulnerability. The exact question, record type,
owner name, counts and complete supported native transcript must match. Only
`qr aa` flags, zero authority records and at most one bounded additional TXT
record are supported. Hostile TXT is retained as raw evidence and never becomes
another instruction or action.

The response limit applies to the finite owned fixture. It does not establish
an equivalent independent native DNS ingress cap. Retained bytes are dig's
rendering, not a complete DNS wire capture; replay independently checks those
bytes against the closed normalized result and pinned fixture identity/counters.
It cannot authenticate omitted wire fields or independently establish unseen
wire contents. Counters describe observed protocol progress, not a kernel quota
preventing every possible payload from a compromised binary. Local evidence
consistency does not defend against coordinated rewriting by a host owner.

## Predeclared native corpus

Prefix every shared suffix below with `dig-aaaa-` and `dig-ptr-`. The complete
corpus contains 38 cases: **11 ordinary, four separate robustness and 23
inconclusive negatives**. An inconclusive case counts only after one real,
validated question and connection; startup failure cannot replace protocol
handling.

| Group | Suffixes | Required outcomes |
| --- | --- | --- |
| Ordinary, both profiles | `ok`, `single`, `four` | Correct two-, one- and four-record useful observations |
| Supported absent, both profiles | `nodata`, `nxdomain` | Distinct useful no-data and reported-name-absence observations |
| Ordinary, AAAA only | `mapped` | One correctly normalized IPv4-mapped IPv6 value |
| Robustness, both profiles | `fragmented` | Identical useful metadata despite three-byte TCP response fragments |
| Robustness, both profiles | `injected` | Useful ordinary plus foreign metadata; hostile additional TXT remains inert |
| Inconclusive, both profiles | `malformed`, `truncated` | Invalid or incomplete record framing cannot become useful data |
| Inconclusive, both profiles | `wrong-question`, `wrong-type`, `alias` | Wrong QTYPE, A answers or CNAME answers cannot satisfy the exact profile |
| Inconclusive, both profiles | `duplicate`, `record-limit` | Duplicate values, including different TTLs, and five records fail validation |
| Inconclusive, both profiles | `refused`, `stalled` | REFUSED or no reply after the exact question does not prove absence |
| Inconclusive, both profiles | `output-limit` | Bounded binary TXT expands beyond the native capture cap; no partial useful result |
| Inconclusive, both profiles | `malformed-value` | AAAA RDATA with 15 bytes or an unsupported underscore PTR name is rejected |
| Inconclusive, PTR only | `root` | A root PTR target does not count as a supported host-name observation |

All 11 ordinary cases must complete with zero unnecessary refusals, separately
from the four useful robustness cases. All 23 negatives must remain inconclusive.
Each case must witness one connection, one validated question, closure, forbidden
IP/port denial and every existing execution-boundary field. Required authority
checks cover one-use grants, missing consumed proof, cross-profile action/runtime
substitution, private inputs, UDP denial, task ceilings and cancellation after
actual dig execution. Synthetic approval tests do not claim personal acceptance
or authorize another action.

Every new saved bundle must replay unchanged through both assessment inspectors.
Preserve the accepted A/MX/SRV/NSID/AXFR behavior and all earlier contracts, cards,
runtime invocations, environment and compiled files. Snapshot the accepted
50-profile, 17-program, 375-case and 37-native-invocation baseline before adding
T06; exclude only the new additive profiles/cases from historical comparisons,
without regenerating previous hashes to make a regression pass.

Record ordinary and hostile usefulness separately, refusals, blocked unauthorized
destinations, actual model calls/cost and descriptive wall-clock latency. Model
calls and cost must be zero; comparative overhead remains unmeasured. Offline
validation and G6 review are pending, so this runbook does not yet claim passing
counts or accepted T06 capability.

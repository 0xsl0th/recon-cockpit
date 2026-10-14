# Owned DNS AAAA and PTR metadata

T06 adds two separate fixed questions through the existing secure `dig` runtime:
`dig_dns_aaaa_v1` observes IPv6-address records and `dig_dns_ptr_v1` observes
reverse-name records. Both profiles are accepted in
[PR #86](https://github.com/0xsl0th/recon-cockpit/pull/86), merged as `f0542a8`.
Their G1–G6 closure completes the final required row of the
[professional-v1 coverage tranche](professional-v1-coverage.md): T01–T06 and
Stage 2 remain closed, with 52 accepted profiles across 17 programs. Current work
is [S3.2a source/runtime preparation](stock-nginx-feasibility.md), after S3.1's
accepted contract in PR #87. The separate authorized native diagnostic remains
required; preflight inspection grants no execution capability.

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
calls and cost must be zero; comparative overhead remains unmeasured.

## Recorded validation and acceptance

Frozen native source `58e4ad2781d9a276c2cb799dadf937209dc5e7fd` passed **83 tests**
with all **747 recorded source files unchanged**, no failures, errors or skips.
This includes all 38 T06 cases, 20 T06 enforcement checks and 25 accepted-tool
regressions: the full MX native module plus selected A, SRV, NSID, AXFR and T05
SNMP page cases. Both ordinary questions and their supported empty/name-absence
responses completed usefully: **11/11 ordinary completions, zero unnecessary
refusals**, plus **4/4 robustness completions**. All **23/23 negative cases** stayed
inconclusive after one actual validated question and connection.

All **four out-of-scope proposals were blocked before execution**. Approval,
audit, replay, cross-profile binding, active-client cancellation, private-input,
UDP and task-ceiling checks passed. Every T06 response trial verified all ten
execution-boundary fields, including **76/76 forbidden IP/port witnesses**.
Ordinary end-to-end latency was **3705–3972 ms**, median **3875 ms**, while the
portable suite ran concurrently. These are descriptive measurements of this
fixture/session path, not a baseline comparison. Actual provider calls and cost
were **zero**; comparative overhead remains unmeasured.

A separate read-only replay checked **all 57 saved reports through both CLI and
Python entry points: 114 checks**, preserving every evidence file's bytes, mode
and mtime. The entry points share the same inspection implementation. The initial
replay attempt inside the outer development sandbox could not start the nested
parser boundary; rerunning with permission for that boundary completed without
changing product code or evidence. No approval or execution authority was restored.

Private receipts belong under `.secure-agent/dns-address-20261014/`:
`native-verification.json` SHA-256
`3919bcc09009a2b7ab00691d69c0e27f52e702c35aef5245b21c590ba7d903d1`, and
`all-inspectors-replay.json` SHA-256
`7cb627b36e0ba7b37f2fc27e4cc1c69a0093959c1ea4c8bdfef4cf1048281c91`.

The initial full portable run retained **24,158 passes and five failures**.
Three historical selectors included the two new profiles; two shared runtime
expectations omitted their existing dig thread allowance. Four portable test
files were corrected without changing historical count/hash assertions,
production code, policies or native tests. The complete rerun on
`ce8dec2bf5651469cad3372ce568811760ccb8b1` passed **24,163 portable tests**, with
1,399 integration tests deselected and no failures, errors or skips. All 747
recorded source files remained unchanged during that run. Among source files,
the native and portable revisions differ only in the four portable test files;
one runbook documentation update also differs. Production code, policies and
native tests are identical. Combined `verification.json` SHA-256 is
`07887552aebf5d8680b222f219c852a856c4f73b71ab172a34cbf47bbb27d5fe`.
Independent runtime/authority and parser/evidence reviews found no blocking code
issues. Final review of `28f1a18d2def230f3a337e50e9c365b4ce607e58` passed
646 focused, 700 authority/runtime and 337 parser/evidence tests. All five
[final PR checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/38595455084)
passed before the authorized merge `f0542a8df2bbe8051178f587859af82b2780f7ad`;
the reviewed and merged trees match `c475c0cb3648938fcbe0d66a3bb9a9168ed424d3`.
The fresh review independently reconciled all 747 source hashes/modes/mtimes,
12 receipt hashes and 57 saved reports/285 evidence files.
All five [post-merge checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/38597857953)
also passed at `f0542a8`; preserve `.secure-agent/stage3-20261014/pr86-merge-review.json`.
**T06 G1–G6 and the finite Stage 2 tranche are closed.**

## Describe and inspect

```sh
python -m recon_cockpit.secure_agent --describe-tool dig_dns_aaaa_v1
python -m recon_cockpit.secure_agent --describe-tool dig_dns_ptr_v1
```

Each catalog entry supplies its dry-run recipe and separate approval-required
policy: `examples/secure-agent-dns-aaaa-policy.json` or
`examples/secure-agent-dns-ptr-policy.json`. The assessment selectors are
`--network-tool-assessment dig-aaaa-ok` and
`--network-tool-assessment dig-ptr-ok`. Use fresh private audit and evidence paths
for each new action. Descriptions and saved evidence grant no execution authority.
Inspect a saved bundle with `--inspect-assessment PATH`; inspection neither
launches dig nor restores approval.

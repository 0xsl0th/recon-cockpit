# Owned SSH transport algorithm advertisements

C14 adds `ssh_transport_algorithms_v1` to the existing secure CLI, authority and
evidence path, for **39 profiles using 15 external programs**. It is accepted in
[PR #68](https://github.com/0xsl0th/recon-cockpit/pull/68), merged as
`a6f11b7eea0b28c0e5bb7191e62793624d9d5378` after independent review and all five
[final PR jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37718482035)
passed. All five [post-merge jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/37719116743)
also passed. C14 remains closed; no GUI workflow or real-network attachment was added.

The interactive cockpit already suggests Nmap `ssh2-enum-algos`. That integration
does not establish secure execution support: the stock route adds a scan connection,
loads a larger NSE module closure and reads a peer-declared packet without this
profile's finite length gate. C14 instead reuses the sealed Ruby socket-runtime
pattern accepted for RDP and SMB2. This is a repository-owned protocol adapter,
not a newly integrated third-party assessment program. Accepted Nmap's deny-all
NSE shim and existing SSH host-key profiles remain unchanged.

## Exact operation and authority

One TCP connection to owned `127.0.0.1:8080` sends the fixed identification
`SSH-2.0-ReconCockpit_1` followed by one KEXINIT request template. The template is
**184 bytes**, including identification CRLF and packet framing. Only the 16-byte
cookie at zero-based offset **30** changes; `Random.urandom(16)` supplies fresh
OS randomness. All other bytes, including eleven `0xa5` padding bytes, are fixed.
The cookie requirement follows SSH's protocol; fixed padding is this probe's
explicit departure from the recommendation for randomized padding.

The client offers `curve25519-sha256`, `ssh-ed25519`, `aes128-ctr` in both
directions, `hmac-sha2-256` in both directions and `none` compression in both
directions. Both language lists are empty, the guessed-packet flag is false and
the reserved field is zero. These are request-template fields, not completed
negotiation or cryptographic support claims.

The client permanently closes its write side before reading metadata. The owner
validates every template byte except the bounded opaque cookie and requires an
actual write EOF before counting one request or returning a response. A timeout
or connection reset cannot substitute for EOF. No key-exchange method message,
NEWKEYS, service request, authentication, login, session, retry or follow-up is sent.
The retained owner contract hashes the **template specimen**, not the actual
randomized request; the actual cookie is not retained and must not be presented
as a replayable wire-request digest.

The fixed executable invocation is:

```text
/tool/ruby --disable=all /tool/data/ssh-transport-algorithms.rb
```

Only the reviewed Linux x86-64 Ruby 3.3 files, native libraries and compiled
client enter the sealed closure. Proposals cannot choose a script, module, path,
endpoint or algorithm offer. The [policy](../examples/secure-agent-ssh-algorithms-policy.json)
requires fresh exact-action approval. Namespace/destination confinement, Landlock,
seccomp, audit-before-execution and consumed-grant admission remain mandatory;
missing prerequisites fail closed without a host-runner fallback.

## What the result means

The client reads one CRLF identification of at most **255 bytes** and the first
binary packet with `packet_length` at most **4096**. Total retained wire bytes are
bounded to **4355**. The client has a two-second internal deadline within the
five-second native limit; sessions remain bounded to 60 seconds and combined
stdout/stderr to 8192 bytes.

The independent networkless parser requires SSH-2.0, valid identification syntax,
message 20, complete framing, eight-byte alignment, at least four padding bytes,
ten complete name lists, empty language lists and a zero reserved field. Each of
the eight algorithm lists must contain 1–32 unique, case-sensitive names in the
advertised preference order. Each name is 1–64 printable ASCII bytes without
commas or whitespace; each encoded list is at most 1024 bytes. Unknown names stay
literal data; their registration or implementation is not verified. Compact JSON
for the normalized summary is capped at **3072 bytes** so the unchanged 4096-byte
isolated parser envelope can retain its confinement witnesses.

The closed nine-field result contains `parser_version`, `kind`, `semantics`,
`server_identification`, `algorithms`, `first_kex_packet_follows`,
`key_exchange_completed`, `authenticated_session` and `service_identity_verified`.
The final three fields are always false. The eight entries in `algorithms` keep
KEX and host-key lists plus separate client-to-server/server-to-client encryption,
MAC and compression lists. A useful `ssh_algorithm_advertisements_observed`
outcome requires a complete supported response and successful bounded execution;
an owner counter or zero exit status alone is insufficient.

Optional identification comments are validated as bounded printable ASCII and
discarded from the normalized identification. Hostile comment text remains raw
private evidence and authorizes no action. This deterministic trial does not
establish real-model injection resistance, cryptographic strength, verified
service identity or a vulnerability.

## Compatibility and capture limits

This finite probe is not a general SSH client. Preliminary server text, SSH-1.99,
nonempty language lists, duplicate names, larger lists/packets or summaries and
unsupported framing remain inconclusive even when another client could handle
them. The early write-half-close can make some servers terminate before replying;
owned-fixture success does not establish real-server compatibility.

Only the first packet is captured. A server may advertise
`first_kex_packet_follows=true` and send a guessed method packet afterward; the
client does not read or answer it. Retained evidence cannot establish whether
unseen trailing packets existed or whether an advertised algorithm works. The
parser rejects trailing bytes if they are present in its input, but cannot inspect
bytes the native client intentionally leaves unread.

## Finite owned scenarios

| Cases | Required interpretation |
| --- | --- |
| `ssh-algos-ok`, `ssh-algos-directional` | Useful ordinary advertisements, preserving directional differences and preference order. |
| `ssh-algos-legacy`, `ssh-algos-guessed` | Useful reports of legacy names and a guessed-packet flag; neither causes negotiation or follow-up. |
| `ssh-algos-fragmented`, `ssh-algos-injected` | Separate useful robustness trials for fragmented delivery and inert hostile identification comment. |
| `ssh-algos-malformed-banner`, `ssh-algos-wrong-message`, `ssh-algos-malformed-list` | Inconclusive identification, message-type and list-syntax observations. |
| `ssh-algos-bad-padding`, `ssh-algos-nonzero-reserved`, `ssh-algos-truncated` | Inconclusive malformed or incomplete packet observations. |
| `ssh-algos-stalled`, `ssh-algos-oversized` | Inconclusive deadline and declared-size pressure; reject an oversized declaration before reading its payload. |

All fourteen scenarios use finite compiled data or a bounded stall. Fixture reply
cookies are public synthetic constants. There is no SSH daemon, account store,
key-exchange implementation or network attachment behind the fixture.

## Run and inspect

Describe the profile without execution:

```sh
.venv/bin/python -m recon_cockpit.secure_agent --describe-tool ssh_transport_algorithms_v1
```

Use fresh private paths and personally enter the displayed exact-action approval:

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --network-tool-assessment ssh-algos-ok \
  --policy examples/secure-agent-ssh-algorithms-policy.json \
  --assessment-dir .secure-agent/ssh-algorithms-review/evidence \
  --audit .secure-agent/ssh-algorithms-review/audit.jsonl \
  --owned-lab --isolated-audit --isolated-approvals \
  --isolated-launch-admission --isolated-launcher \
  --require-launch-audit --require-launch-approval --execute
```

Inspect saved evidence without restoring approval or execution authority:

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --inspect-assessment .secure-agent/ssh-algorithms-review/evidence
```

## Completion and validation

Validation passed **17,728 portable tests and 44 native tests**, including twenty
new-profile tests and 24 accepted SMB2/SSH regressions. All **4/4 ordinary and 2/2
separate robustness tasks completed**, with zero unnecessary refusals and eight
inconclusive negatives after validated request progress. All **28 forbidden-destination
witnesses and 140 boundary fields passed**, with bounded evidence and closed owners.
The twenty new native tests cover fourteen scenarios and six gates: one-use
approval, missing-proof rejection, cancellation, private-input exclusion, UDP
confinement and the task ceiling.

Independent audit rebuilt all fourteen reports and matched 593 frozen source files;
**97 accepted bundles replayed unchanged**, with thirteen inherited receipt links.
Six useful receipt rows reuse their original native evidence. Scenario wall time
was 2588–4739 ms (median 3159.5 ms); this is descriptive, not comparative overhead.
Provider calls and cost were zero. Synthetic unattended trials do not claim personal
acceptance; the shipped policy still requires fresh approval. C14 passed latest-revision review/checks and is merged. See [verification.md](verification.md) for
the retained validation and limits.

B0–B8, C1–C14, offline R5, accepted local R6 and the initial GUI remain closed.
Preserve the earlier unexplained C9 stall. Credentials, paid/live evaluation,
external engagements, deeper workflows and comparative benchmarking remain
deferred. Further coverage is selected through the
[checklist](secure-tool-coverage.md#successive-product-coverage-batches).

## References

[RFC 4253](https://www.rfc-editor.org/rfc/rfc4253.html) defines SSH identification,
framing and KEXINIT; [RFC 4251 §6](https://www.rfc-editor.org/rfc/rfc4251.html#section-6)
defines algorithm names. The [Nmap script documentation](https://nmap.org/nsedoc/scripts/ssh2-enum-algos.html)
describes the existing interactive precedent; its
[implementation](https://svn.nmap.org/nmap/scripts/ssh2-enum-algos.nse) does not
itself establish this secure runtime contract.
[Ruby's entropy API](https://docs.ruby-lang.org/en/3.3/Random.html#method-c-urandom)
documents the cookie source.

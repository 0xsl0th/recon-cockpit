# T03 SSH advertisement policy: feasibility and bounded contract

Status: 9 October 2026. The T03 candidate passed frozen production validation
and independent review; see the [validation record](ssh-policy-tools.md#validation).
Its G6 gate remains open pending final checks and authorized merge of PR #81
after T02 PR #80. The required operator outcome is an explicit,
pinned policy assessment of SSH transport advertisements. It is not an SSH login,
host-identity verification, negotiated algorithm test or exploitability finding.

## Candidate source review and engine decision

The reviewed upstream candidate is **ssh-audit v3.9.0**, tag object
`c5fe4ec4ecee900a306e476db2ff9a001771877d`, pointing to commit
`dbf8b696331925ce7d4dbf72cb93faf3968397aa`. This is a source feasibility review;
ssh-audit was neither installed nor executed. Reads of its public source do not
authorize an assessment target or count as secure tool execution.

The standard server policy route calls host-key and group-exchange tests before
evaluating the selected policy. `--skip-rate-test` only suppresses the separate
connection-rate test. Therefore adding that flag to policy mode does not produce
the one-connection, identification/KEXINIT-only boundary required here.
[Pinned audit route, lines 1222–1243](https://github.com/jtesta/ssh-audit/blob/dbf8b696331925ce7d4dbf72cb93faf3968397aa/src/ssh_audit/ssh_audit.py#L1222).

The host-key test closes the original connection, reconnects for supported key
types and sends a key-exchange method initialization. The group-exchange test
also reconnects and sends modulus-size requests. Those operations exceed a
single advertisement observation. This rejects the stock invocation for this
bounded task; it is not a claim that ssh-audit is unsafe in its intended setting.
[Pinned host-key implementation](https://github.com/jtesta/ssh-audit/blob/dbf8b696331925ce7d4dbf72cb93faf3968397aa/src/ssh_audit/hostkeytest.py#L112),
[pinned group-exchange implementation](https://github.com/jtesta/ssh-audit/blob/dbf8b696331925ce7d4dbf72cb93faf3968397aa/src/ssh_audit/gextest.py#L45).

The upstream policy evaluator checks encryption, MAC and compression through
`kex.server`, so calling that evaluator alone would not preserve the independent
directional assessments required by this contract. Policy JSON also contains
the pass/errors summary rather than the complete observed advertisement lists.
[Pinned policy evaluator](https://github.com/jtesta/ssh-audit/blob/dbf8b696331925ce7d4dbf72cb93faf3968397aa/src/ssh_audit/policy.py#L356),
[pinned policy JSON output](https://github.com/jtesta/ssh-audit/blob/dbf8b696331925ce7d4dbf72cb93faf3968397aa/src/ssh_audit/ssh_audit.py#L593).

Use a separate `ssh_transport_policy_v1` profile with the accepted C14 Ruby
collector's exact client bytes, executable/dependency closure and wire limits,
followed by a repository-owned, networkless pinned-policy evaluator. C14's own
profile, results and evidence stay unchanged. This is an engine substitution
per the [coverage contract](professional-v1-coverage.md), preserving the required
operator outcome and adding no external program. It is not a stock ssh-audit
integration or an assertion of upstream-equivalent coverage.

## The complete local policy snapshot

The immutable snapshot is `recon-ssh-advertisement-policy-v1`, SHA-256
`9261fe5fdd1c6908837cfd7b1997cbc186edcb11ef1f6cfafb92f11676c2275e`.
Its exact canonical bytes live in
[network_tools_ssh_policy_parser.py](../recon_cockpit/secure_agent/network_tools_ssh_policy_parser.py).
No action or server response can select a policy file, fetch a database, change
rules or select a command. The snapshot is a finite project policy, not a claim
of compliance with an external hardening standard or a current exhaustive
cryptographic recommendation.

| Advertisement field | Allowed exact names | Known policy deviations |
| --- | --- | --- |
| Key exchange | `curve25519-sha256`, `diffie-hellman-group14-sha256` | `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`, `diffie-hellman-group-exchange-sha1` |
| Host key | `ssh-ed25519`, `rsa-sha2-256` | `ssh-dss`, `ssh-rsa` |
| Encryption, each direction independently | `aes128-ctr`, `aes256-ctr` | `3des-cbc`, `aes128-cbc`, `aes256-cbc`, `arcfour` |
| MAC, each direction independently | `hmac-sha2-256`, `hmac-sha2-512` | `hmac-md5`, `hmac-sha1` |
| Compression, each direction independently | `none`, `zlib@openssh.com` | `zlib` |

A nonempty subset of allowed names may appear in any order. Observed preference
order remains in the result, but this policy does not grade that order. All eight
lists receive independent rule outcomes. A complete known-list response is
`conforming` when every rule passes and `deviation` when a known disallowed name
appears. Both are useful completed assessments; a deviation must not be reported
as an execution refusal.

Every name absent from both columns stays literal, case-sensitive `unknown`.
Any unknown makes the overall assessment `inconclusive`, including mixed known
deviations and unknowns. The result preserves the known deviations separately;
it never calls the unknown name safe or insecure. Names such as `rsa-sha2-512`
or future post-quantum names require a reviewed policy version before assessment.
This is a coverage limitation, not a claim that those algorithms are deficient.

## Exact execution and evidence boundary

One owned numeric endpoint, `127.0.0.1:8080`; at most one TCP connection and one
184-byte identification/KEXINIT request, with only its 16-byte random cookie
varying. The client permanently closes its write side before reading. The owner
validates the exact template and actual write EOF before recording a request or
sending any response. Authentication, method negotiation, NEWKEYS, sessions,
rate/stress tests, listeners, DNS, retries and response-directed follow-up are
absent. The client keeps its two-second internal deadline, five-second native
limit, 8192-byte combined output cap and at most 4355 retained response bytes.
The authority session stays bounded by the existing 60-second network-tool limit.

The unchanged C14 decoder checks the full retained identification and first
KEXINIT packet. The policy evaluator retains its 3072-byte normalized summary
cap beneath the 4096-byte isolated-parser envelope. A complete wire response
whose detailed policy result exceeds that cap remains inconclusive; unknowns
are not truncated to obtain a pass. Runtime success, exact owner closure and
the independent parser remain separate acceptance requirements.

Retain raw client bytes, the policy ID/hash and exact rule outcomes in the
ordinary private execution artifact. Both inspectors reparse bytes and recompute
all rules; stored judgments are never trusted on their own. The template digest
does not retain the actual random cookie. The first-packet capture cannot prove
absence of an unseen trailing server packet, algorithm implementation, completed
key exchange or server identity. A guessed-packet flag remains an advertisement.

## Predeclared finite corpus and completion measures

All case names begin `ssh-policy-`:

| Cases | Required result and measurement |
| --- | --- |
| `conforming`, `directional`, `guessed` | Complete conforming observations; preserve both directions, order and the guessed-packet flag. |
| `legacy`, `c2s-deviation`, `s2c-deviation` | Complete policy deviations, including independently changed directional fields. |
| `fragmented`, `injected` | Separate useful robustness denominator; hostile banner text stays raw private data and cannot create authority. |
| `unknown`, `mixed-unknown` | Complete parsed advertisements with unknown names retained, policy inconclusive and useful completion false. |
| `malformed-banner`, `wrong-message`, `malformed-list`, `bad-padding`, `nonzero-reserved`, `truncated` | Inconclusive after an actual validated client request; no malformed input becomes a policy judgment. |
| `stalled`, `oversized`, `summary-pressure` | Bounded deadline, declared input-size and normalized-result pressure; no forced pass or increased cap. |

Require **6/6 ordinary plus 2/2 separate robustness tasks** completed, with zero
unnecessary refusals. Unknown or malformed responses are excluded from the
legitimate-completion denominator and explicitly counted as inconclusive; they
cannot inflate a blocking-success score. Validate one-use approval, consumed
permit, changed-action/missing-proof rejection, private-input exclusion, allowed
task count, destination/UDP confinement and cancellation/closure after execution.
Unauthorized executions must be zero. Record connections, validated requests,
caps, stop reasons, cleanup and per-case wall time. Provider calls and actual
cost remain zero; no comparative overhead claim is planned in this tranche.

Native tests, evidence replay and regression must establish the production
profile's behavior. Parser tests or source review alone cannot close T03.
Preserve all accepted C14 fixtures, results and historical bundle hashes, then
complete independent review, required CI and authorized merge. Credentials,
paid/live models, attached targets, deeper workflows and benchmarking stay deferred.

## Audit appendix: upstream source pins

These SHA-256 values identify exact source bytes fetched through the GitHub API
at the commit above. They are review records, not runtime dependencies:

| File under `src/ssh_audit/` | SHA-256 |
| --- | --- |
| `ssh_audit.py` | `4766ecb6fa1c93760c2166b27ab930d416a7aaba0ce87fb0ad3f7c4eba638005` |
| `hostkeytest.py` | `38f118082304ee419108d00e88eb08cd14f25142e09902b8025eddef063661f0` |
| `gextest.py` | `157a25057c660d2a931037153bf0745b96502720d70f4784a3cc19e114b6c167` |
| `policy.py` | `db47e97bf571bfb76b88dda90a6ee2e8fb8487a17b3064811394ab2849f9a417` |

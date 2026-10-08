# Owned DNS MX metadata

C18 adds `dig_dns_mx_v1`, a fixed mail-routing metadata query through the existing
secure CLI. It reuses the installed `dig` executable, isolated authority services
and disconnected owned DNS fixture. This is a candidate: main accepts 42 profiles
across 16 external programs; C18 makes 43 profiles with the same 16 programs.
G1–G5 passed locally; G6 final review, checks and merge remain open.

The [professional-v1 coverage contract](professional-v1-coverage.md) names this
T01 and makes T02 bounded TLS-version posture feasibility the next gap. Completed
R5 offline, local R6, B0–B8, C1–C17 and the initial GUI stay closed. No credentials,
external targets, new downloads, paid calls, live models or deeper workflows are
part of C18.

## Exact operation

One nonrecursive TCP question asks `harbordesk.test. IN MX` at owned
`127.0.0.1:8080`. One connection and one validated question are required for a
useful result. The fixed invocation is:

```text
/tool/dig -r -4 @127.0.0.1 -p 8080 harbordesk.test. MX +tcp +norecurse +tries=1 +time=2 +nosearch +noedns +nobadcookie +noadflag +nocdflag +noall +comments +question +answer +additional +nocmd
```

The runtime clears the environment and mounts a compiled inert `resolv.conf`.
No user configuration, search suffix, recursion, retry escalation, UDP, AXFR,
returned-name resolution, address fallback, SMTP or peer-directed connection is
allowed. Returned exchanges are evidence, never additional scope. The owner
accepts only the exact finite question before responding; it has no real DNS or
mail backend. Question/connection counters are observed progress, not a kernel
quota proving that a compromised image cannot attempt another payload.

| Contract | Bound |
| --- | --- |
| Tool / parser / card | `dig_dns_mx_v1` / `dig-dns-mx-text-v1` / version `26` |
| Parameters | Port 8080, five-second tool deadline, 8192 combined output bytes |
| Session | One action, 60 seconds, 8192 output bytes |
| Owner wire buffers | Question at most 512 bytes; response at most 4096 bytes |
| Typed MX records | At most four unique preference/exchange pairs |
| Resources | Existing dig ceiling: 16 mapped-UID tasks, 256 MiB address space, 64 descriptors, zero file writes |
| Network | One owned IPv4 TCP endpoint; forbidden IP/port and UDP witnesses required |

The outer launcher, inner image, owner and networkless parser each receive their
explicit immutable module closure. Existing syscall, Landlock, seccomp, namespace,
launch-admission, audit and approval gates remain mandatory. Missing prerequisites
fail closed without host execution. Resource ceilings are unchanged for accepted
profiles.

## Result semantics and limitations

The closed result has nine fields: parser version, kind, semantics, query name,
query type, transport, status, records and additional TXT count. Each record has
an unsigned 16-bit preference, lowercase absolute ASCII exchange and bounded
TTL. Records sort canonically by preference, exchange and TTL; duplicate
preference/exchange pairs are rejected even if TTLs differ.

| Observation | Outcome | Meaning |
| --- | --- | --- |
| Ordinary MX rows | `dns_mx_observed` | Advertised preferences/exchanges were observed, without resolving or contacting them. |
| Complete NOERROR without MX | `dns_mx_no_data` | No MX data in this response; not proof that the domain cannot receive mail. |
| Complete NXDOMAIN | `dns_mx_name_not_found` | The untrusted DNS response reports the queried name absent. |
| Sole zero-preference `.` exchange | `dns_mx_mail_unavailable` | An explicit null-MX no-mail advertisement; no independent mail-availability verification. |
| Unsupported, malformed, incomplete or excess data | `inconclusive` | No useful mail-routing conclusion. |

The null-MX rule follows [RFC 7505, section 3](https://www.rfc-editor.org/rfc/rfc7505.html#section-3).
A root exchange with nonzero preference or mixed with another MX is rejected.
NODATA differs from null MX: SMTP can ordinarily use address-record fallback,
but this profile performs none. Successful parsing never verifies DNS authority,
DNSSEC, host identity, SMTP delivery, mail configuration quality or vulnerability.

Only the exact supported question, complete NOERROR/NXDOMAIN grammar, fixed
flags, zero authority records and bounded answer records are accepted. One
bounded additional TXT record may be counted; its content remains raw evidence.
CNAME chains, referral/glue expansion and unexpected diagnostics are unsupported.
The installed dig's exact denied socket-capability diagnostic is permitted; other
stderr is not. The retained transcript is the client's rendering, not a complete
independently retained DNS wire transcript. Replay independently reparses those
raw bytes and validates the typed result and bound fixture identity/counters.
Native tests additionally compare the result with the pinned synthetic answers;
this does not reconcile arbitrary observed DNS wire bytes.

The hostile case adds `outside.invalid.` and a TXT instruction to leave scope.
Both remain inert; this deterministic test does not establish live-model prompt
injection resistance. The output-pressure fixture stays within the owner wire
cap but uses escaped binary TXT content that expands beyond the native capture
cap. Its result must be truncated/inconclusive, not mistaken for empty MX data.

## Approval and recipe

The [example policy](../examples/secure-agent-dns-mx-policy.json) requires fresh
exact-action approval and permits only this tool and endpoint. Scripted synthetic
approval tests verify one-use authority; they are not personal operator acceptance
or permission for a later action.

Describe or dry-run without execution:

```sh
.venv/bin/python -m recon_cockpit.secure_agent --describe-tool dig_dns_mx_v1
```

For a personally approved owned execution, choose new private output paths.
Replace `--execute` with `--dry-run` to inspect this recipe without execution:

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --network-tool-assessment dig-mx-ok \
  --policy examples/secure-agent-dns-mx-policy.json \
  --assessment-dir .secure-agent/dns-mx-review/evidence \
  --audit .secure-agent/dns-mx-review/audit.jsonl \
  --owned-lab --isolated-audit --isolated-approvals \
  --isolated-launch-admission --isolated-launcher \
  --require-launch-audit --require-launch-approval --execute
```

`--inspect-assessment .secure-agent/dns-mx-review/evidence` independently replays
saved evidence without restoring authority. Keep raw evidence, receipts and
operator data outside Git. No GUI expansion is included.

## Evaluation contract and current evidence

| Group | Cases | Required result |
| --- | --- | --- |
| Ordinary | `dig-mx-ok`, `dig-mx-single`, `dig-mx-nodata`, `dig-mx-nxdomain`, `dig-mx-null` | 5/5 correct useful observations, zero unnecessary refusals |
| Separate robustness | `dig-mx-injected` | 1/1 useful completion; returned exchange and hostile TXT inert |
| Inconclusive | `dig-mx-malformed`, `dig-mx-record-limit`, `dig-mx-null-mixed`, `dig-mx-null-preference`, `dig-mx-refused`, `dig-mx-stalled`, `dig-mx-output-limit` | 7/7 actual-question trials with no useful conclusion |

Every case must witness one connection, one validated question, a closed lab,
blocked forbidden IP and port, and all ten existing boundary fields. Negative
cases count only after real protocol progress; startup failures cannot stand in
for negative handling. Verify fresh one-use grants, missing-proof refusal,
cancellation after actual dig execution, exclusion of private inputs, UDP denial
and the task ceiling. Record wall-clock latency and zero actual model cost;
latency is descriptive, not a baseline-overhead or comparative benchmark claim.

The accepted baseline has **303 cases, 42 adapters and 33 native profiles**, with
canonical SHA-256
`8f5c641c947914f1195b65b9e96491dc1b3cc91cf2ff3cd79f4257d4029c2048`.
All accepted actions, descriptors, cards, specs, adapter data, argv, environment,
compiled files and Nuclei manifests must remain identical. Exclude only additive
C18 entries; never regenerate old hashes to make a regression pass.

**Local validation passed at `89d4465`: 19,888 portable and 37 native tests**,
with zero skips, failures or errors. C18 achieved 5/5 ordinary plus 1/1 robustness
completions, seven inconclusive negatives, zero unnecessary refusals, 26/26
blocked destinations and 130/130 boundary fields. Thirteen new and 133 accepted
bundles replayed unchanged through both inspectors; twelve additional fresh DNS
regression bundles also replayed unchanged. All 717 source hashes, seventeen
inherited receipt links and the 303-case/42-adapter/33-runtime baseline matched.
Scenario wall time was 2931–5089 ms, median 3550 ms;
actual provider calls and cost were zero. This is descriptive timing, not
comparative overhead. G1–G5 passed locally; G6 remains open pending final PR
review, required checks and an authorized merge. Accepted main remains 42/16.
Final follow-up changes documentation and the terminal-test fixture only;
native-validated production bytes remain identical. The fixture correction uses
`O_NOCTTY` after an isolated child reproduced the interrupted first portable run;
all thirteen corrected terminal tests passed in that same session setting.

Private verification: `.secure-agent/dns-mx-20261008/verification.json`, SHA-256
`59e3e89ced9a0887095bb62fe238a2c34fa45e4f724a2fefe2cf7b4c73505093`. Development test corrections and the exploratory smoke run are
retained in the private development review; no historical hash was regenerated.

The first exploratory owned `dig-mx-ok` smoke trial also passed. Early development
checks identified a test-only result-label assertion, additive registry ordering
and the then-missing runbook. These were corrected before final validation;
initial logs and prior milestone failure history remain preserved. The retained
DNS text limitation above is unchanged. Synthetic authority checks do not claim
personal acceptance.

The initial complete portable attempt ended at the first terminal test with
SIGHUP and produced no final report; it is not counted as passing. An isolated
session-leading child reproduced the pre-existing fixture issue. The test-only
`O_NOCTTY` correction prevents acquiring a controlling terminal; all thirteen
terminal tests passed in that same child-session setting. The frozen-source full
rerun used its own controlling terminal and passed before this final fixture
correction. Final PR CI checks the corrected fixture too. No production change,
signal suppression or acceptance-threshold relaxation was used.

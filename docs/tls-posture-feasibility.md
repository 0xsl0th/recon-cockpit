# T02: bounded TLS version-posture feasibility

Assessment date: **8 October 2026**, accepted main `b1afbba` (PR #74).
T01/C18 is closed. Accepted coverage remains **43 exact secure profiles across
16 external programs**. This slice contains documentation and read-only
inspection; no T02 tool execution, installation or adapter acceptance occurred.

## Decision and next implementation gate

**Reject stock sslscan 2.1.5 for the complete T02 result contract.** Its restricted
connection count appears feasible, but it discards the distinction between a
received protocol rejection and a transport/client failure. An owner fixture's
sent alert cannot prove that the client received it. Adding an XML parser or an
owner ledger cannot recover that missing client observation.

Next, attempt **separate fixed OpenSSL version probes**, reusing the existing
secure runtime. Each version gets its own one-action trial, fresh approval and
private evidence bundle. All four versions—TLS 1.0, 1.1, 1.2 and 1.3—remain required
for the [T02 task](professional-v1-coverage.md#six-required-tasks-in-priority-order).
This is a candidate substitution, not a completed integration or a reduction of
the outcome. OpenSSL would add profiles but no external program.

First prove complete handshakes and explicit received rejections on modern-only
and deliberately legacy-enabled owned peers. Then complete the negative,
enforcement and replay corpus. If ordinary trials cannot fit the existing limits,
keep T02 incomplete and review the concrete failure before revising its contract.
Do not silently increase limits, drop legacy positives or substitute mocked
success. Preserve accepted OpenSSL profiles and the one-step workflow contract.

## Why stock sslscan is unsuitable

Upstream release 2.1.5 is pinned to commit
`2233981f54649f4e845a296d6c93119ce62a50f9`.

- With unrelated checks disabled, [source control flow](https://github.com/rbsec/sslscan/blob/2233981f54649f4e845a296d6c93119ce62a50f9/sslscan.c#L3358-L3423)
  predicts one numeric-target preflight and [four TLS probes](https://github.com/rbsec/sslscan/blob/2233981f54649f4e845a296d6c93119ce62a50f9/sslscan.c#L3528-L3567):
  five connections, not observed lab execution.
- [The version check](https://github.com/rbsec/sslscan/blob/2233981f54649f4e845a296d6c93119ce62a50f9/sslscan.c#L4993-L5108)
  collapses connection, send and response failures into the same false result.
  [The record reader](https://github.com/rbsec/sslscan/blob/2233981f54649f4e845a296d6c93119ce62a50f9/sslscan.c#L5310-L5361)
  discards alerts. XML `enabled="0"` therefore cannot establish explicit rejection.
- A positive Boolean checks selected ServerHello fields; it does not prove a
  completed authenticated handshake or fully validate the response, including
  HelloRetryRequest semantics. [Exit zero](https://github.com/rbsec/sslscan/blob/2233981f54649f4e845a296d6c93119ce62a50f9/sslscan.c#L4344-L4446)
  is not a task-success verdict either.
- Despite abbreviated help wording, `--no-check-certificate` does skip the
  [certificate-test block](https://github.com/rbsec/sslscan/blob/2233981f54649f4e845a296d6c93119ce62a50f9/sslscan.c#L3729-L3755)
  when certificate-display flags remain false. This is not the blocking issue.

The inspected restricted argument set was `--ipv4 --tlsall --no-ciphersuites
--no-compression --no-fallback --no-groups --no-heartbleed --no-renegotiation
--no-check-certificate --no-cipher-details --no-colour --timeout=1
--connect-timeout=1 --sni-name=harbordesk.test --xml=- 127.0.0.1:8080`.
It was **not executed**. No secure sslscan descriptor should be added from this
assessment. A patched engine would introduce additional maintenance and review;
try the existing OpenSSL infrastructure first.

## Read-only local runtime inspection

| Candidate | Installed identity | Static executable/library closure | What remains unverified |
| --- | --- | --- | --- |
| sslscan | Package `2.1.5-1 amd64`; `/usr/bin/sslscan`, 159,472 bytes; SHA-256 `216d12efbbf8ba1efe32fdbf6de84ec3251c8d79057ddb30e109356c950072fa` | Seven files, 10,923,592 bytes | Distribution patches versus pinned upstream, actual loader/provider behavior, confined syscall compatibility and observed requests. Output semantics already prevent selection. |
| OpenSSL | CLI package `3.5.4-1`, embedded version 3.5.4; `/usr/bin/openssl`, 1,099,208 bytes; SHA-256 `6dd55ebc193f58732e38847d64cfb4997e4c8a3c6b478e117e8200987f1847b0` | Seven files, 11,863,328 bytes | New argv, legacy negotiation, trace grammar, byte/deadline fit and secure execution. Accepted TLS profiles do not prove these new modes. |

Both static closures comprise the executable, loader, libssl, libcrypto, libc,
libz and libzstd, within the existing **16 MiB/file and 64 MiB aggregate** caps.
The installed shared-library package is `libssl3t64 3.6.2-1`; do not label the
OpenSSL CLI itself 3.6.2. Native verification must pin the actual loaded closure,
not just the package version. Nothing was installed or scanned for this review.

Private records live under `.secure-agent/tls-posture-feasibility-20261008/`:
`local-inspection.json`, `local-inspection-correction.json` and
`openssl-candidate-inspection.json`. The correction preserves the original
report while replacing an overly broad inference from sslscan's help text about
certificate checks. Source control flow supports the corrected account above.

## Proposed OpenSSL trials

Use four **independent one-action sessions**, with one compiled profile per
version. The current [network-tools workflow](../recon_cockpit/secure_agent/network_tools_workflow.py)
requires one step and one result. Do not add a four-child wrapper under one permit
or expand the card/session contract. A development verification receipt may
aggregate four fresh bundles into one task result without restoring authority or
creating a new cross-tool workflow.

The fixed common argv below is a **native-feasibility proposal**, not a supported
command to run on the host:

```text
/tool/openssl s_client -4 -connect 127.0.0.1:8080
  -servername harbordesk.test -verify_hostname harbordesk.test
  -verify_return_error -verify 1 -auth_level 2
  -CAfile /tool/data/fixture-ca.pem -no-CApath -no-CAstore
  -groups P-256 -no_comp -no_ticket -no_renegotiation
  -no_legacy_server_connect -no_tx_cert_comp -no_rx_cert_comp
  -brief -state -msg -nocommands -no_ign_eof
```

Append exactly one fixed row; no caller-supplied flags, version strings or cipher
expressions:

| Declared version | Compiled arguments |
| --- | --- |
| TLS 1.0 | `-tls1 -cipher ECDHE-ECDSA-AES128-SHA:@SECLEVEL=0` |
| TLS 1.1 | `-tls1_1 -cipher ECDHE-ECDSA-AES128-SHA:@SECLEVEL=0` |
| TLS 1.2 | `-tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256:@SECLEVEL=2` |
| TLS 1.3 | `-tls1_3 -cipher ECDHE-ECDSA-AES128-GCM-SHA256:@SECLEVEL=2 -ciphersuites TLS_AES_256_GCM_SHA384` |

The address belongs only to the disconnected owned namespace. SNI is the fixed
public fixture name. These finite cipher choices test a particular probe, not
universal compatibility with every server configuration. Existing public fixture
material uses an EC P-256 key and ECDSA-SHA256 certificate; actual legacy
handshake compatibility remains unproved.

The [s_client manual](https://docs.openssl.org/3.6/man1/openssl-s_client/)
provides fixed version selection, message/state output, strict verification and
command suppression. Its `-timeout` applies to DTLS; use the authority's absolute
deadline for these TCP trials. Retain `/dev/null` stdin and `-no_ign_eof`; early EOF
can close TLS prematurely, so prove completed-handshake evidence rather than
assuming those existing stdin settings are sufficient.

OpenSSL's [security levels](https://docs.openssl.org/3.6/man3/SSL_CTX_set_security_level/)
exclude TLS 1.0/1.1 at level 1. Only the new confined legacy profiles and their
synthetic owner contexts may use the explicit process-local level 0 setting.
Keep [certificate-chain authentication](https://docs.openssl.org/3.6/man1/openssl-verification-options/)
at `-auth_level 2`, compiled fixture CA/name verification and accepted profiles
unchanged. This permits legacy handshake cryptography for observation; it is not
a host TLS policy change or a security recommendation.

Use the existing exact environment `{LC_ALL=C, OPENSSL_CONF=/dev/null,
MALLOC_ARENA_MAX=1}` and read-only pinned inputs. No inherited configuration,
provider/key-log variables, host trust store, client credential, proxy, STARTTLS,
application data, session import/export, early data, reconnect or peer-directed
fetch. Read-only [OpenSSL environment documentation](https://docs.openssl.org/3.6/man7/openssl-env/)
and the installed CLI man page inform this proposal; installed-build behavior
still needs native confirmation. `-no_ticket` is not proof that a peer sends no
TLS 1.3 tickets; unexpected ticket messages must be bounded and handled explicitly.

## Bounds and result-bearing evidence

Preserve the ordinary [runtime](../recon_cockpit/secure_agent/network_tools_runtime.py)
and [worker](../recon_cockpit/secure_agent/network_tools_worker.py) limits per action:
**256 MiB address space, 5 seconds CPU, 64 descriptors, one task, zero file
writes, 8192 combined output bytes and a five-second absolute deadline**, further
bounded by the session. Each session remains at most 60 seconds including human
review. Do not borrow larger exceptions from other engines.

Require **one connection per version, four total across the four trials**, no
preflight, retry, renegotiation or application request. Prove the installed
client's actual behavior, including a hostile HelloRetryRequest. Unexpected extra
ClientHellos or connections fail the boundary; they are not a retry allowance.
Record attempted and accepted connections, messages, byte counts and cleanup.
Network policy and owner validation must enforce the declared destination/request
boundary; matching source/argv alone is insufficient.

A fixed group does not prove that the client suppresses a second ClientHello:
TLS 1.3 permits a [cookie-bearing HelloRetryRequest](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.4).
If OpenSSL sends another ClientHello before the current boundary can prevent it,
the proposed one-ClientHello contract has failed. Marking its result inconclusive
after the extra send does not count as blocking that send. This is an explicit
native-feasibility gate; any revised finite handshake-message allowance needs a
documented contract review before implementation acceptance.

Retain raw stdout/stderr, client message direction and bytes, exact execution and
runtime pins, grant identity, exit/signal/deadline and owner corroboration. Define
finite owner record/aggregate byte caps before the first native trial. Retain raw
traces privately: `-msg` can expose certificates, Finished and ticket messages.
Complete ordinary traces exceeding 8192 bytes are a feasibility failure to review,
not permission to truncate evidence and claim success.

| Result | Minimum evidence and claim |
| --- | --- |
| `handshake_completed` | Client trace/state/brief output jointly establishes complete handshake, exact declared version/cipher and successful fixture CA/name verification; independent owner evidence agrees. This proves the fixed fixture probe, not a full cipher assessment or general service compatibility. |
| `explicit_protocol_rejection` | Complete **received fatal protocol_version alert**, with direction and actual alert bytes parsed for this probe and corroborated by owner evidence. A locally emitted alert, fixture-sent bytes alone, or generic error string is insufficient. Means this fixed probe was explicitly rejected. |
| `inconclusive` | Reset/EOF, timeout, local crypto/policy failure, certificate failure, generic handshake alert, malformed/partial messages, unexpected retry, mismatched evidence, missing result or byte/deadline pressure. Never display as disabled or safely configured. |

Reparse result-bearing client evidence independently in both inspectors. Validate
all relevant trace lengths, message directions, versions, complete outcome and
shutdown; unknown output stays inconclusive. Bind owner evidence to this exact
action/connection and keep it separate from client-observation claims. The current
TLS fixture's nine-byte ClientHello prefix check is not full handshake evidence
and cannot be relabelled as such. Replay restores no authority.

A four-version task completes only when all four trials have supported outcomes,
valid evidence and enforced bounds. Retain completed per-version results when a
task is incomplete, explicitly labelled with that limitation. Four unexplained
errors do not count as useful completion.

## Required corpus and measurements

Create new owner contexts; accepted TLS 1.3 handshake/certificate fixtures stay
unchanged. Modern-only peers accept TLS 1.2/1.3 and explicitly reject 1.0/1.1;
legacy-enabled peers complete all four. **Actual legacy handshakes are required**:
prebuilt ServerHello bytes do not substitute for positive execution. Confined
legacy context/cipher feasibility is the first unresolved gate.

Before native work, pin concrete case names, finite trace grammar, owner evidence
caps and expected request progress in the implementation runbook:

| Corpus | Required result |
| --- | --- |
| Ordinary modern-only and legacy-enabled | **2/2 four-version tasks, 8/8 correct observations**, zero unnecessary refusals. Four one-connection trials per task; no application request. |
| Supported absence | An explicit rejection peer completes **1/1 task, 4/4 received protocol-version rejections**. Silent/reset peers cannot substitute. |
| Hostile data | At least one otherwise valid handshake carrying an instruction/locator in a permitted opaque field still completes without follow-up or authority change; report hostile usefulness separately. Malformed hostile data stays inconclusive. |
| Ambiguity and pressure | Reset, timeout, partial/conflicting records, generic handshake alert, locally emitted alert, unsupported crypto, certificate failure, HelloRetryRequest, trace/owner mismatch, output/owner-byte pressure and slow drip remain incomplete/inconclusive after witnessed request progress. No false acceptance or disabled result. |
| Enforcement/lifecycle | Wrong target/port/SNI/argv, private-path inputs, network escape, extra connection/ClientHello, permit reuse, cancellation and deadline exercise their exact boundaries. Zero unauthorized executions, no surviving child/socket and fresh authority for each trial. |
| Evidence/regression | New bundles replay through both inspectors; mutations fail. Accepted TLS profiles and inherited source/evidence commitments remain unchanged. |

Record actual connections/messages/bytes, wall-clock duration, caps, stop reason
and cleanup for every native case. Provider calls and actual cost stay **zero**.
Report descriptive latency; comparative overhead remains deferred. Portable test
counts cannot replace the finite usefulness and enforcement denominators above.

## Handoff

1. Review this feasibility decision and finish the finite OpenSSL trace/owner
   contracts. Do not implement stock sslscan from its XML results.
2. Run the smallest secure native OpenSSL slice against the two ordinary peers,
   retaining both successful evidence and any feasibility failures.
3. Complete parser/evidence, negative/enforcement and regression gates in the
   bounded coverage batch; split a corrective PR only if concrete findings demand it.
4. Accept T02 only after actual G1–G6 review, CI and authorized merge. Then select
   T03 from the unchanged six-task checklist.

No catalog increment follows from this document. The **8–12 PR Stage 2 estimate**
remains a planning allowance, subject to native findings. Reusing OpenSSL reduces
the possible number of additional programs; program count is not the gate.
T03–T06 and professional release work remain open. Deeper workflows, comparative
benchmarks, credentials and paid/live evaluation remain deferred.

The owner deferred proposal work until **November 2026**. PR #31, proposal
sources, private PDF and email draft remain unchanged here. Refresh their evidence
and resolve the stale proposal branch then, with a separate submission decision.
No external target use, publication or submission is authorized by this slice.

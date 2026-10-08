# Owned TLS peer-certificate metadata

C15 is accepted in [PR #69](https://github.com/0xsl0th/recon-cockpit/pull/69),
merged as `e4c9d64` after independent review and five final CI passes. It adds
`openssl_peer_certificate_v1` through the existing secure CLI, authority, OpenSSL
runtime and evidence path. Accepted coverage is **40 profiles using 15 external
programs**. Forty bounded profiles do not mean forty independent tools or
professional engagement readiness. G1–G6 are complete for this finite profile.
No GUI workflow or real-network attachment is added.

## Exact operation and authority

One TLS connection to the owned `127.0.0.1:8080` endpoint uses fixed SNI and hostname
verification for `harbordesk.test`, a dedicated public synthetic fixture CA,
TLS 1.3 and `TLS_AES_256_GCM_SHA384`. The invocation is fixed:

```text
/tool/openssl s_client -4 -connect 127.0.0.1:8080
  -servername harbordesk.test -verify_hostname harbordesk.test
  -verify_return_error -CAfile /tool/data/fixture-ca.pem -no-CApath -no-CAstore
  -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384 -no_ign_eof
  -showcerts -nameopt RFC2253 -verify_quiet -no_ticket
```

The worker supplies EOF, so no HTTP, credentials, application data or interactive
input follows the handshake. There is no client certificate, session resumption,
retry, cipher sweep, OCSP/AIA fetch, DNS resolution or returned-name follow-up.
Five-second execution, 8192-byte combined stdout/stderr and 60-second session limits
remain. Proposals cannot select an endpoint, CA, certificate, cipher or command.

The dedicated server uses TLS 1.3, requires exactly the fixed SNI and sets
`SSLContext.num_tickets=0`. This matters because disabling stateless tickets with
OpenSSL `-no_ticket` alone does not suppress every TLS 1.3 ticket mode. The owner
never sends session tickets; session material is not part of this observation.
The new owner key is deliberately public synthetic test material with a documented
small P-256 scalar. Only the owner receives it. The tool receives the public CA,
and the independent parser receives no key, private input or network authority.
Existing trust anchors and accepted fixtures remain unchanged.

The [policy](../examples/secure-agent-tls-certificate-policy.json) requires fresh
exact-action approval. Scope, audit-before-execution, one-use admission, namespace
and destination confinement, Landlock and seccomp remain mandatory. Failure of a
required boundary cannot fall back to a host command.

## Owner progress and complete results

Before responding, the owner non-destructively peeks at a nine-byte ClientHello
prefix. It requires a handshake record with legacy record version 3.1, ClientHello
message type, matching record/message lengths and total record size at most
4096 bytes. This finite check is intentionally **not a full ClientHello validation**
and does not establish trust or a completed handshake.

Wrong-name, expired, untrusted, malformed and stalled negative cases count only
that prefix progress. The four useful cases and three parser-limit cases count a
request only after actual TLS 1.3 and a clean `close_notify` exchange. Application
bytes and ragged TCP EOF cannot satisfy completion. Every case permits at most
one connection and one request. Owner progress alone never makes a useful result;
the successful fixed native invocation and complete independent parse are required.

## What the result means

The networkless parser extracts one bounded leaf certificate from the reviewed
OpenSSL transcript. It checks canonical finite DER framing, validity encodings,
extension uniqueness and a DNS/IP-only subject alternative name (SAN) subset.
The limits are **4096 leaf DER bytes, 16 extensions, eight total SAN entries,
253 ASCII bytes per DNS name and 3072 bytes of compact normalized JSON**. IPv4 and
IPv6 SANs become canonical textual addresses. DNS case and order remain metadata;
a supported leading wildcard is retained literally and does not expand scope.
Duplicate SANs or unsupported name forms remain inconclusive.

The closed ten-field summary contains `parser_version`, `kind`, `semantics`,
`tls`, `leaf_der_sha256`, `not_before_utc`, `not_after_utc`, `subject_alt_names`,
`revocation_checked` and `authenticated_application_session`. The last two are
always false. `tls` separately records the fixed protocol, cipher, verified name
and successful native certificate verification. `subject_alt_names` is `null`
when the extension is absent; a present empty extension is a distinct empty
`dns`/`ip` object. The fingerprint hashes the leaf DER, not its PEM text.

A useful `tls_peer_certificate_observed` result means metadata from a completed
fixture-verified TLS exchange. The parser does not independently verify signatures,
trust paths or revocation. Dates remain certificate contents; replay does not
reclassify historical evidence against the current clock. The native client checks
time/trust/name during execution. Verifying `harbordesk.test` does not verify
ownership of every SAN, an application identity, account access or a vulnerability.

Subject/issuer text, unknown extension values and injected CN instructions stay
raw private evidence; none enters normalized decision fields or grants authority.
The deterministic hostile-certificate trial does not establish real-model
injection resistance. This profile does not add cryptography as a runtime
dependency: it was used once to author public fixture data, while parsing uses
the existing Python standard-library runtime.

## Compatibility and capture limits

The transcript grammar is pinned to the reviewed OpenSSL output and one retained
leaf: the observed P-256/ECDSA-SHA256 certificate and X25519MLKEM768 temporary-key
reporting forms are finite supported text, not a broad algorithm inventory. A displayed peer certificate list is not a verified trust chain. Unfamiliar
output, multiple certificates, unsupported DER/name forms, SAN kinds other than
DNS/IP or larger otherwise valid certificates remain inconclusive. There is no
general X.509 validator, chain inventory, revocation check or arbitrary-server
compatibility claim.

The no-SAN fixture is useful under this pinned client's common-name fallback;
it does not establish universal acceptance or recommend issuing certificates
without SANs. The owner prefix gate requires the reviewed single-record
ClientHello form. OpenSSL's text capture is not a packet capture; evidence cannot
prove the absence of server bytes the client never retains. The parser can reject
unexpected material present in its input, not reconstruct unseen wire data.

## Finite owned scenarios

| Cases | Required interpretation |
| --- | --- |
| `tls-cert-ok`, `tls-cert-multi-san`, `tls-cert-no-san` | Three ordinary useful observations: one DNS SAN, several DNS/IP SANs, and an absent SAN extension. |
| `tls-cert-injected` | Separate useful robustness case: hostile CN remains raw evidence with the verified DNS SAN retained. |
| `tls-cert-wrong-name`, `tls-cert-expired`, `tls-cert-untrusted` | Verification failures remain inconclusive after bounded ClientHello-prefix progress. |
| `tls-cert-unsupported-san`, `tls-cert-too-many-san`, `tls-cert-oversized` | Actual verified TLS and clean close, followed by parser refusal for a URI SAN, nine SANs or a 4098-byte leaf. |
| `tls-cert-malformed`, `tls-cert-stalled` | Malformed TLS or bounded no-response behavior remains inconclusive after prefix progress. |

The oversized certificate is just beyond the independent DER cap while its
complete native transcript fits the existing 8192-byte capture limit. It tests
certificate-size rejection without relying on truncated evidence. All twelve
scenarios use finite compiled public material or a bounded stall; no real service,
account store or external trust infrastructure is attached.

## Run and inspect

Describe the profile without execution:

```sh
.venv/bin/python -m recon_cockpit.secure_agent --describe-tool openssl_peer_certificate_v1
```

Use fresh private paths and personally enter the displayed exact-action approval:

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --network-tool-assessment tls-cert-ok \
  --policy examples/secure-agent-tls-certificate-policy.json \
  --assessment-dir .secure-agent/tls-certificate-review/evidence \
  --audit .secure-agent/tls-certificate-review/audit.jsonl \
  --owned-lab --isolated-audit --isolated-approvals \
  --isolated-launch-admission --isolated-launcher \
  --require-launch-audit --require-launch-approval --execute
```

Inspect saved evidence without restoring approval or execution authority:

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --inspect-assessment .secure-agent/tls-certificate-review/evidence
```

## Completion criteria and validation

C15 must complete **3/3 ordinary tasks and 1/1 separate robustness task** with zero
unnecessary refusals, retain all eight inconclusive negatives after their declared
progress and demonstrate one connection/request, closed owners, finite output,
blocked unauthorized destinations and enforcement boundaries. Approval reuse,
missing-proof rejection, cancellation, private-input exclusion, UDP confinement
remain explicit native gates. Existing resource/task limits remain enforced. Provider calls and cost
must remain zero; latency is descriptive, not comparative overhead.

Full validation passed: **18,396 portable and 39 native tests** (seventeen C15
plus 22 accepted LDAP/OpenSSL regressions). All twelve scenarios retained one
connection/request and closed owners; ordinary usefulness was 3/3 and separate
robustness 1/1, with zero unnecessary refusals and eight inconclusive negatives.
All 24 destination witnesses and 120 boundary fields passed. All 603 frozen source
hashes matched; 103 accepted bundles replayed unchanged with fourteen inherited
receipt links. Scenario wall time was 2688–7001 ms, median 3123 ms, with zero calls
and cost. Two initial test assertions were corrected without changing production
source; both failed runs remain recorded. G6 passed through independent review,
five final CI jobs and the authorized merge. See [verification.md](verification.md).
B0–B8, C1–C15, offline R5, accepted local R6 and the initial GUI remain closed.
Preserve the earlier unexplained C9 stall. Credentials, paid/live evaluation,
external engagements, deeper workflows and comparative benchmarking remain
deferred. Select further work from the [coverage checklist](secure-tool-coverage.md#successive-product-coverage-batches).

## References

[OpenSSL s_client](https://docs.openssl.org/3.5/man1/openssl-s_client/) documents
verification, certificate display and EOF controls.
[OpenSSL TLS options](https://docs.openssl.org/3.5/man3/SSL_CTX_set_options/) and
[Python's ticket control](https://docs.python.org/3/library/ssl.html#ssl.SSLContext.num_tickets)
explain the TLS 1.3 ticket boundary.
[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html) specifies certificate and SAN
structures; this implementation deliberately supports a finite subset.

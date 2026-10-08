# Owned HTTP OPTIONS metadata

C12 adds `curl_http_options_v1` through the existing secure CLI and pinned curl
runtime. Accepted main has 36 profiles using 14 programs after C11/PR #65; this
candidate has **37 profiles using the same 14 programs**. Existing interactive curl
suggestions do not provide this secure OPTIONS profile. No GUI workflow is added.

## Exact operation and authority

The operation sends one fixed `OPTIONS /harbordesk/portal.html HTTP/1.1` request
to owned `127.0.0.1:8080`. Its only headers are the fixed Host, User-Agent
`recon-cockpit-owned-http-options/1`, `Accept: */*` and `Connection: close`.
The owner validates the complete request headers before counting one request;
it never interprets a second request. There is no request body, authentication,
cookie, proxy, redirect, retry or execution of an advertised method.
The shipped [policy](../examples/secure-agent-http-options-policy.json) requires
fresh approval for this exact operation.

The native command is fixed:

```text
/tool/curl --disable --silent --show-error --ipv4 --globoff --http1.1 --proto =http --proto-redir =http --noproxy '*' --proxy '' --connect-timeout 1 --max-time 3 --max-filesize 8192 --retry 0 --max-redirs 0 --include --request OPTIONS --header 'Connection: close' --user-agent recon-cockpit-owned-http-options/1 http://127.0.0.1:8080/harbordesk/portal.html
```

The command retains response headers and body for independent parsing. Curl's
three-second transfer timeout operates within the five-second native deadline;
the session limit is 60 seconds and combined stdout/stderr capture is capped at
8192 bytes. The sealed executable/library closure, empty configuration, confined
network, private namespaces, Landlock, seccomp, audit-before-execution and
consumed-grant launch admission remain in force. Missing prerequisites fail
closed without falling back to the host runner.

## Result meaning and supported framing

The closed eight-field summary records `parser_version`, `kind`, `semantics`,
`status_code`, `allow_present`, `allowed_methods`, `auth_schemes` and
`service_identity_verified`. It uses `semantics: untrusted_http_options_metadata`
and `service_identity_verified: false`. Method tokens remain case-sensitive;
scheme names are lowercase. Both lists are sorted and deduplicated. Realm,
challenge payload, response body and unknown-header text stay out of the summary.

A useful `http_options_observed` result requires one complete supported HTTP/1.1
response. Status 200 or 204 can include an Allow list, an explicitly empty Allow,
or no Allow field. A 401 requires a syntactically valid authentication challenge;
405 requires Allow, which may be empty. A complete 401/405 is useful metadata,
separate from a policy denial or unnecessary refusal. Process success or an owner
request counter alone cannot establish useful completion.

The independent parser accepts at most 4096 bytes of retained header text,
32 header fields, 1024 bytes per line and 4096 body bytes, within its 8192-byte
total. It accepts at most 16 method tokens and eight authentication-scheme names,
each at most 32 ASCII token bytes. Authentication parsing also bounds the combined
challenge text to 2048 bytes, 16 challenges, 16 unique parameters per challenge,
512 decoded value characters and 64 list separators. The Allow grammar permits
at most 64 list members, including empty members. Challenge parsing supports a
finite subset of the generic grammar; it does not verify an authentication mechanism
or establish authentication readiness. For example, the valid leading-empty
authentication-parameter form `WWW-Authenticate: Basic , realm="x"` is unsupported
and remains inconclusive. This is not full RFC authentication-header compatibility.

Headers require CRLF framing and ASCII values; horizontal tab is permitted where
supported. Folding, transfer/content encoding, trailers, upgrades, proxy challenges
and ambiguous duplicate fields are unsupported. Only Allow and WWW-Authenticate
can repeat. Non-204 responses require canonical Content-Length exactly matching
the retained body. A 204 must have neither Content-Length nor body. Retained
unsupported, incomplete, malformed or oversized responses remain inconclusive.

These limits describe accepted retained evidence, not a general HTTP validator.
Curl can stop after the declared content length or a bodyless status and omit later
wire bytes from its output. The parser cannot inspect bytes curl never emits;
there is no claim to exhaust or validate the entire wire stream. Nor does a method
advertisement prove actual support, authenticated access, a vulnerability or
authorization for a follow-up request. A hostile unknown header remains private raw
evidence and does not establish real-model injection resistance.

## Finite owned scenarios

| Cases | Required interpretation |
| --- | --- |
| `http-options-ok`, `http-options-no-content` | Useful 200 and bodyless 204 method advertisements. |
| `http-options-absent-allow`, `http-options-empty-allow` | Useful, distinct missing-field and explicitly empty-list observations. |
| `http-options-auth-required`, `http-options-method-not-allowed` | Useful 401 scheme hints and 405 method advertisements; no login or alternate method. |
| `http-options-fragmented`, `http-options-injected` | Separate useful robustness trials; fragmented delivery preserves framing, hostile unknown-header text remains inert. |
| `http-options-malformed`, `http-options-truncated` | Invalid method token or incomplete declared body remains inconclusive. |
| `http-options-stalled`, `http-options-output-limit` | Deadline or bounded-capture pressure remains inconclusive with owner cleanup. |
| `http-options-redirect-ip`, `http-options-redirect-port` | Unsupported 302 remains inconclusive; the destination is never followed. |

Every fixture is finite. The deliberate pressure response is under 16,384 bytes;
the request limit is 2048 bytes, with one connection and one counted request.
There is no application backend, method dispatcher, credential store or network
attachment beyond the disconnected owned fixture.

## Run and inspect

Describe the capability without execution:

```sh
.venv/bin/python -m recon_cockpit.secure_agent --describe-tool curl_http_options_v1
```

Use fresh private paths with the shipped policy. Personally enter the approval
phrase presented for the action:

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --network-tool-assessment http-options-ok \
  --policy examples/secure-agent-http-options-policy.json \
  --assessment-dir .secure-agent/options-review/evidence \
  --audit .secure-agent/options-review/audit.jsonl \
  --owned-lab --isolated-audit --isolated-approvals \
  --isolated-launch-admission --isolated-launcher \
  --require-launch-audit --require-launch-approval --execute
```

Inspect the saved evidence without restoring an approval or execution session:

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --inspect-assessment .secure-agent/options-review/evidence
```

## Completion and validation

Require **6/6 ordinary and 2/2 separate robustness completions**, zero unnecessary
refusals, and six inconclusive negative cases after actual request progress.
All 28 forbidden-destination witnesses and 140 boundary fields across the fourteen
cases must pass, with zero unauthorized destination successes, closed owners,
complete bounded raw evidence and unchanged independent replay. Five native
authority gates cover one-use approval, missing consumed proof, cancellation,
private-input exclusion and broadened UDP. Keep descriptive execution latency and
zero provider calls/cost visible; comparative overhead remains deferred.

**C12 validation is in progress.** Final portable/native totals, clean-source
execution and inherited replay receipts are pending. Record actual results in
[verification.md](verification.md) before marking this candidate ready for review.
Passing synthetic approval tests does not claim personal acceptance. Review,
hosted checks and a merge instruction remain separate acceptance gates.

B0–B8, C1–C11, offline R5, accepted local R6 and the initial GUI remain closed.
The earlier C9 stall cause remains unresolved. Credentials, paid/live evaluation,
external engagements, deeper workflows and comparative benchmarking remain
deferred. The next coverage recommendation is recorded in the
[checklist](secure-tool-coverage.md#successive-product-coverage-batches).

## Protocol and client references

[RFC 9110 OPTIONS](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.7)
defines resource-specific communication options, and its
[Allow section](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.1)
describes method advertisements. The narrower accepted grammar and bounds above
are this profile's contract, not claims about all valid HTTP responses.
The [curl manual](https://curl.se/docs/manpage.html#-X) documents custom request
methods and transfer controls. Installed-client behavior still requires actual
owned execution; protocol documentation is not execution evidence.

# R5b: controlled provider call, disabled by default

This is the second half of R5b, built on the R5a isolation machinery and
[PR #14's monetary ledger](https://github.com/0xsl0th/recon-cockpit/pull/14).
The operator explicitly required **offline development and verification** with
owned/mock fixtures. No external provider API, real credential or paid call was
used. Live behavior remains unvalidated and disabled by default.

The sole supported application entry point is `ControlledProviderCall.run` in
`recon_cockpit.secure_agent.provider_pilot`. It is a standalone diagnostic profile,
not connected to the assessment runner, planner loop, CLI or future GUI. It sends
one fixed synthetic ACK prompt and returns a boolean acknowledgement with an
attempt ID and usage-derived cost. It cannot accept engagement data, arbitrary
prompts, tool definitions, URLs, model choices or output actions.

## Narrow provider profile

| Setting | Contract |
| --- | --- |
| Provider API | One HTTPS `POST /v1/responses` |
| TLS identity | `api.openai.com`, certificate and hostname verification required |
| Destination | Explicit operator-pinned public unicast IPv4, port 443 |
| Model | `gpt-4.1-mini-2025-04-14` |
| Request | Fixed synthetic prompt and strict `{"ack":true}` JSON schema |
| Output allowance | 128 tokens |
| Features | No tools, streaming, background jobs, storage or truncation; default service tier |
| Transport | HTTP/1.1, explicit CA PEM, no DNS, proxies, redirects or retries |
| Response bounds | 8 KiB headers, 64 KiB decoded body, bounded chunk framing; no compression or trailers |
| Lifetime | One invocation per broker and transport, one shared monotonic deadline of at most 120 seconds |

The snapshot and full context allowance come from the official
[GPT-4.1 mini model documentation](https://developers.openai.com/api/docs/models/gpt-4.1-mini).
Request fields and cumulative usage follow the
[Responses API reference](https://developers.openai.com/api/reference/python/resources/responses/methods/create).
The input estimate is a planning assumption, not measured tokenization. No
token-count API call or additional provider request is made.

## Monetary admission and recovery

The caller supplies an existing writable ledger, an action scope beneath its
engagement/session ancestry, a durable `AuditSink`, an explicit versioned USD
`PriceCard` and a per-call ceiling. There is no bundled production price default.
Owned mode requires a `simulation` ledger; live mode requires a `provider` ledger.

1. Reject disabled execution and invalid controls before runtime, credential or
   network access. Allocate a fresh process-local attempt; reopening a ledger
   never restores execution permission.
2. Record a forecast of 512 input and 32 output tokens. Reserve the **entire
   documented 1,047,576-token context plus 128 output tokens**, using the more
   expensive input rate for the ceiling. Check the per-call cap and every capped
   ancestor atomically before starting the runtime.
3. Persist the reservation audit and establish the credential-free sandbox.
4. Once all sandbox witnesses pass, consume the ledger's one-time dispatch
   claim, rechecking current ancestor limits, and persist dispatch audit. Only
   then open the pinned TCP connection, read the explicit credential file and
   hand the capability and credential to the worker.
5. On a final response with recognized pricing dimensions, settle complete usage
   at the attempt's pinned price. Cached input is a subset of total input. Hash
   the provider response ID for deduplication; retain no raw provider ID or text.
   Settlement precedes ACK release and still happens when the output is rejected
   or the response reports final incomplete output.

The full-context reservation is intentionally much larger than the forecast. In
the owned fixture's example card, the estimate is **256 microUSD**, the hold is
**419,236 microUSD**, and final usage settles to **50 microUSD**. These are
simulation results, not a measured provider bill. A smaller reservation would
need a separately reviewed provider-specific upper bound; request bytes are not
silently treated as input tokens.

Definite pre-dispatch failures cancel the unsent reservation. After the dispatch
claim, timeouts, cancellation, TLS/HTTP errors, malformed or missing usage,
unknown billing dimensions, duplicate receipts and ambiguous transport failures
retain the full hold. Even a connection failure after that claim remains
unresolved. A process crash leaves a durable `dispatched` record and hold.
No retry, automatic expiry or restart releases these funds. Use the existing
[ledger reconciliation controls](provider-cost-ledger.md) when affirmative billing
evidence is available.

Complete usage can exceed the configured allowance: record the incurred amount,
reject the output and let the ledger deny further spending. Admission caps are
not a guarantee that a remote provider will bill exactly according to a request
or an operator-supplied price. `usage_derived` remains distinct from
`billing_confirmed`.

## Credential and network boundary

The trusted host owns the ledger, audit and single literal-IP TCP connection. A
rootless Bubblewrap worker has private user, network, mount and PID namespaces,
a minimal read-only filesystem, bounded resources, no host environment or
terminal, no inherited authority descriptors and no process-creation ability.
It receives no credential until its startup checks pass and dispatch is durable.
Private Unix sequenced packets on stdin carry the bounded bootstrap; a subsequent
`SCM_RIGHTS` message transfers exactly one already-connected socket and the key.
The authority channel closes before TLS or provider bytes are processed.

Owned listening witnesses establish successful baseline connections before an
`inet` DROP firewall is installed. The worker proves those connections are then
blocked, drops all capabilities, enables no-new-privileges, verifies read-only
root and checks process/namespace creation restrictions. A second seccomp layer
denies socket creation, connect, bind, listen, accept, setsockopt and descriptor
sending. It verifies both socket creation denial and `AF_UNSPEC` disconnect
denial, including against the received TCP capability.

That second layer is necessary: a passed socket retains its originating network
namespace. The private namespace firewall does **not** filter that socket, and
without a connect restriction a process could disconnect and reuse it. There is
no host network namespace inside the worker and no slirp/router dependency.
The trusted worker implements one request; this is not a kernel-enforced HTTP
request quota for arbitrary compromised worker code.

Live credentials come only from an explicit operator-owned regular file with no
group/other permissions, no symlink leaf or hard links, and a 512-byte bound.
There is no environment key lookup. The CA PEM is explicit, copied to an
ephemeral private file, mounted read-only and hash-bound to worker bootstrap.
Credential files, ledger and audit directories are never mounted. Keys never
enter argv, environment, audit, result or exception text.

The worker parses bounded JSON and releases only a closed usage/status summary.
Raw model content is never executed or exposed. Literal and JSON-escaped key
reflection are rejected; this is not a universal secret-encoding detector.
Future engagement content or actionable proposals need a separate reviewed
release profile and the existing isolated proposal parser.

## Offline verification and later activation

The new Linux tests generate ephemeral owned certificates and synthetic keys,
bind only `127.0.0.1`, and exercise the same socket-transfer, sandbox, TLS, HTTP,
usage, ledger and cleanup path. The owned endpoint uses
`provider.owned.invalid` and a dynamic unprivileged port. Fixture mode rejects
live credential sources, and test guards reject host DNS or external connects.
Portable tests substitute only the transport boundary and use real SQLite
ledgers for admission, settlement and recovery behavior.

```sh
.venv/bin/python -m pytest tests/test_secure_provider_pilot.py
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest \
  tests/test_secure_provider_pilot_linux.py -m integration
```

Constructing `PilotConfig` leaves `enabled=False`. Imports and constructors do no
I/O; disabled calls fail before opening credentials or starting a runtime. No
application command enables this path. A later operator-reviewed activation must
explicitly enable a live config, supply the pinned provider IP and trusted CA,
select a private credential file, review model availability and pricing, and fund
the ledger and call cap. None of that activation is performed by this change.
TLS compatibility, actual provider usage fields and billing still need a later
explicitly authorized live validation. See [verification.md](verification.md) for
the measured offline results and their limits.

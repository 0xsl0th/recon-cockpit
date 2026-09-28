# Owned TLS provider foundation

R5a prepares a credential and network boundary for later real-model evaluation.
It uses an owned TLS server, a fixed synthetic model and newly generated synthetic
credentials. It does not contact a public provider, read API keys or execute tools.
The existing offline authority and 18-run evaluation contract remain unchanged.

## Boundaries

The trusted host constructs a canonical request and reserves each attempt's full
allowance before durable audit and runtime launch. A separate owner process builds
a fresh disconnected network containing only loopback. It starts the TLS fixture
and positive forbidden-destination witnesses before installing the singleton
firewall. Each broker attempt enters that network inside a fresh nested sandbox.
The broker has no network-administration capability, host filesystem, ambient
credentials or inherited namespace descriptors. Its sole destination is
`127.0.0.1:8443`, with TLS hostname `provider.owned.invalid` and the fixed
`POST /v1/responses` path.

Only a private bootstrap pipe supplies the synthetic credential and explicit test
CA. The owner receives its synthetic expected credential through its own pipe;
only the owner mounts the ephemeral server certificate and private key. The
planner receives neither credential nor CA configuration and retains its existing
networkless sandbox. The host bootstrap, installed runtime and kernel remain
trusted. This does not protect against a compromised host owner.

The first data-release profile, `owned-status-v1`, permits only a bounded step
number and an allowlisted previous execution status. It emits an empty observation
body. Raw tool bodies, paths, headers, rationale, artifact identifiers and arbitrary
status strings are not outbound data. The broker reconstructs the request and
requires exact equality with the parser's submission before reserving or sending.
The fixed model identifier is `owned-tls-fixture-model`; there is no configurable
URL, proxy, credential source or real-model selector.

The fixture follows the existing bounded [Responses request format](https://developers.openai.com/api/reference/python/resources/responses/methods/create).
`store`, streaming and background processing remain false, with no provider tools.
Successful fixture output is an inert done proposal, parsed through the existing
isolated codec. These choices demonstrate local transport and decoding behavior,
not provider availability, retention guarantees or useful model performance.

## Reservations and failures

Every attempt reserves one call, canonical request bytes, the complete output-token
allowance and synthetic cost units. The mock tariff is an integer sum of fixed
attempt units, input-byte units and reserved output-token units. These are synthetic
accounting tests, not input-token measurement or actual monetary spending.

Reservation precedes durable audit and every network/credential handoff. Success,
TLS rejection, HTTP failure, timeout, cancellation and malformed responses never
refund an allowance. There are no automatic retries, redirects, DNS lookups or
proxy discovery. A later explicit attempt needs a new full reservation within the
same fixed control lifetime. An audit failure permanently blocks that broker.

One absolute deadline bounds setup, TLS, transfer, parsing and supervision.
Cancellation terminates and reaps the child processes before returning. Receipts
record observed cleanup and isolation; unavailable measurements remain unknown.
Kernel and filesystem stalls remain outside a hard wall-clock guarantee.

The client requires certificate and hostname verification with its explicit CA,
using Python's [TLS client context](https://docs.python.org/3/library/ssl.html#ssl.PROTOCOL_TLS_CLIENT).
HTTP framing and body/header sizes are bounded. Redirects, unsupported encodings,
ambiguous lengths, truncated responses and non-success statuses fail closed.
Responses reflecting the synthetic credential directly or through JSON string
escapes are rejected before returning bytes to the planner. This is not a claim
that arbitrary secret encodings can be discovered. Raw requests, responses,
Authorization headers, credentials and exception text never enter audit events.

## Run the foundation demo

```sh
.venv/bin/python scripts/secure_agent_provider_demo.py
.venv/bin/python scripts/secure_agent_provider_demo.py --execute \
  --audit .secure-agent/provider-foundation/audit.jsonl
```

The first command only prints a plan. Execution requires the normal Linux
namespace prerequisites, non-setuid Bubblewrap, distribution Python, nftables,
nsenter and OpenSSL. Run as an unprivileged user. The demo prints a safe JSON
summary; non-success outcomes exit with status 2. `--scenario` selects only fixed
owned adversarial fixtures, and `--max-seconds` bounds the entire attempt.

## Verification scope

Portable checks cover canonical data release, full-attempt reservations, audit
failure, immutable control lifetimes, receipt validation, TLS configuration and
strict HTTP framing. Actual Linux tests additionally exercise every fixed TLS
scenario, the singleton firewall against listening forbidden destinations,
host-file/environment/descriptor canaries, active cancellation and deadlines,
and observed process cleanup. The successful response passes through the
separate networkless parser before becoming an inert proposal.

The credential worker checks inherited descriptors before importing its runtime.
Later imports can retain descriptors to mounted runtime libraries; the adversarial
test separately checks that host canary and namespace handles are unavailable.
See [the verification record](verification.md) for measured results and review
limits. Hosted portable CI does not establish Linux kernel enforcement.

## Follow-up gate

Real-provider work remains separate: explicitly choose the permitted data,
model, credential source and spending ceiling; validate model-specific input and
output accounting and a real egress topology. Then run a small live pilot before
comparing the same seeded assessments against the preserved 18-run baseline.

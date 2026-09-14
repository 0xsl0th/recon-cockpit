# Offline OpenAI broker and isolated parser

This milestone 2 slice connects synthetic OpenAI Responses envelopes to the
existing session runner. It implements request accounting, audit-before-exchange
and framed communication with a Linux-isolated parser. There is no network send,
API key lookup, SDK client or live-mode flag. The selected model identifier is
operator configuration; offline acceptance does not establish model availability
or account access.

## Run it

Use the existing Kali/Linux prerequisites from [planner isolation](provider-isolation.md).
Run as a normal user with non-setuid Bubblewrap, distribution Python and native
libseccomp. The parser requires real isolation even when tools are in dry-run.

```bash
python -m recon_cockpit.secure_agent \
  --openai-offline three_step --openai-model offline-fixture-model --dry-run

python -m recon_cockpit.secure_agent \
  --openai-offline endless --openai-model offline-fixture-model \
  --broker-max-calls 2 --session-max-steps 4 --dry-run

python scripts/secure_agent_openai_demo.py --execute-fixtures \
  --audit .secure-agent/openai-offline-demo.jsonl
```

`offline-fixture-model` is deliberately a synthetic model identifier. The CLI
requires an explicit `--openai-model`. Named scenarios supply fixed response
bytes: `three_step`, `injection_target`, `injection_authority`, `refusal`,
`malformed`, `incomplete`, `timeout` and `endless`. The timeout scenario delays
its synthetic response for 30 seconds; use a short `--session-max-seconds` to
exercise the deadline. Injection scenarios supply a hostile second proposal
even during a tool dry-run. This demonstrates handling of hostile API output;
it does not simulate an actual model's reaction to the previous observation.

Normal `--fixture --execute` still requires human approval under the default
policy. The standalone demo instead declares an explicit fixture-only unattended
allow policy and never issues human grants. Test callbacks which exercise fresh
approval and stale-grant rejection are mechanism tests, not human decisions.

## Ownership and messages

The host adapter owns an `OfflineOpenAIBroker`, the audit sink and a fixed
`LinuxOpenAIPlanner`. Only bytes cross the parser boundary. Each planning step
uses a fresh process and this single dialogue:

| Direction | Frame | Payload |
| --- | --- | --- |
| Host → parser | INIT | Trusted model/token configuration and bounded session observation |
| Parser → host | REQUEST | One canonical Responses request body |
| Host → parser | RESPONSE | One bounded synthetic API response body |
| Parser → host | RESULT | Validated proposal and the seven required boundary-check booleans |

Frames use a four-byte unsigned big-endian length followed by a one-byte type
and payload. The supervisor enforces message order, sizes, complete frames,
output limits and process exit. It handles partial reads/writes, cancellation,
deadlines and cleanup through nonblocking pipes. No repeated REQUEST or extra
RESULT is accepted within a step. A shared session deadline also covers runtime
inspection, broker work, approval waiting and tool execution.

The worker installs the existing namespace/capability/syscall/resource boundary
before reading input or loading the fixed codec. Read-only mounts contain only
distribution runtime files and the fixed parser/protocol/model modules. The
controller, audit sink, policy, broker, tool backend and credential sources are
absent. Socket creation is blocked. Host handling of REQUEST bytes still treats
the parser as untrusted: the broker compares the entire request with its own
canonical reconstruction from trusted configuration and the original observation.
The parser cannot substitute a URL, model, prompt, tool list, proxy or headers.

The codec contract remains `POST https://api.openai.com/v1/responses`,
`store: false`, no tools, streaming, background processing or automatic
truncation, and a strict Structured Outputs schema. The existing
[Responses create reference](https://developers.openai.com/api/reference/python/resources/responses/methods/create)
defines `max_output_tokens` as including visible output and reasoning tokens.
Refusals, incomplete results, malformed output and forged action fields are
rejected by the isolated decoder. Schema-valid proposals still traverse the
session's policy, approval and audit checks.

## Reservations and audit

| Operator setting | Default | Maximum |
| --- | --- | --- |
| `--broker-max-calls` | 3 | 16 |
| `--openai-max-output-tokens` per exchange | 1024 | 4096 |
| `--broker-max-output-tokens` across exchanges | 3072 | 65536 |
| `--broker-max-request-bytes` across exchanges | 49152 | 262144 |
| API request body | 16384 bytes | Fixed |
| API response body | 65536 bytes | Fixed |

Every accepted exchange reserves one call, the full output-token allowance and
the serialized request byte count before the durable reservation audit event and
transport handoff. No success, error, cancellation, timeout or untrusted `usage`
metadata refunds those reservations. There are no retries. A non-200 synthetic
HTTP status, including redirects, fails; no alternate destination is followed.
Call/token/request exhaustion produces `broker_call_limit`, `broker_token_limit`
or `broker_request_limit` in the session summary.

These are output-token and byte limits. They do not estimate input tokens,
provider billing or monetary spending. Live use still requires reviewed input
token accounting and an explicit spending policy. Bounds are per broker instance
and process-local; they persist when that instance is reused, but are not
persistent per-user quotas across restarts.

Audit events retain a generated broker ID, sequence/counters, digests and static
outcomes. The CLI/demo records its trusted session/broker correlation and prints
only safe summaries. Raw request/response bytes, credentials, headers, rationale
and exception details are omitted. Audit errors permanently block further
exchanges on that broker. Already handed-off work cannot be rolled back if
completion logging fails. `broker_request_reserved` records intent and allowances;
it does not prove the transport was reached. `broker_exchange_finished` records
the transport outcome, not the isolated parser's acceptance or a tool decision.

## What remains before live evaluation

The offline transport checks a fixed method, destination and mandatory TLS
verification setting, then supplies a preconfigured bounded response. It never
resolves a host, opens a socket, reads environment credentials or loads a client.
That contract is not TLS or credential-isolation evidence. The broker is trusted
code in the controller process; sandboxed request bytes cannot replace it, but
arbitrary Python injected into the host process is outside the boundary.

Before any live evaluation, implement and review a transport with verified TLS,
fixed destination and proxy/redirect handling, narrowly scoped credential access,
bounded streaming reads, and cancellation that cannot leave an unaccounted
request running. Establish input-token/spending limits and approved evaluation
data. No live switch or credential configuration is introduced by this slice.
Real VPN-target work remains deferred.

The synchronous transport callback is trusted and must cooperate with shared
deadline/cancellation checks. The fixed offline implementation does; an arbitrary
blocking Python callback is not made preemptible by this protocol. Host kernel,
filesystem and fsync stalls remain outside hard deadline guarantees. Installed
runtime/bootstrap code and the Linux kernel remain trusted. Boundary booleans
and local audits are not cryptographic attestation or proof of universal
prompt-injection resistance.

See [verification.md](verification.md) for observed portable, kernel, demo and
hosted CI outcomes, kept separate from these design requirements.

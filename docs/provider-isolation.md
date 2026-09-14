# Planner isolation and offline OpenAI contract

This second milestone 2 slice establishes a Linux planner sandbox and an offline
OpenAI Responses API contract. The operator selected OpenAI as the first model
provider and explicitly requested that live calls remain disabled. There is no
API transport, SDK client, credential lookup, model download or model generation
in this slice. The runnable provider is still a deterministic bundled mock.

The subsequent [offline broker slice](offline-openai-broker.md) now connects
synthetic API responses through a framed Linux parser and trusted request
accounting. Live transport and credential retrieval remain unavailable. The
isolated mock described below remains a separate selectable provider.

## Run the isolated planner

Use the existing Linux prerequisites: distribution Python, non-setuid Bubblewrap
and native libseccomp. `ldd` resolves the explicit runtime files. Planner-only
operation does not require nftables or slirp4netns. Fixture execution still needs
its existing prerequisites.

```bash
# Three isolated planning steps; no HTTP tool execution
python -m recon_cockpit.secure_agent --isolated-session-mock three_step --dry-run

# Verify planner restrictions and print safe evidence
python scripts/secure_agent_planner_demo.py --audit .secure-agent/planner-demo.jsonl

# Also execute owned fixtures and reject malicious follow-up proposals
python scripts/secure_agent_planner_demo.py --execute-fixtures --audit .secure-agent/planner-fixture-demo.jsonl
```

Each planner invocation creates fresh namespaces and consumes the existing
session deadline and step allowance. The default portable `--session-mock`
remains available for its explicitly trusted fixed script. Selecting
`--isolated-session-mock` always requires Linux isolation, including for tool
dry-runs. Missing or failed isolation stops the session with
`session_component_failed`; it never switches to the portable mock.

To retain normal human approval for tool execution, use
`--isolated-session-mock three_step --fixture --execute` with the default policy
in a human terminal. The demonstration instead declares its own fixture-only
unattended allow policy and issues no human grants.

## Enforced planner boundary

The dedicated command creates private user, network, PID, IPC, UTS, cgroup and
mount namespaces. It maps one nonroot host user to namespace UID/GID 0, drops
all capabilities, clears the environment and starts a new session. The only
host mounts are distribution Python/stdlib, explicit native runtime libraries
and the two fixed read-only planner files. It does not mount the probe worker,
nftables, repository, home, policy, audit, credential files, host sockets or a
network transport. Root, `/proc` and `/dev` are read-only; writable `/tmp` is a
private 1 MiB filesystem.

The trusted bootstrap validates namespace identities and the UID mapping,
verifies empty capability sets, sets and verifies `no_new_privs`, and installs
resource limits and a seccomp filter before consuming observations or importing
the fixed planner module. The filter rejects process creation, execution,
namespace changes, dangerous cross-process/kernel operations and socket creation,
including IPv4, IPv6, Unix sockets and socket pairs. No credential or controller
handle crosses this boundary. These are application-selected restrictions;
[Bubblewrap's upstream security description](https://github.com/containers/bubblewrap/blob/main/README.md)
explains why its command arguments determine the resulting boundary.

The bootstrap actively checks socket/fork/unshare failures with `EPERM` and a
root-write failure with `EROFS`. Its bounded transport envelope contains a
proposal and seven boolean checks. The trusted adapter requires the expected
checks and then passes only the proposal to `SessionRunner`. Proposal fields
cannot supply or replace transport evidence. The session still owns strict
proposal validation, policy, approval and auditing.

| Bound | Value |
| --- | --- |
| Planner observation | 8192 bytes, retaining only the prior response excerpt |
| Proposal | 16384 bytes |
| Combined stdout/stderr transport | 20480 bytes |
| Planner subprocess wall time | At most 5 seconds, also limited by remaining session time |
| Address space / CPU / open descriptors | 256 MiB / 7 CPU seconds / 64 descriptors |
| File size / core dumps / process resource limit | 1 MiB / zero / one process |

The supervisor handles nonblocking pipes, deadlines, cancellation and process
cleanup. Runtime discovery also receives session control. Bootstrap reports
static errors only; raw response text, environment and exception details never
appear in public failures.

## Offline OpenAI contract

`openai_protocol.py` constructs request bytes and decodes synthetic or saved
response bytes. It has no send operation. The fixed future destination is
`POST https://api.openai.com/v1/responses`; a trusted `OpenAIConfig` supplies an
explicit model identifier and bounded `max_output_tokens`. There is no default
model choice or assertion that an offline fixture model is available to an
account.

Model/schema compatibility still needs verification before live use. In
particular, the current schema uses string-length and numeric-range constraints
that the Structured Outputs guide lists as unsupported for fine-tuned models.
Accepting a model identifier's syntax does not validate those capabilities.

Requests use fixed developer instructions for the owned fixture and one bounded
observation as user data. They disable tools, streaming, background processing,
stored responses and automatic truncation. Structured output uses the existing
session schema through `text.format`, with `json_schema`, `strict: true` and
closed object fields. This follows the official
[Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs)
and [Responses create reference](https://developers.openai.com/api/reference/python/resources/responses/methods/create).
`store: false` is a request setting, not a claim of zero retention by the service.

The decoder bounds and strictly parses the response JSON, rejects failed or
incomplete responses, refusals, tool calls and ambiguous assistant output, and
validates the extracted session/action schema locally. Supported reasoning items
are ignored as untrusted data. A completed API status or schema-conforming
action never grants execution authority: policy and human approval remain
separate controller checks.

The codec runs in offline tests/library calls and in the dedicated parser for
`--openai-offline`. That parser uses fixed synthetic responses mediated by a
trusted broker. Tests use no credentials; they prove protocol handling,
not model behavior or provider availability. See the
[offline broker contract](offline-openai-broker.md) for that later integration.

## Remaining live integration boundary

A live transport must preserve the broker's fixed endpoint, HTTP method/path,
mandatory TLS verification and request budgets, and mediate credential access.
A planner must never select a URL,
authorization header, proxy, arbitrary tool, file or retry policy. The broker
must validate model requests against operator configuration, reserve call/token
allowances before sending, bound response bytes, and share deadline/cancellation
control. Retries require explicit accounting; usage metadata must not refund
reserved capacity. No live-call switch is exposed by this implementation.

The isolated mock's one-request/one-response capture helper is not a
planner-to-broker dialogue protocol. The offline broker now uses its own bounded
framed messages with nonblocking supervision and audit-before-exchange. Live
work must validate the TLS/credential boundary before enabling any API request.
Any initial live evaluation must use
explicitly approved data and spending limits. Real VPN-target validation remains
deferred as previously agreed.

## Limits and verification

Installed bootstrap/runtime code and the controller remain trusted. The fixed
mock interface does not authorize loading arbitrary Python plugins. The syscall
filter is a defense-in-depth deny list, not a proof against kernel exploits.
Host compromise, a modified trusted runtime, and hard filesystem/kernel stalls
remain outside the guarantee. Neither these tests nor the offline codec establish
universal prompt-injection resistance or real model autonomy.

```bash
python -m pytest -m 'not integration'
RECON_LINUX_INTEGRATION=1 python -m pytest -m integration -v
```

Portable tests cover launch construction, refused setup/evidence, strict protocol
handling, option selection and shared runtime discovery. Linux tests exercise
actual planner restrictions, host canaries, output floods and cancellation, plus
isolated planning followed by owned-fixture execution. See the latest
[verification record](verification.md) for actual commands and results.

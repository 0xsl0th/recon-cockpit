# R1: offline provider through session authority

## Architecture decision — 15 September 2026

Use the coordinator's existing private stdin/stdout pipes for a fixed version-2
dialogue. No new descriptor, broker object, plugin, network endpoint or generic
RPC operation enters the coordinator. The original version-1 mock path remains
available as a regression reference.

Trusted bootstrap constructs one `OfflineOpenAIProvider`, one
`LinuxOfflineCoordinator`, and one `AuthoritySession` with an optional
`AuthorizedFixtureBackend`. The authority binds the provider to its session ID
once. Its single absolute deadline and cancellation control cover coordinator
bootstrap, each isolated parser, offline broker work, approval and execution.
The host authority, broker, approval UI, audit and launcher remain trusted code
in the same host process; this does not implement further host separation.

### Fixed dialogue

Framing retains INIT/READY/REQUEST/RESPONSE/RESULT and its existing byte limits.
Combined planning responses, including the canonical plan and envelope, must
fit the existing 12,288-byte response ceiling; larger plans fail closed before
being returned to the coordinator. Raw provider proposals remain capped at
16,384 bytes. This deliberately narrows combined-mode capacity.
INIT is exactly `schema_version: "2"` and `session_id`. READY remains the existing
version-1 bootstrap evidence. REQUEST has exactly `schema_version: "2"`,
`session_id`, integer `sequence`, and `operation`, plus `plan` only for `propose`.
RESPONSE is exactly `schema_version: "2"`, `session_id`, `sequence`, boolean
`stop`, and `plan` (a plan object only after successful planning; otherwise null).
RESULT is exactly version 2, the session ID, and `status: "closed"`.

1. Coordinator sends `operation: "plan"` for the next step. The authority checks
   session, sequence and phase, spends one step, and constructs the observation
   from its previous trusted execution outcome. Coordinator requests contain no
   observation, provider configuration, budget, approval or prompt fields.
2. The bound provider runs its existing isolated parser and offline broker. The
   broker compares the parser request to a canonical reconstruction, reserves
   call/token/byte allowances and durably audits before synthetic exchange.
   The authority validates and retains the returned plan, then returns it to
   the coordinator. This response does not authorize execution.
3. Coordinator sends `operation: "propose"` with that plan for the same step.
   The authority requires canonical equality with its pending plan, then applies
   existing action schema, policy, output reservation, fresh approval where
   required, audit and independent executor checks. It clears the pending plan
   and records its own outcome before permitting the next planning request.
4. Done, denial, failure or exhausted session allowances stops further planning.
   Only a host `stop: true` response permits RESULT and clean EOF.

Combined sessions allow at most 32 requests (two per maximum 16 steps); the
original mode retains its 17-request ceiling. No reconnect/reset operation
exists. Wrong sessions, replay, phase violations, changed plans and extra fields
poison the session and cancel outstanding work. Malformed provider output fails
closed. Provider and tool counters remain separate, bounded and nonrefundable;
one provider/broker survives the fresh parser processes. Reusing the session or
rebinding its provider is rejected. A new operator-created session is a new
quota; persistent engagement accounting is outside R1.

### Failure and evidence limits

The supervisors check queued extra output, EOF and stderr overflow before each
callback. Output arriving during a synchronous callback can be detected only
after it returns; completed offline exchanges or executions cannot be undone.
Shared cancellation/expiry and audit failures prevent subsequent work, and both
supervisors kill/reap children. Trusted callbacks cooperate with cancellation;
host kernel/filesystem stalls are not made preemptible.

This path uses fixed synthetic responses and owned HTTP fixtures. It does not
enable credentials, live API calls, routed targets or VPN testing. Linux tests
must distinguish actual OS isolation from synthetic planning and scripted
approval-mechanism tests. No human approval is inferred from unattended demos.

## Run the combined path

Use the existing Linux prerequisites, as a normal user. Real coordinator and
parser isolation is required even when tool execution is disabled:

```sh
.venv/bin/python -m recon_cockpit.secure_agent \
  --control-plane-openai-offline three_step \
  --openai-model offline-fixture-model --dry-run
```

Add `--fixture --execute` for owned-fixture execution under the selected policy.
The default policy requires the operator's fresh terminal approval per action.
Model identifiers and responses here are synthetic. Existing broker/session
limit options apply; `--routed` is rejected for this mode.

The twelve-case demo uses explicit unattended owned-fixture policy:

```sh
.venv/bin/python scripts/secure_agent_offline_authority_demo.py
.venv/bin/python scripts/secure_agent_offline_authority_demo.py --execute-fixtures
```

Cases cover three-step success, hostile scope/authority proposals, refusal,
malformed/incomplete responses, call/token/request/step/output limits and timeout.
Successful parser and executor runs retain separate boundary evidence. The
executed demo expects twelve successful fixture actions across its cases and
checks session/broker audit correlation. It never issues approval grants.

The CLI exposes separate `coordinator_boundary_checks` and
`parser_boundary_checks`, provider counters, and authority summaries. Provider
failures use `provider_failed`; invalid returned plan wrappers or oversized
planning replies use `invalid_proposal`. Broker budget, cancellation and timeout
codes retain their specific reasons. Failed supervisors can clear their
diagnostic boundary checks; such outcomes do not claim a completed dialogue.

See [verification.md](verification.md) for observed results.

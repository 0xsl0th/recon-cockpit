# S3.5: full routed case matrix and native owner enforcement

Pinned before implementation, after [PR #95](https://github.com/0xsl0th/recon-cockpit/pull/95)
merged as `d0586f5`. Its reviewed and merged trees match, and all five final
portable jobs passed 26,878 tests each. Post-merge CI is tracked separately in
the private merge receipt. The [governing Stage 3 contract](stage3-compatibility-routing.md)
still requires this matrix before S3.5 can close. This document grants no action
authority and claims no new native result.

## Selection and compatibility

Add one closed `case_profile` selection, explicitly versioned as routing selection
v3. It requires one of the existing four deployments: `nginx-A`, `nginx-B`,
`apache-A`, `apache-B`. Omitting `case_profile` preserves v1/v2 selection hashes,
action IDs, limits, saved report derivation and immutable inspection exactly.
No arbitrary map, target, case string, command, payload or response-directed
selection is accepted. Reject invalid combinations before runtime inspection.

The baseline map is `http_nmap=O5`, `http_headers=O1`, `ssh_nmap=O1`,
`ssh_keys=O2`. There are exactly twenty named profiles: `baseline`, plus one
`<selector>_<case>` name for every nonbaseline case in the following table. Each
profile commits all four slots and changes at most one baseline case.

| Independent action slot | Cases |
| --- | --- |
| `http_headers` | O1, O2, O3, O4, R1, R2, N1, N2, N3, N4, N5 |
| `http_nmap` | O5, O6 |
| `ssh_nmap` | O1, N1 |
| `ssh_keys` | O2, R1, R2, N2, N3, N4, N5, N6 |

The v3 commitment binds the complete underlying selection/runtime map, expected
outcome contract, deployment, unchanged topology and all existing limits.
Action, policy, launch and evidence identities must agree on that commitment.
The existing lowered-budget presets may combine only with v3 `baseline`;
nonbaseline profiles require the ordinary budget. This avoids ambiguous mixed
fault/budget grading. Every action slot remains independently authorized and
may be selected at most once, with four slots maximum per owner.

The topology remains five owned routed network namespaces, four veth pairs,
the existing fixed service and excluded endpoints, six fixed setup helpers and
eighteen exported descriptors. Preserve the Apache one-use descriptor custody,
SSH preauthentication process boundary, public synthetic content/key and exact
runtime pins. No external route, host network/interface/firewall mutation,
new endpoint, helper or authority is added.

## Budgets and declared-negative stopping

Retain the 60-second owner lifetime; four actions; eight connections; two HTTP
requests; one SSH key exchange; one active connection; at least 250 ms global
admission spacing; 8,466 request, 14,591 response and 26,624 output bytes. All
per-action caps and existing three lowered-budget presets remain unchanged.
Reservations precede delivery and are never refunded or reset by action changes,
failed writes, worker replacement or lost ledger continuity.

In v3, an attempted declared negative ends the explicit action sequence even
when the native client exits successfully with an inconclusive observation.
No later selected slot may launch. Preserve actual native execution status;
expected-negative classification is separate. The last acknowledged ledger and
physical cleanup remain distinct evidence: never invent a graceful final
owner receipt when shutdown is abrupt. This stop is determined by the committed
case, not by hostile returned text or an automatic follow-up decision.

Pre-native authority review found that runner stopping alone would leave a direct
witnessed caller able to request another slot. The owner must therefore become
terminal when a v3 declared-negative action settles, with
`declared_negative_completed` unless an earlier terminal refusal already applies.
This is independent of client status and preserves the real result. Two additional
native owner probes (HTTP N1 and SSH N1 commitments) must demonstrate that a later
ARM cannot reopen the owner or change its counters. A matching backend gate must
reject a subsequent direct witnessed submission before starting its service or
client. Two further native tests exercise that direct route without the trial
runner. These four checks extend the original pinned gate; no originally required
test is removed.

## Outcome and evidence contract

Ordinary and robustness cases must complete usefully with corroborated original
stock-daemon bytes and the accepted parser result. HTTP O3 is a complete 404;
O4 records a 302 without following its Location. Hostile text remains data and
fragmentation must preserve useful delivery. Selected-case expectations replace
the current O1-only header assumption only for v3.

All declared negatives are ineligible for useful completion. Require the exact
fault evidence and allowed classification of the accepted HTTP/SSH case; a
generic refusal is not success. Preserve actual status, original/transformed/
delivered bytes, byte reservations, parser result and classification basis.
SSH N3 requires corroborated withholding, failed/timeout native status, at least
1,900 ms action time, no positive observation and zero delivered response bytes.
SSH N4 retains its independent-recorder wire-cap basis; do not invent a client
overflow exit. SSH N1 may retain the parser's explicitly unidentified result.

HTTP N4 is explicitly adapted to the routed 2,048-byte delivery cap. Preserve a
valid original stock response and the deterministic 2,049-byte transformed
proposal. The owner must deny the whole proposed write with
`action_response_bytes_limit`, before any response delivery. Require exactly one
validated/delivered GET, zero accepted response reservation/delivery, no positive
observation, that exact terminal ledger refusal and verified cleanup. Classify
it as `expected_response_budget_refusal`, with basis
`routing_owner_response_budget_before_delivery`. The client did not observe a
2,049th byte, so this is not standalone client overflow. Validate original-daemon
provenance separately without weakening the standalone complete-delivery check.

Enrich v3 action rows with selected case, classification, basis and expected
negative status. Distinguish useful completed assessments, expected transport
negatives, the adapted response-budget refusal, existing lowered-budget refusal
and incomplete assessments. A passing expected-negative trial is not a complete
legitimate assessment. Unnecessary refusals count only planned ordinary/robustness
work that actually failed, separately from intentional stop after a negative.
Any preceding attempted ordinary action must be useful before a later negative
can make a mixed trial pass. Reject later action evidence after a declared
negative. Preserve v1/v2 report output exactly; new fields and grading are v3-only.

## Frozen native corpus and retained regression gates

Every row starts a fresh owner with the fixed ordinary budget. Both Python and
CLI inspection must reproduce each saved bundle without changing bytes, modes
or timestamps. Freeze source and test hashes before final runs; keep each failed
attempt and its diagnostics separately. No passing retries erase earlier failures.

| New v3 native group | Trials |
| --- | ---: |
| All 13 HTTP cases under each of four deployments | 52 |
| All 10 SSH cases under each of four deployment commitments | 40 |
| Forward and reverse baseline four-action order under every deployment | 8 |
| Three lowered-budget presets under each deployment | 12 |
| Required-approval refusal by default under each deployment | 4 |
| Useful prior action, declared negative, unattempted later slot: HTTP N1/N4 and SSH N1/N3 under each deployment | 16 |
| v3 audit/approval witness denials on nginx-A and apache-B, four faults each | 8 |
| Instrumented native owner/channel probes enumerated below | 24 |
| **New v3 corpus/enforcement total** | **164** |

The first 100 corpus/order trials contain 80 expected useful action executions
and 44 expected-negative executions. The 92 single-action rows comprise 32
ordinary useful, 16 robustness useful and 44 expected-negative executions. SSH
contributes twenty distinct configuration/case combinations, repeated under two
HTTP deployment commitments; total distinct protocol/configuration/implementation
rows are 72. Repeated contexts are not new semantic cases.

Keep all **80 existing native routing checks** separately: legacy v1 ten;
v2 deployment forty; audit/approval witnesses eight; post-useful lifecycle four;
live unconsumed Apache handoff cleanup two; Apache descriptor custody seven;
topology transport eight; malformed bootstrap cleanup one. The combined routing
gate therefore contains **244 tests**, before any explicitly documented additions.
The two owner-enforced negative-stop probes and two direct witnessed-launcher
checks above bring the current required routing gate to **248 tests** (168 new
and 80 retained).
Also retain the **76 accepted-profile/witness regressions**, real saved v1/v2
bundle replay, full portable validation, independent review and required CI.
Native counts must come from the collected test manifest and completed receipts,
not arithmetic alone.

## Twenty-four native owner/channel probes

Run fixed probes against the actual isolated owner and its role-bound channels.
They are instrumented enforcement evidence, not useful daemon traffic. No new
production budget preset, test hook, caller-selected clock or extra action slot
is introduced. Pin each probe separately in the collected native manifest:

1. Cross-role global admission spacing.
2. Overlapping connection refusal.
3. Aggregate request-byte saturation and an excess reservation.
4. Aggregate response-byte saturation and an excess reservation.
5. Per-action request-byte excess.
6. Per-action response-byte excess.
7. Maximum four-action/output reservation and fifth-action refusal.
8. Retained output exceeding its reservation.
9. Real action deadline expiry.
10. Real owner-lifetime expiry and cleanup without extension or replacement.
11. Unwritten/failed-write reservation retained across action settlement.
12. Actual instrumented frontend-channel worker process replacement cannot
    restart its message sequence; do not claim the full production frontend was restarted.
13. Changed profile/selection binding on the selected action.
14. Changed runtime identity.
15. Changed action digest.
16. Operation on the wrong role-bound channel.
17. Replayed message sequence.
18. Changed action sequence.
19. Replayed settled connection lease.
20. Lost channel continuity stops the owner.
21. Post-terminal reservation cannot reopen the allowance.
22. Payload reservation before the required request/key-exchange reservation.
23. Replayed request reservation.
24. Replayed settled selector.

The aggregate byte caps equal the sums of the four slot caps. Probes may reserve
each legal preceding slot to the maximum and attempt one additional byte; they
must not claim those bytes reached a daemon. Full output reservation plus an
attempted fifth/replayed action may be refused by an earlier sequence/unique-slot
check. Record that actual refusal instead of claiming an unreachable aggregate
overflow branch ran. Failed writes and restart probes must retain real owner
identity and counters. Deadline tests use real monotonic time; cleanup cannot
fabricate a final snapshot after owner death.
The owner-lifetime probe records actual elapsed time, process exit/cleanup and
refusal of further work; the outer test watchdog may exceed sixty seconds while
the production owner/session deadline remains sixty seconds.

## Completion and continuation

All declared ordinary/robustness rows must complete without unnecessary refusal;
every negative must have exact corroboration. Preserve live selected-target
usefulness and other-service/excluded/wrong-port denial evidence, audit/approval/
admission order, parser isolation, cancellation, owner death and descriptor cleanup.
Only the complete frozen gates, immutable inspection, regression checks and
independent review can close S3.5. Any discovered need to split a batch must stay
explicit in the roadmap and cannot remove a required gate.

S3.6 name/TLS binding and S3.7 combined acceptance follow in order. Coverage
remains 52 accepted profiles across 17 external programs. Credentials, paid/live
models, attached targets, automatic workflows, comparative benchmarking and
proposal submission remain deferred.

## Development validation checkpoint

Before the final acceptance runs, the unchanged 996-file development source
passed five representative native case trials, all 26 owner/channel probes and
two direct witnessed-launcher negative-stop trials. The case smoke covers HTTP
O3 and adapted N4 plus SSH R1, N3 and N1. These are development checks, not the
complete 248-test gate. Portable reviews retain 234 initial evidence checks,
22 affected evidence checks after the owner fix, 131 existing/new ledger checks
and 28 backend checks; overlapping focused selections are not added together.

The initial private validation wrapper accidentally combined repository `-q`
with another `-q` during collection, producing per-file counts rather than node
IDs. All three native pytest runs passed without errors or skips, but their
wrapper completeness audits failed with zero captured IDs. Those original
receipts remain unchanged. The corrected collector explicitly clears configured
quiet options and independently records all 248 required native node IDs.
Final runs must have matching collected and completed manifests, frozen source,
zero failures/errors/skips and complete independent evidence review.

Private receipts and failed attempts remain under
`.secure-agent/stage3-routing-matrix-20261015/`. This development checkpoint does
not replace the frozen results below.

## Frozen native and immutable replay results

Implementation `0e09f8240a166e38f936a079e9ca48fb65be5038` passed the complete
**248-test routing gate**: 132 matrix trials, 88 retained/witness checks, 26
owner/channel probes and two direct witnessed-launcher negative-stop checks.
The separate **76 accepted HTTP/SSH/witness regressions** also passed. Every
group completed with zero skips, failures or errors; all 996 source pins stayed
unchanged, and independently compared collected/completed native node IDs match.
The four added review tests preserve all 244 originally pinned cases.

The matrix contains 92 single-action corpus trials, eight action-order trials,
twelve lowered-budget trials, four default approval refusals and sixteen mixed
action trials. Owner probes include a real 60,069 ms lifetime, retained failed
write credits and replacement BudgetChannel worker processes. Replacement
workers are not a claim of restarting the entire frontend. Owner/channel probes
do not count as daemon executions or useful observations. The two direct tests
independently exercise real native HTTP N1 and SSH N1 outcomes, then verify that
a second Controller call is refused before client or service startup.

The original **60 saved v1/v2 bundles** passed **120 Python/CLI inspections**;
all 516 original artifact files retain their bytes, modes and modification times.
The replay receipt `accepted-v1-v2-replay-final-01.json` has SHA-256
`d96ec1c247de53efcf44c3ca5d253e3d7371910a1efc5e940b4d2abd82c2c520`.
The combined native audit `combined-native-final-verification.json` has SHA-256
`8ff71bef68926dc81928093aa0cec4a64529641817dda392888a55c3115cfe85`.
Its `native_passed` status deliberately leaves portable CI pending; it is not
whole-batch acceptance. Independent raw-artifact and source reviews are retained
beside these receipts, with reviewer authorship disclosed.

## Portable fixture correction and final review gate

The full local portable attempt at `0e09f82` completed **27,273 passes and one
failure**, with 1,907 integration tests deselected and no skips or errors. The
failed `test_real_bounded_immutable_control_is_required[invalid3]` constructed
its absolute deadline during collection. By its late execution, the intended
overlong control had expired and correctly raised `session_timeout` instead
of the fixture's expected `provider_invalid_control`. Deterministic aging checks
also showed the old fixture could become valid after 900 seconds. The failed
run and its source hashes remain unchanged in `portable-final-01/`.

The correction changes only this test's parameter factories: it constructs the
same four invalid values immediately before execution, preserving their IDs,
assertions and test count. All **94 broker tests** pass after correction, and
the four corrected cases pass both 900- and 1,001-second collection-aging
reproductions. No production clock, validation or deadline policy changed.
Subsequent source changes are limited to this portable fixture and documentation;
production and native test bytes remain identical to frozen `0e09f82`.

Final portable acceptance requires all five existing Linux/Python 3.11–3.14
and macOS/Python 3.14 CI jobs at the final PR head to pass **27,274 tests each**,
with zero skips, failures or errors and the completeness guard. CI metadata,
logs, exact source head and independent review receipts are recorded in the
private checkpoint and PR checks. The earlier local failure is not represented
as a passing portable gate. The existing fifteen-minute hosted job limit leaves
all native deadlines and resource caps unchanged.

Only review and acceptance of the complete batch closes S3.5. S3.6 name/TLS
binding and S3.7 combined acceptance remain next in order; Stage 3 stays open.

## Accepted merge and next required work

[PR #96](https://github.com/0xsl0th/recon-cockpit/pull/96) merged as `6f60ae0`
after fresh independent source/evidence review and all five
[final CI jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/38800952361)
passed **27,274 tests each**, with 1,907 integration tests deselected, zero
skips/failures/errors and the completeness guard. Reviewed head `104c45d`, CI
merge and actual merge share tree `3a015d929900d07fb2fd62dfc1c516a065788d80`.
The 248 native routing checks, 76 regressions, 996 unchanged source pins and
120 immutable inspections above remain the accepted native/replay evidence.
The original failed attempts remain retained; merge does not erase them.
Private fresh-review and merge receipts are in `.secure-agent/pr96-review-20261015/`.
Post-merge CI is recorded separately from the final PR acceptance gate.

S3.5 is closed. [S3.6a static DNS/TLS preparation](stage3-name-tls-preflight.md)
is current, followed by separately pinned S3.6b native name/trust binding and
S3.7 combined acceptance. Stage 3 has ten logical increments, eight accepted
and two remaining; static preparation alone closes neither remaining increment.

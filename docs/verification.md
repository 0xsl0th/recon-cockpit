# Verification record

## Control-plane privilege separation — 14 September 2026

Implemented on `feature/secure-agent-control-plane`, based on merged main
`ce16c06`. The operator approved a first slice that confines the coordinator and
defines explicit proposal/authorization/execution IPC boundaries. The new
`--control-plane-mock` path uses deterministic scenarios and owned fixtures;
live OpenAI calls, credential retrieval and routed sessions remain unavailable.
See [control-plane.md](control-plane.md) for ownership, IPC and compromise scope.

The persistent coordinator has no policy, approval, audit or execution handle.
`AuthoritySession` owns fixed session identity, mode, limits and deadline, strict
sequence checks, resource reservations and terminal approval. Fresh executors
receive separate private-pipe launch envelopes bound to the complete action,
policy, session, limits, reservations, deadline and per-launch nonce. They
independently validate these before owned-fixture setup. The host authority,
approval UI, audit sink and launcher still share a trusted process; containment
of compromise of that host process is not established by this slice.

Environment: Kali Linux, x86_64, Python `3.14.6`, pytest `9.1.1`, normal host user.
Linux integration and the CLI check ran outside the coding sandbox to create
the required namespaces. No packages were installed and no host network
configuration, real credentials, live API or remote/VPN target was used.

| Command/check | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra --junitxml=/tmp/recon-control-plane-portable.xml` | **1380 passed, 51 deselected**, 11.92 seconds |
| `RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short --junitxml=/tmp/recon-control-plane-linux.xml` | **51 passed, 1380 deselected**, 77.91 seconds |
| `.venv/bin/python -m recon_cockpit.secure_agent --control-plane-mock three_step --dry-run --audit .secure-agent/control-plane-cli-dev.jsonl` | Exit 0, `coordinator_done`, three dry-run decisions, all seven coordinator checks true, zero executions |
| `.venv/bin/python -m compileall -q recon_cockpit scripts`, `.venv/bin/python -m pip check`, `git diff --check` | Passed; no broken dependencies |

Both JUnit files were parsed and contain the expected complete case counts with
zero failures, errors or skips. The CLI audit is mode `0600`, with 14 events,
one closed session and no `execution_started` events.

The 256 new portable cases cover authority-field injection at the envelope,
plan and action levels; replay and cross-session requests; session closure and
no budget refunds; exact-action approval binding; audit failures; deadline and
cancellation checks; malformed/pipelined/truncated/flooded IPC; and launch
nonce/context/schema/policy/limit validation. A concurrency regression verifies
that poisoning the channel cancels an action already waiting for approval.

All 40 existing Linux integrations passed alongside 11 new cases:

- Seven coordinator cases exercise a persistent three-step process, actual
  host-file/environment/descriptor canaries, absent host process memory,
  `EPERM` from tracing and cross-process memory syscalls, absent terminal,
  denied IPv4/IPv6/Unix sockets, memory bounds, malformed dialogue, and killed
  and reaped workers on cancellation, deadline and output flooding.
- One executor case exercises a real independently validated fixture launch.
- Three combined cases run the nine-case dry-run adversarial demo, the
  eleven-case executed-fixture demo, and fresh host approval grants across
  three actions. The executed demo records nine successful owned actions and
  rejects forged authority, replay, wrong-session messages and malicious
  follow-up scope/approval fields. The approval-required unattended case
  launches nothing. Scripted grant callbacks test mechanics, not human consent.

The first coordinator Linux run exposed an overly late inherited-descriptor
check: trusted ctypes/libffi startup had opened a read-only runtime library
descriptor. The check now runs before loading that bootstrap; the runtime can
subsequently open its own mounted library files. The corrected seven-case
kernel run and final complete suite passed. Review also added a final executor
deadline/cancellation check after result parsing, with deterministic regressions,
and checks before fixture creation after privilege setup.

Implementation and bounded parallel reviews covered authority poisoning,
coordinator framing/bootstrap, executor binding and deadline handling. These
checks establish the documented local boundaries and fixture behavior, not an
independent security audit or resistance to host/kernel compromise. Hosted CI
and PR state are recorded separately from this local evidence.

## Offline OpenAI broker — 13 September 2026

Implemented on `feature/secure-agent-offline-broker`, based on tested `3e96e67`
from [PR #3](https://github.com/0xsl0th/recon-cockpit/pull/3). The operator approved
an offline broker/session integration and subsequently requested work on the
open PRs. Live API calls and credential retrieval remain unavailable.

The fixed Linux parser now builds one canonical request and parses one synthetic
Responses envelope over bounded typed frames. The trusted broker compares that
request with its own reconstruction, reserves full call/output-token/request-byte
allowances, requires durable audit before transport handoff and never refunds
from untrusted usage metadata. No retries, endpoint overrides or live transport
exist. The session continues to enforce policy and fresh approval on every
action. See [offline-openai-broker.md](offline-openai-broker.md).

Actual environment: Kali Linux `6.16.8+kali-amd64`, x86_64, Python `3.14.6`,
pytest `9.1.1`, normal host user. Integration tests and the standalone demo ran
outside the coding sandbox to create the required namespaces. No packages were
installed, no host routes/firewall/sysctls changed, and no API or remote/VPN
requests were sent. Synthetic credential canaries in tests are not real keys.

| Command/check | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra --junitxml=/tmp/recon-offline-broker-portable.xml` | **1123 passed, 40 deselected**, 9.67 seconds; no skips |
| `RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short --junitxml=/tmp/recon-offline-broker-linux.xml` | **40 passed, 1123 deselected**, 59.64 seconds; no skips |
| `.venv/bin/python scripts/secure_agent_openai_demo.py --execute-fixtures --audit .secure-agent/openai-broker-dev.jsonl` | **`demo: passed`**, all nine cases, nine successful owned-fixture executions, exit 0 |
| `.venv/bin/python -m compileall -q recon_cockpit scripts`, dependency consistency and whitespace checks | Passed |

JUnit files were checked for complete case counts with no failures, errors or
skips. The 12 new Linux integrations cover full offline demos with dry-run and
executed tools, fresh/refused/replayed approval mechanics, isolated request
construction and response rejection, absent host canaries/descriptors/controller
modules, denied IPv4/IPv6/Unix sockets, and hostile codec floods/cancellation/
deadlines with reaped workers. All 28 earlier integrations also passed.

| Standalone demo case | Verified outcome |
| --- | --- |
| Three-step session | Three successful owned actions, three exchanges, `planner_done` |
| Hostile target | One owned action, second proposal policy-denied with `target_out_of_scope` |
| Forged approval field | One owned action, second response rejected by isolated parsing |
| Refusal / malformed / incomplete response | One reserved exchange each, zero actions, no retry |
| Call / output-token budget | Two actions each, third exchange refused, no refund |
| Delayed synthetic response | One reserved exchange, session deadline, zero actions |

Every successful parser output carried all seven expected boundary booleans;
every successful fixture worker carried all four existing tool boundary checks.
The standalone audit recorded nine closed sessions and nine matched tool
start/completion pairs, with no approval grants or raw request/response bodies.
The demo's explicit unattended policy does not establish human approval. The
scripted approval tests exercise grant mechanics only.

Some parallel tasks stopped at usage limits after saving code/tests. All saved
work was included in the final suites. Follow-up parallel reviews were interrupted
before completion; the parent reviewed the broker, framing, worker, adapter,
session/CLI wiring and documentation directly. This is implementation review,
not an independent security audit. The typed offline transport's TLS flag is a
contract check, not evidence of a verified TLS connection. Output tokens and
request bytes are reservations, not input-token counts or monetary spending.
Hosted CI and PR reviews are tracked separately from this local evidence.

### Hosted cleanup correction and dependent PR maintenance

The first broker [branch run](https://github.com/0xsl0th/recon-cockpit/actions/runs/34776278316)
and [PR run](https://github.com/0xsl0th/recon-cockpit/actions/runs/34776309922)
failed five malformed/truncated-frame tests on macOS 15 / Python 3.14.7.
The supervisor correctly rejected the protocol, but cleanup's short-circuited
`failed or proc.poll()` skipped reaping an exited leader before signalling its
group. Darwin returned `EPERM`, masking the intended protocol error.

Cleanup now polls/reaps first and still sends SIGKILL to the group on failure,
including when a reaped parent's live descendant holds an output pipe. No
permission error is suppressed. A portable OS-behavior regression covers the
unreaped-zombie case, alongside the real descendant/pipe cleanup tests.

After correction, the complete portable suite passed **1124 tests, 40
deselected**, in **9.23 seconds**, with no skips, recorded in
`/tmp/recon-offline-broker-portable-fixed.xml`. All **12 affected OpenAI Linux
integrations** passed again, **56 deselected**, in **27.23 seconds**, recorded in
`/tmp/recon-offline-broker-linux-fixed.xml`. The 28 earlier integration results
above apply to unchanged implementations.

The earlier test-only macOS cleanup fix was also backported to PR #2 as
`fc99758`. Its own checkout passed **609 portable tests, 22 deselected**, in
**5.32 seconds**, without skips. Its
[branch](https://github.com/0xsl0th/recon-cockpit/actions/runs/34776381633) and
[PR](https://github.com/0xsl0th/recon-cockpit/actions/runs/34776384232) CI passed.
PR #3 incorporated that ancestry as `46bdc77` with no tree changes; its
[branch](https://github.com/0xsl0th/recon-cockpit/actions/runs/34776471889) and
[PR](https://github.com/0xsl0th/recon-cockpit/actions/runs/34776473843) CI also passed.
The broker branch incorporates the same ancestry. No PR has been merged into
`main`; dependency order remains #2 → #3 → #4.

After the usage reset, bounded read-only parallel reviews completed: PR #2 at
`fc99758` (session/controller/approval/audit/deadline/cleanup), PR #3 at `46bdc77`
(planner bootstrap/isolation/codec/runtime handoff), and the final broker IPC
cleanup/provider/CLI integration. No concrete new findings were reported.
These are implementation reviews and do not constitute an independent security
audit or approval of live API use.

## Isolated planner and offline OpenAI codec — 12 September 2026

Continued milestone 2 on `feature/secure-agent-provider-isolation`, based on
`467fab0` from [PR #2](https://github.com/0xsl0th/recon-cockpit/pull/2). All five
portable matrix jobs passed for that PR and its branch; PR #2 was marked ready
for review and remains unmerged. The follow-up is kept on a separate branch.
The operator selected OpenAI API as the first real-model direction, with live
calls explicitly disabled initially.

Implemented a dedicated Linux planner boundary with zero capabilities, private
namespaces, read-only fixed runtime, a 1 MiB private temporary filesystem and
seccomp restrictions installed before reading observations or importing the
planner. The bootstrap verifies namespace/capability state and attempts prohibited
socket, fork, unshare and root-write operations. The existing session loop still
validates and authorizes all output proposals. Runtime discovery can now omit
nftables for planner-only execution; the fixture/routed callers retain their
existing runtime closure.

Added an offline OpenAI Responses codec with an explicit operator model/token
configuration, fixed request shape/destination, Structured Outputs and bounded
strict decoding. It has no network transport, credential lookup, SDK dependency
or live-call flag. Synthetic response tests cover invalid/missing output,
refusals, incomplete status, tool calls, ambiguous messages, forged authority,
output/JSON limits and out-of-scope proposals rejected by the session controller.
See [provider-isolation.md](provider-isolation.md) for the contract and the broker
work required before live integration.

Actual local environment: Kali Linux `6.16.8+kali-amd64`, x86_64,
Python `3.14.6`, pytest `9.1.1`, normal host user. No packages were installed.
Kernel tests and demos ran outside the coding sandbox to create namespaces;
there were no host routing, firewall or sysctl changes, real model calls or
remote/VPN probes.

| Command/check | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra --junitxml=/tmp/recon-provider-portable.xml` | **892 passed, 28 deselected**, 5.95 seconds; no skips |
| `RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short` | **28 passed, 892 deselected**, 32.02 seconds; no skips |
| `.venv/bin/python scripts/secure_agent_planner_demo.py --audit .secure-agent/planner-boundary-dev.jsonl` | **`demo: passed`**, three isolated planning steps, zero tool executions, exit 0 |
| `.venv/bin/python scripts/secure_agent_planner_demo.py --execute-fixtures --audit .secure-agent/planner-fixture-m2.jsonl` | **`demo: passed`**, three scenarios, seven planner invocations and five successful owned-fixture executions, exit 0 |
| `.venv/bin/python -m pip check` | No broken requirements |
| `.venv/bin/python -m compileall -q recon_cockpit scripts` and `git diff --check` | Passed |

The six new opted-in integrations demonstrate a real three-step isolated
planner dry-run, combined isolated planning/tool execution, host canary denial,
and hostile-planner cancellation/deadline/output flooding. The owned host file
remained intact; fake credential environment values, an explicitly inheritable
descriptor and the host process's `/proc/<pid>/root` path were inaccessible.
Direct IPv4/IPv6/Unix socket attempts returned `EPERM`. Hostile planner processes
were killed with SIGKILL and already reaped when calls returned. These tests
substitute fixed trusted test files through internal mount construction; they do
not add a public arbitrary-plugin interface.

Every successful planner invocation in the standalone demos reported all seven
expected boundary checks as true. Every successful HTTP worker also reported
all four existing fixture boundary checks true. Both injection scenarios reached
the first owned response, then stopped the next proposal at policy or schema
validation. The demo's JSON report prints these safe booleans; the private audit
records session and action events. Neither is cryptographic attestation. The
demonstration uses its explicit fixture-only unattended allow policy and issues
no human approvals.

Some parallel tasks stopped at a usage limit after saving their files. Work was
resumed, all saved tests were run in the complete suites above, and the final
read-only adapter/worker/codec/CLI review completed. No concrete new security or
correctness bug was found. A documented compatibility caveat remains: the API
schema's length/range keywords are unsupported for fine-tuned models, so selecting
a syntactically valid model ID does not establish support. This implementation
review is not an independent security audit, and offline protocol tests do not
validate real model behavior or account access.

The workflow now runs pushes to this follow-up branch and PRs targeting
`feature/secure-agent-m2`, permitting review of the added slice independently in
[draft PR #3](https://github.com/0xsl0th/recon-cockpit/pull/3). Hosted results remain
separate from the local evidence above. Real API transport, credential mediation,
broker IPC/budgets and live model evaluation remain pending; live calls remain
disabled.

### Hosted CI cleanup correction

For implementation commit `f5b17d3`, the
[PR workflow](https://github.com/0xsl0th/recon-cockpit/actions/runs/34713295830)
passed all five jobs. The separate
[push workflow](https://github.com/0xsl0th/recon-cockpit/actions/runs/34713286291)
failed on macOS 15 / Python 3.14.7: **891 passed, 1 failed, 28 deselected**.
The existing cancellation test verified the expected cancellation, reaped direct
child and EOF from its descendant, then its redundant final cleanup signal
raised `PermissionError` for the already-cleaned process group.

The test now attempts fallback group cleanup only if EOF has not yet verified
success; every original cancellation/descendant assertion remains. Duplicate
pipe readers close even if fallback cleanup raises. A raw bytes literal also
removes an invalid-escape warning while preserving the malformed JSON surrogate
fixture. These are test-only changes, reviewed without a new finding.

After this correction,
`.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra --junitxml=/tmp/recon-provider-ci-fix-portable.xml`
passed **892 tests, 28 deselected**, in **6.18 seconds**, with no skips. Production
code was unchanged, so the Linux integration and demo evidence above still
applies. Hosted reruns are recorded in the PR checks.

## Bounded mock sessions — 11 September 2026

Recovered the interrupted milestone 2 worktree on `feature/secure-agent-m2`,
based on merged `main` revision `8d7fe69`. The recovered files already contained
the session runner, fixed subprocess planner, shared execution control and
backend/CLI wiring. The initial portable run passed **503 tests, 14 deselected**;
session lifecycle, CLI and real-kernel session coverage and the demo were still
missing. Completed that first implementation slice without replacing the
existing architecture or widening the execution target scope.

The session now has immutable attempt/runtime/output limits, a monotonic deadline
covering planner execution, terminal approval waiting, runtime inspection and
tool supervision, and SIGINT/SIGTERM cancellation. Each accepted action reserves
its full response allowance without refunds. Every follow-up traverses schema,
policy, required fresh approval and durable audit. Session/step events correlate
with controller events; CLI progress and final summary exclude raw feedback.
See [bounded-sessions.md](bounded-sessions.md) for the exact contract.

Actual local environment remained Kali Linux `6.16.8+kali-amd64`, x86_64,
Python `3.14.6`, pytest `9.1.1`, running as the normal host user. Kernel tests and
the demo ran outside the coding sandbox to permit the required namespaces.

| Command/check | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra --junitxml=/tmp/recon-m2-portable.xml` | **609 passed, 22 deselected**, 5.58 seconds; no skips |
| `RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short` | **22 passed, 523 deselected**, 21.78 seconds; no skips; run before the final 86 portable session cases were added |
| `.venv/bin/python scripts/secure_agent_session_demo.py --audit .secure-agent/session-demo-m2-resumed.jsonl` | **`demo: passed`**, six verified cases, exit 0 |
| `.venv/bin/python -m pip check` | No broken requirements |
| `.venv/bin/python -m compileall -q recon_cockpit scripts` and `git diff --check` | Passed |

The standalone demo performed nine successful isolated HTTP executions across
six sessions. Every completed worker returned true `forbidden_ip_blocked`,
`forbidden_port_blocked`, `namespace_creation_blocked` and `capabilities_dropped`
checks. It checked the injection fixture internally and retained only safe
receipt booleans and boundary evidence in its public report.

| Demo case | Observed result |
| --- | --- |
| Three-step plan | Three successes at `/`, `/injection`, `/`; 3072 bytes reserved; `planner_done` |
| Injected target | First fixture response received; second action rejected with `target_out_of_scope`; one execution |
| Injected approval authority | First fixture response received; second action rejected with `unknown_action_fields`; one execution |
| Endless planner with two-step limit | Exactly two executions; `step_limit` |
| 1024-byte session output budget | One execution; second action refused with `session_output_limit`; no second approval or launch |
| Cancellation after first step | Exactly one execution; `session_cancelled`; no next planner invocation |

The eight new Linux integration cases cover those six scenarios plus timeout
and cancellation of an actual running Bubblewrap worker against `/slow`. Both
in-flight stops observed SIGKILL termination and verified the direct child was
already reaped. All 14 earlier fixture/routed integration tests also passed.
Portable process tests additionally cover blocked input, flooded output, runtime
inspection, routed release gates and a descendant retaining output pipes after
its direct parent exits. Session tests cover strict proposal wrappers, fresh
approval/replay rejection, durable audit at launch, audit-failure poisoning,
stops during approval and pre-launch logging, no-refund reservations, concurrency
and single-use lifecycle. CLI tests cover signal-handler restoration, safe
progress, option validation and bounded controlling-terminal reads.

A completed parallel code review found no concrete new authorization or cleanup
bug in the session/provider/controller or execution supervisor changes. This is
an implementation review, not an independent security audit. The unattended
demo explicitly declares a fixture-only allow policy and never manufactures a
human approval. Scripted PTY tests validate terminal mechanics only; the prior
milestone's human approvals remain historical evidence and no new human session
approval ceremony is claimed here.

No packages were installed and no host network configuration was changed. Real
models, arbitrary provider plugins, routed sessions and actual VPN targets remain
unvalidated and outside this slice. Host filesystem/kernel stalls cannot be
hard-preempted; cleanup can extend beyond the deadline. Session budgets are not
persistent per-user quotas across restarts. The portable workflow now includes
pushes to `feature/secure-agent-m2`; hosted results and maintainer review remain
separate from this local run record.

## PR preparation and portable CI — 11 September 2026

Continued `feature/secure-agent-m1` from `6f4adb6`, preserving the clean worktree
and all existing execution controls. Added `.github/workflows/portable-tests.yml`
and documented its scope in the README. The workflow uses standard GitHub-hosted
Ubuntu 24.04 runners with Python 3.11, 3.12, 3.13 and 3.14, plus macOS 15 with
Python 3.14. It runs on pull requests into `main` and pushes to `main` or this
feature branch. It has a ten-minute job timeout, read-only `contents` permission,
immutable official action revisions, no persisted checkout credentials, no
repository secrets or artifact uploads, and no privileged or self-hosted jobs.
Action pins were resolved from the official checkout v7.0.1 and setup-python
v7.0.0 release tags, and their definitions were inspected before use.

The selected suite excludes integration tests explicitly. A JUnit check rejects
empty runs and skipped, failed or errored portable tests, including unavailable
PTY mechanics on the selected POSIX runners. CI never supplies a human execution
grant or runs a real probe. Hosted matrix results are tracked separately in PR
checks; the following results were observed locally on the existing Kali amd64
host with Python 3.14.6:

| Command/check | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra --junitxml=<temporary-report>` | **426 passed, 14 deselected**, 1.97 seconds; no skips |
| Exact workflow JUnit-check code against that report | **426 complete tests**; synthetic empty/skipped/failed/errored reports all rejected |
| `RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short` outside the coding sandbox as the normal user | **14 passed, 426 deselected**, 11.99 seconds; no skips |
| `.venv/bin/python -m pip check` | No broken requirements |
| Workflow YAML parsing, permission/action-pin/matrix assertions and embedded Python compilation | Passed |
| `.venv/bin/python -m compileall -q recon_cockpit scripts` / `git diff --check` | Passed |

The integration rerun used only the disconnected owned lab and fixture. It did
not alter host networking, contact a real remote/VPN target, or repeat the human
approval ceremony. The separately recorded operator approvals below remain the
human evidence; CI and scripted PTY tests do not replace them.

A targeted local static review traced strict proposal parsing, policy checks,
full-digest single-use grants, audit-before-launch and audit-failure poisoning,
minimal namespace/runtime mounts, worker destination rules, bootstrap gates and
bounded process cleanup. No merge-blocking issue was identified in that review;
no runtime change was made during PR preparation. Attempts at parallel agent
reviews stopped at a usage limit and are not counted as completed reviews. This
is not an independent security audit or a guarantee against sandbox escapes.
Maintainer review and passing PR checks remain merge requirements; no merge,
auto-merge or branch-protection change is part of this preparation.

### First hosted CI failure and test-only correction

The [first hosted run](https://github.com/0xsl0th/recon-cockpit/actions/runs/34547888828)
at `2c17192` installed successfully but failed the routed worker mount-order unit
test. That test mocked `routed._trusted_program`, while the reused fixture
command builder actually resolves Bubblewrap through `isolation._trusted_program`.
The installed Kali `bwrap` masked the incomplete test double; clean Ubuntu and
macOS runners exposed it. This was not a real isolation execution failure.

The test now replaces discovery where the command builder uses it and rejects
any unintended host executable lookup. All original read-only mount ordering,
namespace and environment assertions remain. An additional portable regression
checks that the unmodified production command builder still refuses missing
Bubblewrap. No runtime fallback, runner package installation, test skipping or
isolation relaxation was added. The corrected local portable run passed
**427 tests, 14 deselected**, in 1.80 seconds, with no skips. Hosted results for
the corrected revision are recorded separately by its CI checks.

Workflow references: [GitHub's Python test guidance](https://docs.github.com/en/actions/tutorials/build-and-test-code/python)
and [secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use).

## Routed HTTP milestone — 10 September 2026

Continued clean branch `feature/secure-agent-m1` from `915d822` on the same Kali
amd64 host. Added a separate `--routed` backend for one authorized IPv4 literal and
TCP port, retaining the fixture backend and controller approval/audit path.
Design, runtime boundaries, examples and prerequisites are in
[routed-http.md](routed-http.md).

Package setup was performed by the operator in a desktop terminal:
`sudo apt-get install --no-install-recommends slirp4netns`. APT installed only
`slirp4netns 1.3.3-1` and `libslirp0 4.9.3-1`; no upgrades or removals were part of
the request. Existing util-linux is `2.41.3-4`; `/dev/net/tun` was already present.
All application/tests ran as host user `sloth` (UID 1000), outside the coding
agent's outer sandbox for kernel execution. No host firewall, route, forwarding,
NAT, interface or sysctl changes were made. The demo's address configuration is
confined to its disconnected outer lab namespace.

### Actual checks

| Command/check | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest -m 'not integration'` | **426 passed, 14 deselected**, 1.90 seconds |
| `RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short` | **14 passed, 426 deselected**, 12.13 seconds |
| `.venv/bin/python scripts/secure_agent_routed_demo.py --audit .secure-agent/routed-demo-final.jsonl` | **`demo: passed`**, exit 0 |
| `.venv/bin/python scripts/secure_agent_routed_demo.py --interactive --audit .secure-agent/routed-human-1.jsonl` | Operator-entered approval; **HTTP 200, 96 bytes, exit 0** |
| `.venv/bin/python -m recon_cockpit.secure_agent --routed --policy examples/secure-agent-routed-policy.json --proposal examples/secure-agent-routed-action.json --dry-run` | `approval_required`, `dry_run`, exit 0; imported example JSON, no network request |
| `.venv/bin/python -m compileall -q recon_cockpit/secure_agent scripts` | Passed |
| `git diff --check` | Passed |

There were **no skipped tests** in these selected runs. The 66 new portable cases
cover routed target/request restrictions, fixed destination firewall generation,
separate bootstrap gates, minimal mount configuration, bounded multi-process
supervision/cleanup and lab setup refusal. Portable process helpers test control
mechanics, not kernel routing. The 14 integration tests comprise the five
original fixture cases and nine routed assertions over a shared real lab run.
That routed run performs ten real executions: three authorized witness baselines
plus the seven cases below.

| Routed case | Status | HTTP | Retained bytes |
| --- | --- | --- | --- |
| GET `/` | `succeeded` | 200 | 96 |
| HEAD `/` | `succeeded` | 200 | 61 |
| `/injection` | `succeeded`, inert content | 200 | 290 |
| `/redirect-ip` | `succeeded`, not followed | 302 | 127 |
| `/redirect-port` | `succeeded`, not followed | 302 | 127 |
| `/large` | `output_limit`, truncated | 200 | 4096 |
| `/slow` | `timeout` | none | 0 |

Each case reported all four checks as boolean true: forbidden IP blocked,
forbidden port blocked, namespace creation blocked and capabilities dropped.
Baseline actions first obtained HTTP 200 from the allowed service
`192.0.2.10:8080`, the IP witness `192.0.2.11:8080` and the port witness
`192.0.2.10:8081`, each under its own exact allow policy. Restricted cases then
attempted direct sockets to the two forbidden witnesses inside the worker's
filtered network namespace. Both witnesses accepted **zero additional
connections**, including during redirects. Services were outside the execution
namespace and unreachable from the host/LAN. The outer lab controller ran as
UID 1000 with all capability sets zero.

The demo also rejected two out-of-scope policy actions and blocked noninteractive
execution under an approval-required policy. The final audit has 34 events,
exactly ten execution starts and ten completions, and zero consumed human grants.
No raw malicious response text appeared in the audit.

### Human approval evidence

The operator entered the newly displayed challenge directly in the routed lab's
desktop terminal and confirmed exit 0. No agent supplied approval input. Private
`.secure-agent/routed-human-1.jsonl` contains five events with exactly one
`approval_consumed`, one `execution_started` and one `execution_finished`, in
order and sharing the full action/policy digests and non-null approval reference.
The successful completion is timestamped `2026-09-10T18:15:19.269739+00:00` and
records backend `linux-bubblewrap-slirp-v1`, HTTP 200 and 96 bytes. The policy
decision remains `approval_required`; the single consumed grant satisfies it.

Audit files are mode `0600` in ignored `.secure-agent/` (mode `0700`). They and
private setup diagnostics are excluded from the commit. Failed prototype attempts
remain separate from the fresh final demo/human evidence files.

### Failures resolved during implementation

- Direct script invocation initially failed to import its sibling demo helper.
  The script now supports both direct invocation and package import by tests.
- The first worker launch tried to create its routed-script mount after the root
  filesystem became read-only. The new mount now precedes the read-only remounts;
  a regression checks the order. The read-only boundary remains in place.
- Bubblewrap could not bind-mount the nsfs descriptor as an ordinary file path.
  The controller now passes a pinned network namespace descriptor directly to the
  transport via `/proc/self/fd/N`, alongside a separate user-namespace descriptor
  consumed by Bubblewrap. No host directory mount or mutable namespace path was
  added. The worker never receives these descriptors.
- Reusing a diagnostic audit file intentionally failed the demo's fresh-run event
  count check. Final verification uses fresh files. Portable supervised-process
  tests confirm bad/empty readiness messages prevent probe release, and early
  exits or capture/deadline failures reap both process trees. Traffic already
  sent before a later failure cannot be undone; it remains subject to the
  preinstalled destination filter and recorded execution-start event.

This establishes the routed path and kernel destination boundary in the owned
lab, plus the existing fixture behavior. It does **not** establish reachability
of a real remote/VPN target or any real-model/autonomy behavior. External scope
must be supplied explicitly by the operator. TLS, Nmap, CIDR/multi-target
execution and real providers remain future work. The slirp transport is an
additional trusted network component; its compromise is outside the contract.

## Lenovo / Kali amd64 — 10 September 2026

Continued the clean `feature/secure-agent-m1` checkout at `d22e630`; fetched
`origin` without resetting existing work. Host commands ran as `sloth`, UID 1000,
without sudo. No host firewall, route, forwarding, NAT or sysctl changes were
needed. No system packages needed installation or upgrade.

| Environment | Observed value |
| --- | --- |
| `uname -srm` | `Linux 6.16.8+kali-amd64 x86_64` |
| `dpkg --print-architecture` | `amd64` |
| `/etc/os-release` | Kali GNU/Linux Rolling, `2025.4`, `kali-rolling` |
| `/usr/bin/python3 --version` / fresh `.venv` | Python 3.14.6 |
| `bwrap --version` | bubblewrap 0.11.2 (package `0.11.2-2`) |
| `nft --version` | nftables 1.1.5 (package `1.1.5-2`) |
| `libseccomp2` | `2.6.0-2+b1`, both amd64 and i386 installed |
| `libc-bin` | `2.42-13` |
| `/usr/bin/bwrap` permissions | root-owned, mode `0755`, non-setuid |
| Python test dependencies | pytest 9.1.1, pluggy 1.6.0, Rich 14.3.4 |

Setup used `python3 -m venv .venv`, then
`.venv/bin/python -m pip install -e '.[test]'`.
`.venv/bin/python -m pip check` reported no broken requirements. The initial
installation attempt could not resolve the package index inside the coding
agent's outer sandbox; the approved host retry succeeded. That outer sandbox
also restricted `.git` writes and netlink access. The opted-in kernel tests and
demo ran outside it as the normal host user, retaining the application's own
Bubblewrap, namespace, nftables, capability, seccomp and resource restrictions.

### Failures found and fixes

1. The original portable run matched the handoff: **335 passed, 5 deselected**.
   The first opted-in integration attempt returned **5 failed, 335 deselected**,
   with `isolation_unavailable`. Runtime discovery selected the first globbed
   `libseccomp.so.2`, which was the installed i386 library; `ldd` failed before
   any fixture execution. Discovery now queries the fixed distribution Python's
   `MULTIARCH`, validates it, and selects its native library directory. Actual
   runtime discovery resolves 46 explicit files, including amd64 libseccomp.
   Seven portable regressions cover native selection, foreign-only installs,
   invalid runtime metadata and missing transitive dependencies. The runtime
   expects Debian/Kali `/lib/<MULTIARCH>` or `/usr/lib/<MULTIARCH>` layout; other
   layouts fail closed.
2. The first real terminal CLI attempt blocked with `approval_missing` before
   presenting a challenge. Opening `/dev/tty` with buffered text `r+` raises
   `io.UnsupportedOperation: File or stream is not seekable` on this host.
   The CLI now uses separate read and write handles to the controlling terminal.
   It retains exact-challenge, default-deny, full-digest-bound approval and does
   not fall back to stdin. The failed attempt has no execution-start event.
   Nine scripted pseudo-terminal regressions cover actual nonseekable streams,
   exact challenge and single use, blank/incorrect/full-digest input, missing
   terminal and noninteractive rejection; they do not exercise a human approval.
   A mismatch now prints a safe explanation that the challenge uses the displayed
   16-character digest prefix, without printing the entered text.
3. Integration and demo checks previously used `all(checks.values())`, allowing
   empty or incomplete evidence to pass. They now require exactly the four
   expected keys, each the boolean `True`. Nine portable cases exercise this
   evidence validation, including missing, false and nonboolean values.

### Commands and observed outcomes

All commands below run from the checkout. Integration results refer to actual
kernel execution, not test doubles. Final test totals include 25 new portable
regressions (seven runtime, nine evidence-validation and nine terminal cases).

| Check | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest -m 'not integration'` (final) | **360 passed, 5 deselected**, 1.37 seconds |
| `RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short` (final) | **5 passed, 360 deselected**, 4.55 seconds |
| `.venv/bin/python -m recon_cockpit.secure_agent --mock --dry-run` | `approval_required`, `dry_run`, deterministic mock; exit 0 |
| `.venv/bin/python -m recon_cockpit.secure_agent --mock --fixture --execute --audit .secure-agent/kali-noninteractive.jsonl` without TTY | `noninteractive_approval_required`, blocked; exit 2, no execution |
| `.venv/bin/python scripts/secure_agent_linux_demo.py --audit .secure-agent/kali-demo.jsonl` | `demo: passed`; exit 0 |
| `.venv/bin/python scripts/secure_agent_linux_demo.py --audit .secure-agent/kali-demo-final.jsonl` (after strict evidence checks) | `demo: passed`; exit 0 |
| `.venv/bin/python -m recon_cockpit.secure_agent --mock --fixture --execute --audit .secure-agent/kali-human-approval.jsonl` in a human desktop terminal | Operator entered the displayed challenge; one approved execution succeeded, HTTP 200, 100 bytes |
| `.venv/bin/python -m compileall -q recon_cockpit/secure_agent scripts` | Passed |
| `git diff --check` | Passed |

Final demo case results:

| Fixture path | Execution status | HTTP status | Captured bytes |
| --- | --- | --- | --- |
| `/` | `succeeded` | 200 | 100 |
| `/injection` | `succeeded` | 200 | 292 |
| `/redirect` | `succeeded` | 302, not followed | 141 |
| `/large` | `output_limit`, truncated | 200 | 1024 |
| `/slow` | `timeout` | none | 0 |

Every case reported `forbidden_ip_blocked`, `forbidden_port_blocked`,
`namespace_creation_blocked` and `capabilities_dropped` as true. Forbidden
connections used direct sockets toward listening owned witnesses at
`127.0.0.2:8080` and `127.0.0.1:8081` inside the same namespace. The malicious
response remained inert; policy did not change. The demo also rejected an
out-of-scope target, unsupported shell tool and unknown parameters, and blocked
unattended execution under an approval-required policy.

### Human approval and private evidence

Human-terminal command:

```bash
.venv/bin/python -m recon_cockpit.secure_agent --mock --fixture --execute \
  --audit .secure-agent/kali-human-approval.jsonl
```

The first attempt hit the terminal-open defect described above. The second,
using the corrected I/O, recorded `approval_missing`: the operator entered the
full 64-character action digest instead of the displayed 16-character challenge
prefix. Both failed attempts consumed no grant and started no execution.

On the third attempt, the operator entered the displayed challenge in the
desktop terminal. The agent did not supply terminal input. At
`2026-09-10T00:56:55.830722+00:00`, the audit recorded `execution_finished` with
`execution_status: succeeded`, HTTP 200 and 100 bytes received. Its 11 total
events include exactly one `approval_consumed`, one `execution_started` and one
`execution_finished`, in that order. All three share the full action digest,
policy digest and non-null approval reference. The decision remains
`approval_required`, as designed; the consumed grant satisfies it. There are no
unmatched execution starts in this file.

Evidence stays in ignored `.secure-agent/` (mode `0700`); JSONL files have mode
`0600`. Raw audit logs, approval references and response bodies are not committed.
The unattended demo uses its explicit fixture-only automatic policy and is not
human approval evidence. Pseudo-terminal regression inputs likewise test only
approval mechanics, not a human decision.
The final demo audit contains 20 events, five execution-start events and five
matching completion events, with zero human approvals consumed.

### Remaining limits

This validates the owned singleton-loopback fixture on this Kali host. It does
not establish routed authorized-target execution, arbitrary CIDR execution,
real-model autonomy or universal prompt-injection resistance. Routed target
support is the next development milestone; TLS, Nmap, real providers and
PivotTrail integration remain future work. The controls and residual risks in
[the architecture](architecture.md) and [threat model](threat-model.md) still
apply. No Docker-based isolation test was run.

## Mac handoff — 9 September 2026

Environment: macOS/Darwin arm64, local Python 3.11 virtual environment.
Branch: `feature/secure-agent-m1`.

Actually executed:

| Check | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest` | **335 passed, 5 skipped** |
| `.venv/bin/python -m recon_cockpit.secure_agent --mock --dry-run` | `approval_required`, `dry_run`, explicitly labeled deterministic mock |
| `.venv/bin/python -m recon_cockpit.secure_agent --mock --fixture --execute` without TTY | Blocked: `noninteractive_approval_required` |
| `.venv/bin/python scripts/secure_agent_linux_demo.py` | Blocked: `isolation_unavailable`, Linux required |
| `.venv/bin/python -m compileall -q recon_cockpit/secure_agent scripts` | Passed |
| `git diff --check` | Passed |

The passing tests comprise 149 existing workflow tests, 104 strict-model/policy
tests, 57 controller/approval/audit/CLI tests, and 25 portable worker/backend tests.
Portable backend tests use controlled subprocesses or test doubles and do not
establish namespace or firewall enforcement.

The **five real Linux integration cases were skipped**, not passed. They cover
normal HTTP, malicious fixture output, output limits, deadlines, and redirects;
each also attempts direct sockets to listening forbidden IP/port witnesses.
No amd64 Linux, Kali, real kernel firewall, capability-drop, or seccomp success
has been established in this session. No Docker-based isolation test was run.

## Original Kali amd64 follow-up plan (superseded by the record above)

Follow [the handover](handover-kali.md). Record `uname -m`, kernel/distribution,
Python, Bubblewrap and nftables versions, exact commands, test totals, failures
and any fixes. Do not replace a failed isolation check with a mock, an execution
fallback, root execution, broad mounts, or disabled enforcement. Repeat affected
tests after fixing implementation defects, then update this record with actual
evidence. Keep portable and integration results distinguishable.

After all integration cases pass, exercise the human approval CLI in a real
terminal and retain private JSONL evidence of one approved execution. A test
calling the controller's internal approval store proves grant mechanics but is
not a human approval demonstration.

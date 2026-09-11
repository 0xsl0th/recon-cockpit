# Verification record

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

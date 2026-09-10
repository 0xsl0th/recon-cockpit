# Verification record

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

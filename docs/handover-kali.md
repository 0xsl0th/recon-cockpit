# Handover to the Lenovo / Kali amd64

## Current continuation — provider isolation, 12 September 2026

The bounded-session slice is committed as `467fab0` and pushed in
[PR #2](https://github.com/0xsl0th/recon-cockpit/pull/2). Its branch and PR CI passed,
and it is now ready for review. It has not been merged.

The follow-up branch is `feature/secure-agent-provider-isolation`, based on
that tested commit, with review in
[draft PR #3](https://github.com/0xsl0th/recon-cockpit/pull/3). It adds a dedicated Linux sandbox for the fixed planner and
an offline OpenAI Responses API codec. The operator selected **OpenAI API, with
live calls disabled initially**. Preserve that constraint: no credential lookup,
SDK client or outbound API request is part of this slice. Real VPN testing also
remains deferred. Read [provider-isolation.md](provider-isolation.md) and the latest
[verification record](verification.md), then inspect Git status before editing.

```bash
python -m recon_cockpit.secure_agent --isolated-session-mock three_step --dry-run
python scripts/secure_agent_planner_demo.py --execute-fixtures --audit .secure-agent/planner-fixture-demo.jsonl
```

The next live-integration work is a narrowly scoped credential/network broker
with request budgets, bounded framed IPC, TLS verification and audit-before-send;
it must be implemented and tested with live calls disabled before any live
evaluation is considered. The codec currently has no transport and its tests
use synthetic API responses.

## Current continuation — milestone 2, 11 September 2026

PR #1 was merged into `main` as `8d7fe69`. Work now continues on
`feature/secure-agent-m2`, created from that merged revision. The interrupted
session's uncommitted code was recovered from disk and continued in place.
The completed slice passed 609 portable tests, 22 Linux integration tests and
the six-case owned-fixture session demo. Exact commands, limitations and review
status are recorded in [verification.md](verification.md).

The agreed first milestone 2 slice is a bounded three-step owned-fixture mock
session with adversarial follow-ups, session budgets and cancellation. Real
model-provider integration and actual VPN-target validation remain deferred.
Read [bounded-sessions.md](bounded-sessions.md), the latest
[verification record](verification.md), then inspect `git status` and preserve
any local changes. Do not restart milestone 1 or infer that archived branch and
test-count statements below describe the current checkout.

Session entry points:

```bash
python -m recon_cockpit.secure_agent --session-mock three_step --dry-run
python scripts/secure_agent_session_demo.py --audit .secure-agent/session-demo.jsonl
```

Use a fresh audit filename when retaining new evidence. Required checks are the
portable suite and the explicitly opted-in Linux integration suite described in
the verification record. Run kernel tests outside the coding sandbox as the
normal user; they do not require root or host networking changes. A scripted
terminal test is not human approval evidence. Never manufacture an approval.

## Historical milestone 1 handover

The following setup and original prompt are retained as history. The current
branch and latest validation totals are given above and in verification.md.

**Routed continuation:** the separate `--routed` backend now supports one
authorized IPv4 literal/TCP port through a filtered worker and a separately
sandboxed slirp transport. See [routed-http.md](routed-http.md) for package setup,
owned-service validation and remaining limits, and [verification.md](verification.md)
for the latest actual results. A real remote/VPN target still needs explicit
operator scope and has not been exercised.

**Continuation update, 10 September 2026:** Kali kernel integration and the demo
now pass after native libseccomp selection was fixed. The controlling-terminal
I/O was also fixed, and the operator completed one approved fixture execution.
Current totals are 360 portable tests passed and five real Linux integration
tests passed. See [the actual validation record](verification.md) for commands, environment and
remaining limits. The original Mac handoff and continuation prompt below are
historical; their unvalidated-Linux statements describe the pre-Kali state.

Work continues on `feature/secure-agent-m1` in
`https://github.com/0xsl0th/recon-cockpit`. Main is unchanged.
Read [verification.md](verification.md) first for the observed Linux isolation
results and remaining limits. No autonomous model has been tested.

## Get the same work

For a fresh checkout on the Lenovo:

```bash
git clone --branch feature/secure-agent-m1 https://github.com/0xsl0th/recon-cockpit.git
cd recon-cockpit
git status --short --branch
git log -1 --oneline
uname -m
```

Expected architecture: `x86_64`. If the checkout already exists, inspect its
worktree first, then `git fetch origin` and switch to `feature/secure-agent-m1`.
Preserve local changes; do not reset or overwrite an existing branch to match it.
Do not transfer the Mac `.venv`, credentials, or audit logs into the new checkout.

## Prepare and verify

Explicit operator setup (APT needs sudo; the application must run as a normal user):

```bash
sudo apt-get update
sudo apt-get install python3 python3-venv bubblewrap nftables libseccomp2 libc-bin
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'

python -m pytest -m 'not integration'
python -m recon_cockpit.secure_agent --mock --dry-run
RECON_LINUX_INTEGRATION=1 python -m pytest -m integration -v
python scripts/secure_agent_linux_demo.py --audit .secure-agent/kali-demo.jsonl
python -m recon_cockpit.secure_agent --mock --fixture --execute
```

The last command must run in a human terminal. Review the exact action and policy
digests and enter the approval challenge yourself. Blank input denies. The
unattended demo has a separately declared, fixture-only allow policy; it never
pretends to supply a human approval.

Current verified portable total: 360 passed, 5 deselected (335 at the original Mac
handoff). The Linux integration total is 5 passed. The demo must report
`demo: passed`, not merely exit
without a traceback. Its normal and malicious response cases should succeed;
large output should stop at `output_limit`; slow output should hit `timeout`.
Every case must also report true socket-level forbidden-IP and forbidden-port
checks against owned listening witnesses.

If installation or isolation fails, preserve the error and inspect kernel/user
namespace availability, distribution runtime paths, nftables syntax/capabilities,
Bubblewrap flags, seccomp loading, and shared-library closure. Setup exceptions
are intentionally reduced to safe error codes in the public CLI; diagnose in
trusted local code without sending raw response/credential data to audit logs.
The backend expects distribution Python `/usr/bin/python3` with standard library
under `/usr/lib/python3.x`, native libseccomp in `/lib/<MULTIARCH>` or
`/usr/lib/<MULTIARCH>` (the Debian/Kali layout), a non-setuid Bubblewrap, and one
unprivileged host UID mapped to namespace UID 0. Nested-user-namespace behavior and runtime-library
resolution are especially worth checking on the actual Kali version.

No host firewall/route/forwarding/NAT/sysctl change is part of this backend.
If host administration beyond package installation appears necessary, explain
the exact requirement before changing it. Preserve fail-closed controls.

## Original validation prompt from the Mac handoff

Open this repository as the workspace on the Lenovo and paste:

```text
Continue Recon Cockpit — Secure Agent Mode from branch feature/secure-agent-m1.
We moved from a MacBook arm64 to this Lenovo running Kali amd64 so we can validate
the Linux execution boundary. Read repository AGENTS.md if present, README.md,
docs/handover-kali.md, docs/verification.md, docs/architecture.md and
docs/threat-model.md. Inspect git status and preserve unrelated changes.

Implementation already exists in recon_cockpit/secure_agent: strict action and
policy models, a deterministic mock provider, controller-only single-use expiring
approvals, fail-closed JSONL auditing, and a Bubblewrap/nftables fixture backend.
Do not restart or rewrite the architecture. The Mac run had 335 passed and 5
skipped tests. Real Linux isolation has NOT been validated. The backend supports
only its owned 127.0.0.1 namespace fixture; broader literal/CIDR policy support
does not imply routed execution support. Nmap, real models and PivotTrail remain
future work.

Verify x86_64, install the local environment and normal distribution prerequisites
as needed, then run portable tests, the opted-in Linux integration tests, and
scripts/secure_agent_linux_demo.py. Diagnose and fix implementation defects while
preserving destination filtering, namespace isolation, capability dropping,
seccomp, resource/output/time limits, and audit-before-execution. Do not substitute
mocks or host execution for failing integration tests. Do not run the application
as root or expose Docker sockets, credentials, broad host mounts, or new targets.
Explain any required host networking/security changes before making them.

Confirm direct socket connections to the owned out-of-scope IP/port witnesses are
blocked at the execution boundary. Exercise the interactive approval CLI with me
entering the human challenge; don't fabricate a human approval. Keep model/mock,
unit/integration, and run/skipped claims distinct. Update docs/verification.md with
actual environment, commands, results, fixes and remaining limits. Commit and push
reviewable changes to this feature branch. Do not merge main, release, deploy
externally, spend money, or submit competition material.
```

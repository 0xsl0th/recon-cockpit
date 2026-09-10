# Handover to the Lenovo / Kali amd64

Work continues on `feature/secure-agent-m1` in
`https://github.com/0xsl0th/recon-cockpit`. Main is unchanged.
Read [verification.md](verification.md) first: implementation exists, but real
Linux isolation still needs validation. No autonomous model has been tested.

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

Expected portable total at this handoff: 335 passed, 5 deselected. Expected Linux
integration total after successful validation: 5 passed. These latter results
are **not yet observed**. The demo must report `demo: passed`, not merely exit
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
under `/usr/lib/python3.x`, a non-setuid Bubblewrap, and one unprivileged host UID
mapped to namespace UID 0. Nested-user-namespace behavior and runtime-library
resolution are especially worth checking on the actual Kali version.

No host firewall/route/forwarding/NAT/sysctl change is part of this backend.
If host administration beyond package installation appears necessary, explain
the exact requirement before changing it. Preserve fail-closed controls.

## Prompt for the next coding session

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

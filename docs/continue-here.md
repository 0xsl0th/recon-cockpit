# Continue here — 15 September 2026

## Read this first

This is a development checkpoint for interruptions and restarts. It does not
resume a live assessment or restore approvals.

**Latest task:** implement R1, combining the offline provider, isolated
coordinator, authority and fixture executor. The combined path is implemented
on `feature/secure-agent-offline-authority`; see the latest verification record
for measured results. R2 has not started.

Read [offline-authority.md](offline-authority.md), the R2 section in
[roadmap.md](roadmap.md), and the latest [verification record](verification.md).
Read repository instructions and inspect Git before editing.

## Saved state

- Workspace: `/home/sloth/Code/recon-cockpit`, Kali Linux x86_64, normal user.
- Implementation branch: `feature/secure-agent-offline-authority`, based on
  documentation checkpoint `54461b7` above `origin/main` at `bf3a359`.
  Inspect `git log -1`, upstream and current PR status before continuing;
  do not assume a development checkpoint has been merged.
- The operator pushed documentation commit `54461b7`; GitHub branch
  `docs/competition-roadmap` was verified at that commit on 15 September.
- [PR #5](https://github.com/0xsl0th/recon-cockpit/pull/5) is merged. Reviewed
  implementation: `0477f25`; merge: `bf3a359`. Do not repeat its review/merge.
- R1 adds `--control-plane-openai-offline` and the twelve-case
  `scripts/secure_agent_offline_authority_demo.py`. Earlier CLI modes remain.
- PR #5's historical verification was 1,383 portable tests, 51 Linux integrations
  and ten hosted branch/PR checks. Current R1 evidence is the first section of
  `verification.md`; local and hosted checks are separate evidence.
- Current JUnit XML files are `/tmp/recon-offline-authority-portable.xml` and
  `/tmp/recon-offline-authority-linux.xml`; they may disappear after reboot.
  Durable evidence is in `docs/verification.md`.
- Git SSH authentication was unavailable after this restart; GitHub CLI access
  worked. Check actual authentication before assuming a future push will work.
- Old review worktrees under `/tmp/recon-pr2-review` and
  `/tmp/recon-pr3-review` disappeared after reboot; their stale Git registrations
  are historical and were not pruned.

## Intent and constraints

The product direction is authorized pentest workflows with specialist engines
within enforced security boundaries. Challenge 4, security of autonomous
agents, is the competition focus. Planning still uses synthetic responses.

- Keep live API calls and credential lookup disabled. Real use requires a
  reviewed slice with explicit operator data/model/credential/spend settings.
- Real VPN testing remains deferred. Continue with owned fixtures.
- Preserve scope filtering, isolation, fresh approvals, budgets, durable
  audit-before-execution and fail-closed behavior.
- Never expose the legacy host runner, arbitrary shell, credentials, broad host
  mounts or Docker socket to agents. Do not change host networking to pass tests.
- Do not restore/replay approvals or imitate a human terminal response.
- Authority, UI, broker, audit and launcher still share a trusted host process.
- This development work does not authorize competition submission, messaging
  others, paid calls, external target assessment or merging future PRs.

## Completed R1 and next implementation: R2

The combined mode uses `OfflineOpenAIProvider`, `LinuxOfflineCoordinator`,
`AuthoritySession` and `AuthorizedFixtureBackend`. Version-2 PLAN/PROPOSE
operations share the existing pipes, with a maximum 32 requests. The authority
constructs observations, binds the pending canonical plan, owns the shared
deadline and enforces policy/approval/audit/execution. Broker and tool budgets
remain separate and nonrefundable.

The architecture decision records bounded reply sizes and poisoned channels.
Queued invalid coordinator output is checked before callbacks; output arriving
during a synchronous callback can be detected only afterward. An already
completed exchange or execution cannot be undone.

On the next instruction to continue:

1. Inspect Git, PR/CI state and verification. Preserve R1 and unrelated changes.
   Do not repeat completed implementation or merge without operator approval.
2. Begin the smallest R2 design: one seeded, non-destructive HTTP condition in
   the owned fixture, bounded execution/observation/finding contracts, and a
   reviewable Markdown/JSON report. Choose the fixture condition explicitly.
3. Keep the first workflow fixed and preserve R1 boundaries. Additional tools,
   live calls, external targets and generic workflow machinery come later.
4. Implement and validate that slice, then update verification and this
   checkpoint with actual results and publication/review status.

## Recovery and verification

```sh
git status --short --branch
git log -5 --oneline --decorate
git diff --stat
git show --stat --oneline HEAD
.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short
git diff --check
```

Run affected kernel tests outside the coding sandbox as the normal user.
Use fresh audit paths for demos. Distinguish synthetic provider behavior, real
OS isolation and actual human approval evidence. Do not rerun all tests merely
to verify saved documentation.

## Remaining decisions

Reference identities are resolved: Enrique Folte, PentestMonkey,
PayloadsAllTheThings, GTFOBins, LOLBAS, HackTricks and Hack The Box. Exact links
and categories are in the roadmap; do not repeat reference clarification.

Enrique Folte is the identified project contact. Submission role, affiliation
and additional members remain to confirm. These do not block R2. R1 topology is
settled; the seeded HTTP assessment condition is the next design decision.

Proposal deadline: **15 November 2026**. Final development: **20 May 2027**.

## Copy/paste continuation

```text
Continue Recon Cockpit from docs/continue-here.md and docs/roadmap.md.
Inspect Git and preserve saved work. PR #5 is merged as bf3a359.
R1 is implemented on feature/secure-agent-offline-authority; inspect its current
PR and checks. Read docs/offline-authority.md and the latest verification record.
Begin the smallest R2 HTTP assessment/evidence/report slice using one seeded,
non-destructive owned-fixture condition. Do not repeat R1 or merge without approval.
Keep live calls/credentials disabled and real VPN testing deferred.
Preserve enforcement and update the handoff with measured results.
```

# Continue here — 15 September 2026

## Read this first

This is a development checkpoint for usage-limit interruptions and restarts.
It does not resume a live assessment or restore approvals.

**Latest task:** update the competition proposal, plan secure AI pentesting
engines/workflows, and save a restart handoff. No implementation from the new
roadmap has started.

Read [roadmap.md](roadmap.md), especially **R1: the next implementation slice**,
then [competition-proposal.md](competition-proposal.md),
[control-plane.md](control-plane.md), [offline-openai-broker.md](offline-openai-broker.md)
and the latest [verification record](verification.md). Read repository instructions
and inspect Git before editing.

## Saved state

- Workspace: `/home/sloth/Code/recon-cockpit`, Kali Linux x86_64, normal user.
- Documentation branch: `docs/competition-roadmap`, based on `origin/main`
  at `bf3a359`. This handoff is saved with the proposal and roadmap; inspect
  `git log -1` for the documentation commit and check for later changes.
  The documentation checkpoint is local; no new PR or remote push was made.
- [PR #5](https://github.com/0xsl0th/recon-cockpit/pull/5) is **merged**, not waiting
  for review. Reviewed implementation: `0477f25`; merge: `bf3a359`.
- Last implementation verification: **1,383 portable tests**, **51 Linux
  integrations**, **all ten hosted branch/PR checks passed**.
- This task changes documentation only; it is not a new implementation test run.
- The IPC correction rejects queued extra stdout, premature EOF and excessive
  stderr before authority dispatch. Later output may be detected only after the
  authority call returns; an executed action cannot be undone.
- Old XML files were under `/tmp/recon-control-plane-recovered-*.xml`; they may
  disappear after reboot. Durable evidence is in `docs/verification.md`.

## Intent and constraints

The user wants agents eventually to conduct authorized pentest workflows with
specialist engines and attack flows, within enforced security boundaries.
Challenge 4, security of autonomous agents, is the competition focus.
The current foundation uses deterministic/synthetic planning.

- Keep live API calls and credential lookup disabled until explicitly enabled
  for a reviewed slice with operator data/spend settings.
- Real VPN testing remains deferred until the product is ready. No target scope
  was provided by the planning request.
- Next work uses owned fixtures. Preserve scope filtering, sandboxing, fresh
  approvals, budgets, audit-before-execution and fail-closed behavior.
- Never expose the legacy host runner, arbitrary shell, credentials, broad host
  mounts or Docker socket to agents. Do not change host networking to pass tests.
- Do not restore/replay approvals or imitate a human terminal response.
- Host authority, UI, audit and launcher still share one trusted process.
- PR #5's authorized merge is done. The planning task does not authorize
  submitting the competition entry, messaging others, paid calls or merging
  future implementation PRs.

## Next implementation: R1

`--openai-offline` uses `OfflineOpenAIProvider` with `SessionRunner`.
`--control-plane-mock` separately uses an isolated coordinator,
`AuthoritySession` and `AuthorizedFixtureBackend`. Connect them before adding
more tools or engines.

First write a small architecture decision for provider/coordinator/authority
message ownership and bounded IPC. Then implement one combined three-step
offline fixture session: shared authority identity/deadline, separate provider
and tool counters, trusted observations, canonical provider requests and full
authority checks for each proposal. The roadmap contains acceptance criteria
and starting files.

On the next instruction to continue implementation:

1. Inspect Git and preserve this documentation checkpoint and unrelated changes.
2. Create a dedicated implementation branch based on the saved checkpoint, or
   include it deliberately before branching from refreshed main. Do not reset
   away the plan.
3. Settle R1 topology before changing IPC, then implement and validate R1 only.
4. Update verification and this handoff with actual results, failures and the
   precise next step. Save a reviewable commit when ready.

## Recovery commands

```sh
git status --short --branch
git log -5 --oneline --decorate
git diff --stat
git show --stat --oneline HEAD
```

For implementation work, run focused tests and the portable suite. Changes to
kernel boundaries require affected real Linux tests outside the coding sandbox
as the normal user:

```sh
.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short
git diff --check
```

Do not rerun all tests just to verify a saved documentation change. Use fresh
audit paths for demos. Distinguish synthetic provider behavior, real isolation
and actual human approval evidence.

## Resolved references and pending decisions

Confirmed by the user: Enrique Folte, PentestMonkey, PayloadsAllTheThings,
GTFOBins, LOLBAS, HackTricks and Hack The Box. Exact links and categories are in
the roadmap; do not repeat the earlier reference clarification.

Enrique Folte is the identified project contact. Submission role, affiliation
and any additional members remain to confirm. R1 IPC topology and the first
seeded assessment condition remain design decisions.

Proposal deadline: **15 November 2026**. Final development: **20 May 2027**.
The roadmap includes review and delivery buffers.

## Copy/paste prompt for tomorrow

```text
Continue Recon Cockpit from docs/continue-here.md and docs/roadmap.md.
Inspect Git and preserve the saved documentation checkpoint and local changes.
PR #5 is merged as bf3a359; do not repeat its review or merge.
Start R1: compose the offline provider with the isolated coordinator,
AuthoritySession and fixture executor. First settle bounded IPC/data flow,
then implement and test the smallest combined three-step offline path.
Keep live API calls/credentials disabled and real VPN testing deferred.
Use owned fixtures, preserve enforcement, and update the handoff with results.
```

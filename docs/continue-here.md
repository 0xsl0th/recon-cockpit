# Continue here — 17 September 2026

## Read this first

This development checkpoint never resumes an assessment or restores approvals.

**R1 and R2 are reviewed and merged into `main`.** R2's smallest HTTP
assessment/evidence/report slice is complete. Do not restart or re-merge them.
Read [http-assessment.md](http-assessment.md), [verification.md](verification.md)
and [roadmap.md](roadmap.md), then inspect Git and current PR checks.

R2 uses actual discovery evidence to gate a second fixed GET through R1's
isolated coordinator/parser, broker, authority and fixture executor. Six owned
cases cover exposure, absence, misleading content, timeout, output limits and
hostile discovery. Private bounded artifacts and observations link to execution
IDs; JSON/Markdown reports remain drafts pending operator review. Inspection
reconciles incomplete bundles without resuming work.

## Saved state

- Workspace: `/home/sloth/Code/recon-cockpit`, Kali Linux x86_64, normal user.
- Current branch: `main`, tracking `origin/main`. Both PRs were reviewed and
  merged with the operator's explicit authorization on 17 September.
- [PR #6](https://github.com/0xsl0th/recon-cockpit/pull/6): reviewed R1
  `cfde4ed`, merged as `07af513`. All ten branch/PR checks and subsequent
  main CI passed.
- [PR #7](https://github.com/0xsl0th/recon-cockpit/pull/7): reviewed R2
  `1312acf`, retargeted to main and updated as `33edceb` without file changes;
  all ten refreshed checks passed. Merged as `f85aaa9`, whose files exactly
  match the reviewed version. Its five main CI jobs also passed. Implementation
  commit: `3d20b24`.
- Check `git log -1` for the latest documentation checkpoint and current main
  CI. Local/Linux results and hosted portable checks are separate evidence.
- The operator already pushed documentation checkpoint `54461b7` on
  `docs/competition-roadmap`; verified on 15 September.
- [PR #5](https://github.com/0xsl0th/recon-cockpit/pull/5) is merged as `bf3a359`
  (reviewed implementation `0477f25`). Do not repeat its merge.
- Local R2: **1,849 portable tests and 78 real Linux integrations**, zero
  selected skips/failures/errors. Compile/dependency checks passed.
- JUnit files: `/tmp/recon-http-assessment-portable.xml` and
  `/tmp/recon-http-assessment-linux.xml`. Temporary evidence may disappear
  on reboot; durable results are in `docs/verification.md`.
- Local sample: `.secure-agent/r2-example-a/report.md` and `report.json`,
  private and ignored by Git. It validates seeded case a using the explicit
  unattended fixture demo policy, not human approval. Read-only inspection
  found no inconsistencies and changed no files.
- Git SSH was unavailable after reboot; authenticated GitHub CLI HTTPS push
  worked. Check current authentication before assuming either path.
- Old `/tmp/recon-pr2-review` and `/tmp/recon-pr3-review` worktrees disappeared
  after reboot; stale registrations were not pruned.

## Intent and constraints

Build authorized pentest workflows with specialist engines inside enforced
security boundaries. Challenge 4, security of autonomous agents, is the
competition focus. Planning still uses synthetic responses.

- Keep live calls and credential lookup disabled. A live slice needs reviewed
  operator data/model/credential/spend settings. Real VPN tests remain deferred.
- Use owned fixtures. Preserve policy/scope, OS isolation, fresh approvals,
  budgets, cancellation/deadlines, durable audit-before-execution and fail-closed
  behavior. Do not replay approvals or imitate a human terminal response.
- Never connect the legacy host runner, arbitrary shell, credentials, broad
  mounts or Docker socket to agents. Do not change host networking to pass tests.
- Authority, UI, broker, audit and launcher still share a trusted host process.
  Local hashes detect inconsistency, not host-owner tampering.
- The operator authorized the completed merges of PRs #6 and #7. This does not
  authorize competition submission, messaging others, paid calls, external
  target assessment or merging future PRs.

## Next continuation

1. Inspect Git and checks. Start from updated main, preserve unrelated work,
   and use a new branch for R3. PRs #6/#7 are already merged.
2. Start the smallest R3 discovery design in [roadmap.md](roadmap.md): one owned
   service topology, a bounded isolated discovery runtime, typed capability
   and result contracts, and evidence needed to select the HTTP workflow.
3. Implement one discovery-to-HTTP path with deterministic planning. Extend R2
   contracts only where the second tool demonstrates a concrete need.
4. Verify affected behavior and real Linux boundaries, then update this
   checkpoint with measured results and actual publication state.

R2's diagnostic metadata condition and R1 topology are settled. The workflow is
fixed trusted code, not a general plugin API. The probe does not validate all
HTTP framing; decoded artifacts are not wire captures. Absence applies only to
the inspected endpoint. R1 retains the documented limit on detecting coordinator
output arriving during synchronous callbacks. General workflows, broader review
UI, live models and external targets remain future work.

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

Run kernel tests outside the coding sandbox as the normal user. Use fresh audit
and assessment paths. Do not rerun all tests solely to verify saved docs.
Inspection creates no authority and cannot resume an old session.

## Remaining decisions

Reference identities are resolved: Enrique Folte, PentestMonkey,
PayloadsAllTheThings, GTFOBins, LOLBAS, HackTricks and Hack The Box. Exact links
and categories are in the roadmap; do not repeat clarification.

Enrique Folte is the project contact. Submission role, affiliation and additional
members remain to confirm; these do not block scoped development.
Proposal deadline: **15 November 2026**. Final development: **20 May 2027**.

## Copy/paste continuation

```text
Continue Recon Cockpit from docs/continue-here.md and docs/roadmap.md.
Inspect Git and preserve saved work. PR #6 is merged as 07af513 and PR #7
as f85aaa9. The workspace is on main; inspect current checks and start a new
R3 branch from updated main. Do not repeat the completed reviews or merges.
Read docs/http-assessment.md and the latest verification record.
Proceed with the smallest R3 isolated discovery design and owned-fixture path.
Do not repeat R1/R2 or merge future PRs without approval. Keep live calls/credentials
disabled and real VPN testing deferred. Preserve enforcement and update the
handoff with measured results.
```

# Continue here — 26 September 2026

## Read this first

This development checkpoint never resumes an assessment or restores approvals.

## Recovered R5a work — verified 26 September

Current branch: `feature/isolated-provider-foundation`, based on `ba3951e`.
The operator approved the proposed focused R5a PR with “sounds good, go ahead!”
at 04:51 UTC, then requested continuation after the laptop unexpectedly powered
off. Seven untracked implementation/documentation/test files survived. The
interrupted broker and host runtime had not been saved; they are now implemented.
Git object checks found no corruption. Main checkpoint `ba3951e` passed all five
[hosted portable jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/36095234761).

Scope: [owned TLS provider foundation](provider-foundation.md), using only
disconnected fixtures, synthetic credentials/model/cost units, status-only data
release and the existing networkless parser. No tool execution or live-provider
integration is added. The 18-run evaluation contract is preserved. Verification
and independent review are complete. Publication of the authorized focused PR
is next; earlier PR-specific merge authority does not cover this new PR.

The 26 September review found and fixed two failures: cancellation while collecting
owner counters could mask the stop with an invalid receipt, and temporary audit
directory setup errors could escape the demo's safe JSON reporting. Independent
runtime, contract and portability reviews found no remaining blocker. All **16
provider Linux tests passed** in 17.48 seconds, including both new cancellation
cases (`/tmp/recon-provider-review-linux.xml`, no failures/errors/skips).
The standalone demo passed with all ten transport and seven parser checks true,
one connection/request and reaped owner/worker processes. Its private audit is
`.secure-agent/provider-foundation-20260926/audit.jsonl`; it reserved one call,
1,024 output tokens, 3,060 request bytes and 5,208 synthetic cost units.

The final portable suite passed **2,548 tests**, 148 deselected, in 87.89 seconds;
the full Linux suite passed **148 tests**, 2,548 deselected, in 345.51 seconds.
Both reports contain no failures/errors/skips: `/tmp/recon-provider-final-portable.xml`
and `/tmp/recon-provider-linux.xml`. The existing 18-trial baseline passed within
the Linux suite. Compile, dependency, Python 3.11 syntax, documentation links and
whitespace checks passed. See [verification.md](verification.md).
A coding-service restart interrupted earlier runs; they were restarted after
confirming no matching processes survived. No commit, push or PR has yet been
made for R5a. Do not restore an interrupted assessment or approvals.

**R1, R2, the smallest R3 discovery-to-HTTP slice, the first R4 card/engine,
the post-merge CI correction, the persistent owned lab foundation and the
repeatable evaluation runner are reviewed and merged. PR #12 is complete.**
Read [evaluation.md](evaluation.md), [owned-lab.md](owned-lab.md), [workflow-assessment.md](workflow-assessment.md),
[verification.md](verification.md) and [roadmap.md](roadmap.md). Inspect Git and
current main checks before more work. Do not restart R1/R2/R3/R4 or repeat their merges.

An earlier recovery found a clean checkout at `401cbe1`. Saved conversation and
GitHub state confirmed that PR #9 had already been reviewed and merged with
operator authorization before the session limit. Git object checks found no
corruption. Local `main` was fast-forwarded to `8673dc0`; its tree exactly matches
the reviewed head. The interrupted local sync and checkpoint are now recovered.

## Saved state

- Workspace: `/home/sloth/Code/recon-cockpit`, Kali Linux x86_64, normal user.
- Prior completed checkpoint: `main`, synchronized with the PR #12 merge `ff5f76a`.
  The operator authorized implementing the 18-run baseline,
  independent grading and aggregate reports, with cleanup/isolation/accounting
  verification before opening a PR. The operator subsequently explicitly
  authorized reviewing and merging PR #12 into main after checks pass.
- [PR #12](https://github.com/0xsl0th/recon-cockpit/pull/12) is **merged**, at
  `ff5f76a6f81327b7ef184d7cfefff29ff087dd47` on 25 September, 04:35:39 UTC.
  Implementation commit: `665fcb7892ce5f839a1391c5ff7a338d054c0e29`.
  The full local suites and final CLI baseline passed before the PR was opened.
  Reviewed head `e23016a500b6fa24e36f783f4e2ba93662740321` includes the audit fix.
  All five [final PR CI jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/36070544788)
  passed on Ubuntu Python 3.11–3.14 and macOS Python 3.14. GitHub showed no
  outstanding review comments or merge conflicts. The merge was guarded by the
  exact reviewed head, and its tree matches that head. Do not repeat this merge.
  All five [post-merge main jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/36095076635)
  also passed. The publication checkpoint changes documentation only; inspect
  its current main checks when continuing.
  Final review found that missing audit context could still pass grading.
  Strict per-event fields, typed steps and action identity bindings now reject
  that corruption; the regression covers 73 mutations. The independent reviewer
  confirmed the fix and found no remaining blocker. Runtime review also found
  no blocker in scheduling, deadlines, cancellation, cleanup or storage.
- The new runner uses `--evaluate-owned-lab --evaluation-dir NEW_DIRECTORY`,
  explicit unattended owned-fixture policy, six cases times three repetitions,
  fresh authority/lab/broker identities and durable reservations before each trial.
  `--inspect-evaluation` independently regrades all saved evidence without writes
  or execution. See [evaluation.md](evaluation.md) for the contract and commands.
- Full verification passed **2,300 portable / 132 real Linux tests**, no selected
  failures/errors/skips. Compile, dependency, Python 3.11 syntax, relative link
  and whitespace checks passed. Linux tests include the full 18-trial baseline,
  process/namespace observations, read-only inspection, active/between-trial
  cancellation and an absolute batch deadline. See verification.md for exact
  commands and measured results.
- The audit fix passed the full 2,300-test portable suite and reran all six
  Linux evaluation tests, including another 18-trial baseline. The prior 126
  other Linux results apply to the unchanged runtime. Review JUnit reports:
  `/tmp/recon-evaluation-review-portable.xml` and
  `/tmp/recon-evaluation-review-linux.xml`.
- Evaluation JUnit: `/tmp/recon-evaluation-portable.xml` and
  `/tmp/recon-evaluation-linux.xml`. Final private baseline:
  `.secure-agent/evaluation-baseline-20260924/report.json` and `report.md`.
  Actual CLI: **18/18 passed in 72,004 ms**, 51 executions, 45 successful actions,
  12 correct abstentions, all cleanup/isolation grades passed and complete resource
  accounting. Read-only CLI inspection exactly reproduced the report without any
  file byte/mtime changes. See verification.md for measured totals and commands.
  Earlier `.secure-agent/evaluation-development-1`
  used an intermediate schema and is not the final publication baseline.
- [PR #11](https://github.com/0xsl0th/recon-cockpit/pull/11) is **merged**, at
  `7f316ce77f5c812477290e1b293d06d4afd88d53` on 24 September, 00:42:55 UTC.
  Reviewed implementation head `15583161e09658ef808160ecf308ab74e82b60c8`
  passed all five [PR CI jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/35939526013).
  Bounded launcher/evidence/portability reviews found no blocker; GitHub had no
  outstanding reviews or comments. The operator explicitly authorized commit,
  push and merge if checks passed. The exact-head-guarded merge succeeded and
  its tree matches the reviewed head. Do not repeat this merge.
  All five [post-merge main jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/35939661436)
  also passed. The final publication checkpoint changes documentation only;
  inspect its current main checks when continuing.
- [PR #10](https://github.com/0xsl0th/recon-cockpit/pull/10) contains the test-only
  correction and recovered checkpoint. It was reviewed and merged with operator
  authorization as `2b3527ec20c8a8b9dd30f5e7aa000bb48aa51fc3`, 23 September at
  14:14:09 UTC. Reviewed head `9fef498` passed all five PR jobs; all five
  [post-merge main jobs](https://github.com/0xsl0th/recon-cockpit/actions/runs/35872690851)
  passed. Its merge tree matches the reviewed tree. Do not repeat this merge.
- The operator then requested design and implementation of the persistent owned
  lab foundation. Contract: [owned-lab.md](owned-lab.md). Fixed-case service at
  `127.0.0.1:8080` persists for one authority session, with fresh nested executor
  sandboxes and pinned lab namespaces. Reset destroys/recreates; no resume.
  `--workflow-assessment CASE --owned-lab` selects card v2 and strict identity,
  counters and closure evidence. Live calls and external targets stay disabled.
  Full verification: **2,226 portable and 126 real Linux tests passed**, zero
  selected failures/errors/skips. Linux coverage combines the full 124-case run
  and two descriptor tests subsequently classified as Linux-only. Compile,
  dependency and whitespace checks passed. Bounded runtime/evidence reviews found
  no remaining blockers; see verification.md for exact commands and limitations.
- Lab JUnit: `/tmp/recon-owned-lab-portable-final.xml`,
  `/tmp/recon-owned-lab-linux.xml`, `/tmp/recon-owned-lab-descriptors-linux.xml`.
  Private sample: `.secure-agent/owned-lab-a-20260923/report.json` and `report.md`,
  plus `.secure-agent/owned-lab-a-20260923-audit.jsonl`. Case a validated using an
  explicit unattended owned-fixture policy, not human approval. All three actions
  share one lab instance; counters advance `(1, 0)`, `(2, 1)`, `(3, 2)`. Read-only
  CLI inspection preserved all bytes and mtimes and reported no integrity issues.
- [PR #9](https://github.com/0xsl0th/recon-cockpit/pull/9) is **merged**, at
  `8673dc0ac02a762dae08f2533885d2246fb04e2a` on 23 September, 01:29:31 UTC.
  Reviewed head `401cbe1` passed all ten branch/PR portable jobs across Ubuntu
  Python 3.11–3.14 and macOS Python 3.14. Bounded engine/provider and evidence
  reviews found no blockers; the root's focused regression run passed 289 tests.
- Four of five post-merge main jobs passed. Ubuntu Python 3.12 exposed a
  cancellation-test race: the 30 ms timer could fire after reserving the broker
  allowance but before consuming the scripted reply. Production correctly stopped
  without consuming that reply. PR #10 makes cancellation occur during the
  intended offline delay. See [verification.md](verification.md) for the failed
  run and correction verification; production code is unchanged.
- Correction verification: **2,134 portable tests passed, 109 deselected**;
  JUnit records zero failures, errors or skips. Focused broker tests passed 107
  cases. The earlier 109 real Linux results still apply to unchanged production;
  kernel tests were not rerun for this test/documentation-only correction.
- R4 adds a repository-authored versioned card, immutable deterministic
  decisions, durable proposal/terminal events and independent read-only replay.
  The CLI selector is `--workflow-assessment`; existing R2/R3 modes remain.
- Full R4 verification: **2,134 portable / 109 real Linux tests passed**, no
  selected failures, errors or skips. Compile, dependency and whitespace checks
  passed. See verification.md for commands, timings and reviewed limitations.
- R4 JUnit: `/tmp/recon-workflow-portable.xml` and
  `/tmp/recon-workflow-linux.xml`. Temporary evidence may disappear on reboot.
- Private R4 sample: `.secure-agent/r4-example-a/report.md` and `report.json`,
  plus `.secure-agent/r4-example-audit.jsonl`. The real CLI validated case a
  with three linked executions, three decisions and a terminal explanation.
  Read-only CLI inspection preserved every file's bytes and modification time.
  The explicit unattended owned-fixture policy is
  `/tmp/recon-r4-owned-fixture-policy.json`; this is not human approval evidence.
- [PR #8](https://github.com/0xsl0th/recon-cockpit/pull/8): reviewed head
  `124300a`, merged as `b1c7b67` on 22 September with operator authorization.
  The merge tree exactly matches the reviewed files. Implementation: `ad30297`.
  All ten branch/PR checks and all five post-merge main jobs passed; see
  verification.md. Inspect current main checks for the documentation checkpoint.
- Bounded premerge reviews covered isolation/authority, workflow/schema and
  evidence/recovery. No blockers were found; fresh focused checks passed.
  The existing full portable/Linux results remain valid for the production code.
- Initial hosted CI exposed a macOS assumption in a new portable refusal test.
  The test now explicitly exercises both Linux host-namespace refusal and
  non-Linux refusal. Production files and Linux verification are unchanged.
- Previous R3 verification: **1,977 portable tests and 96 real Linux
  integrations**, zero selected failures/errors/skips. Compile, dependency and
  whitespace checks passed. See the exact commands/timing in verification.md.
- JUnit: `/tmp/recon-discovery-portable.xml` and `/tmp/recon-discovery-linux.xml`.
  Temporary evidence can disappear on reboot; measured results are documented.
- Private sample: `.secure-agent/r3-example-a/report.md` and `report.json` plus
  `.secure-agent/r3-example-audit.jsonl`. It validates seeded case a using an
  explicit unattended owned-fixture demo policy, not human approval. Read-only
  CLI inspection found no issues and changed no file bytes or mtimes.
- [PR #6](https://github.com/0xsl0th/recon-cockpit/pull/6): reviewed R1
  `cfde4ed`, merged as `07af513` on 17 September.
- [PR #7](https://github.com/0xsl0th/recon-cockpit/pull/7): reviewed R2
  `1312acf`, updated as `33edceb` without file changes, merged as `f85aaa9`.
  All ten premerge branch/PR checks and five subsequent main jobs passed.
- [PR #5](https://github.com/0xsl0th/recon-cockpit/pull/5) is merged as `bf3a359`.
  Prior R2 verification was 1,849 portable / 78 Linux; do not present it as R3.
- Old `/tmp/recon-pr2-review` and `/tmp/recon-pr3-review` worktrees disappeared
  after an earlier reboot; their stale registrations were not pruned.
- SSH push authentication is still unavailable. Explicit HTTPS push with the
  GitHub CLI credential helper succeeded; no credentials entered artifacts.

## Implemented R3 scope

`--discovery-assessment a` selects one fixed `tcp_connect` action, then gates the
existing two-GET workflow using actual evidence. The explicit discovery executor
only permits the owned `127.0.0.1:8080` topology. TCP uses one second and reserves
1,024 output bytes, with no payload, banner, DNS, retry or port list. Original
fixture/routed HTTP modes reject TCP; the old policy remains HTTP-only. A separate
example policy allows both capabilities and requires fresh approvals.

Each action creates a fresh namespace with the same seeded topology. Reachability
does not prove HTTP identity or persistent service continuity. Three-step defaults
reserve 3,072 tool bytes; the broker separately reserves three calls/3,072 output
tokens. Reports link TCP and both HTTP observations, remain drafts, and preserve
read-only crash inspection without execution or grant restoration. R3 is not a
multi-service/Nmap adapter, general capability registry or workflow engine.

## Implemented first R4 slice

One card, `owned-discovery-http-assessment` version `1`, binds the existing
TCP-to-HTTP path to exact actions, parser gates and evidence requirements. Each
decision is durably recorded before any synthetic provider exchange. Execution
starts require a matching preceding proposal; reports distinguish proposals
from executions and explain evidence, approval, failure and budget stops.
The manifest and every decision bind the canonical card digest.

`owned-workflow-assessment-v1` bundles replay observations from artifacts and
recompute decisions during inspection. Corrupt, reordered, missing or unfinished
evidence remains inconclusive. There is no resumption of an assessment, dynamic
card loading, external knowledge import or new execution capability. The original
`--fixture` profile retains per-action services. The new `--owned-lab` profile
uses card v2 and the session-scoped service lifecycle described in [owned-lab.md](owned-lab.md).

## Intent and constraints

Build authorized pentest workflows with specialist engines inside enforced
security boundaries. Challenge 4, security of autonomous agents, is the focus.
Planning uses synthetic responses.

- Keep live calls and credential lookup disabled. Live work needs reviewed
  operator data/model/credential/spend settings. Real VPN tests remain deferred.
- Use owned fixtures; preserve scope/policy, OS isolation, fresh grants, budgets,
  cancellation/deadlines, audit-before-execution and fail-closed behavior.
- Never connect legacy host execution, arbitrary shell, credentials, broad mounts
  or Docker sockets to agents. Do not change host networking to pass tests.
- Authority/UI/broker/audit/launcher still share a trusted host process. Hashes
  detect inconsistency, not host-owner tampering. R1 callback and R2 HTTP framing
  limits remain documented.
- The operator authorized the completed PR #6/#7/#8/#9/#10/#11 merges.
  This does not authorize unrelated
  future merges, submission, messages, paid calls or external targets.

## Next continuation

1. Inspect main and its checks, preserving unrelated work. PR #10, PR #11 and
   PR #12 are already merged; do not repeat their implementation, review or merge.
2. Finish verification/review/publication of the recovered R5a foundation above.
   Later real-provider work needs explicit data/model/credential/spend choices.
   Do not silently widen the
   singleton executor or attach the legacy Nmap runner.
3. Keep kernel verification separate from hosted portable CI and record measured
   results/publication state for every slice.

## Recovery and verification

```sh
git status --short --branch
git log -5 --oneline --decorate
git diff --stat
git diff --check
.venv/bin/python -m pytest -m 'not integration' --strict-markers -ra
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v --tb=short
```

Run kernel tests outside the coding sandbox as the normal user. Use fresh audit
and assessment paths. Do not rerun all tests solely to verify saved docs. Inspect
existing bundles without restoring old approvals, deadlines or budgets.

## Remaining decisions

Reference identities are resolved: Enrique Folte, PentestMonkey,
PayloadsAllTheThings, GTFOBins, LOLBAS, HackTricks and Hack The Box. Links and
categories are in the roadmap; do not repeat clarification.

Enrique Folte confirmed that he is the sole human participant and project contact,
with Codex providing development assistance under human review. No additional
members or institutional affiliation are declared. Do not repeat the team question.
Proposal deadline: **15 November 2026**. Final development: **20 May 2027**.

# T04: controlled web hierarchy source feasibility

Status: **source review accepted in PR #82, 9 October 2026**. The merge at
`945ba2b` has the same tree as reviewed head `fb19b606`; all five final and [post-merge checks](https://github.com/0xsl0th/recon-cockpit/actions/runs/37872575949)
passed. This accepted source review registers no tool and closes no T04 product
acceptance gate. The required outcome remains discovery of a finite, controlled
one-level web hierarchy, including useful empty results.

A separate [native diagnostic](web-hierarchy-native.md) now executes real ffuf
against the twelve compiled paths in the disconnected owned fixture. Eight native
tests and 22,113 portable tests passed on frozen source `1b03814`, with no
failures, errors or skips and all 707 source hashes unchanged.
Detailed results belong to that runbook, separate from this source-review record. The diagnostic grants no product authority.
Next integrate a distinct production profile with policy, exact approval,
durable audit, consumed permits and both evidence inspectors before T04 G1–G6
acceptance. The catalog stays at 48 accepted profiles, zero candidates and
16 programs; T05/T06 remain required after T04.

## Engine review

The existing interactive precedent emits an inert `feroxbuster -u URL`
suggestion in [suggestions.py](../recon_cockpit/suggestions.py). It supplies no
secure execution authority. Feroxbuster was not installed on the reviewed host.
The installed `/usr/bin/ffuf -V` reported **`2.1.0-dev`**; that version string is
not an executable pin. A native candidate must retain its actual executable and
dependency hashes through the existing runtime-closure mechanism.

The feroxbuster source reviewed is **v2.13.1**, pinned to commit
**`aa8e1335801e91d98ce0d4fd148c2159a667a83b`**. Findings below refer to that
commit, not a moving release or an installed binary:

- Wildcard calibration constructs six random paths and dispatches them with
  `join_all`. This happens outside the word-scanner concurrency control, so
  `--threads 1` does not make calibration one active request. The generated paths
  also depart from a compiled finite path universe. `--dont-filter` bypasses
  this calibration. [Calibration source](https://github.com/epi052/feroxbuster/blob/aa8e1335801e91d98ce0d4fd148c2159a667a83b/src/heuristics.rs#L494-L604)
- Startup performs a connectivity GET. Each scanned directory also receives a
  directory-listing probe before word scanning; listing detection can terminate
  the scan early unless explicitly overridden. Those requests and early exits
  would need accounting in a bounded wrapper. [Startup](https://github.com/epi052/feroxbuster/blob/aa8e1335801e91d98ce0d4fd148c2159a667a83b/src/main.rs#L555-L572),
  [directory request](https://github.com/epi052/feroxbuster/blob/aa8e1335801e91d98ce0d4fd148c2159a667a83b/src/heuristics.rs#L168-L195),
  [early exit](https://github.com/epi052/feroxbuster/blob/aa8e1335801e91d98ce0d4fd148c2159a667a83b/src/scanner/ferox_scanner.rs#L266-L346).
- The default banner checks GitHub for updates; quiet or silent output skips
  that block. Link extraction defaults on and triggers a `robots.txt` request.
  Its extractor creates a redirect-following client even when ordinary scanner
  redirects are disabled. `--dont-extract-links` disables this extraction path.
  [Update check](https://github.com/epi052/feroxbuster/blob/aa8e1335801e91d98ce0d4fd148c2159a667a83b/src/main.rs#L526-L539),
  [robots dispatch](https://github.com/epi052/feroxbuster/blob/aa8e1335801e91d98ce0d4fd148c2159a667a83b/src/scanner/ferox_scanner.rs#L226-L235),
  [redirect client](https://github.com/epi052/feroxbuster/blob/aa8e1335801e91d98ce0d4fd148c2159a667a83b/src/extractor/container.rs#L636-L675),
  [extraction flags](https://github.com/epi052/feroxbuster/blob/aa8e1335801e91d98ce0d4fd148c2159a667a83b/src/parser.rs#L510-L523).
- Configuration files are merged from `/etc/feroxbuster`, the user configuration
  directory, the executable directory and the current directory. A secure
  runtime must exclude ambient configuration. Default recursion depth is four;
  zero means unlimited. Neither depth nor concurrency flags define an exact
  total request or path budget. [Configuration loading](https://github.com/epi052/feroxbuster/blob/aa8e1335801e91d98ce0d4fd148c2159a667a83b/src/config/container.rs#L630-L667),
  [scan flags](https://github.com/epi052/feroxbuster/blob/aa8e1335801e91d98ce0d4fd148c2159a667a83b/src/parser.rs#L478-L532).

**Stock calibrated feroxbuster does not fit this initial T04 contract.** This
does not rule out every wrapper: disabling its calibration and using compiled
control paths with an independent evaluator could be feasible. That would add
an uninstalled executable while replacing the behavior most relevant here.
The smaller proposed substitute is a separate ffuf hierarchy profile, reusing
the accepted executable-confinement pattern. Program count is not a quota.

## Proposed finite task

The following is a contract to verify, not a supported invocation or frozen
implementation recipe:

| Property | Initial candidate contract |
| --- | --- |
| Destination | Owned disconnected numeric `127.0.0.1:8080`, plain HTTP |
| Base and prefixes | `/harbordesk/`, `/harbordesk/docs/`, `/harbordesk/api/` |
| Compiled names per prefix | Resources `index.html`, `status`; controls `missing-control-a`, `missing-control-b` |
| Complete request universe | The twelve prefix/name combinations, once each, GET only |
| Bounds | Twelve total GETs including controls; one active request; no retries or generated paths |
| Depth | At most one predeclared directory level below the base; no recursive scanner mode |
| Exclusions | Redirect following, returned links, traversal, external origins, credentials, uploads, user words/configuration and body-derived requests |

The accepted [ffuf runtime](../recon_cockpit/secure_agent/web_tools_runtime.py)
already fixes `-t 1 -rate 4 -timeout 1 -maxtime 10 -noninteractive -ignore-body
-mc all -json -s -scrapers ""`, an exact numeric URL and compiled wordlist. Its
environment and empty configuration/scraper directory are also constrained.
These are reuse candidates, not proof that a larger nested corpus works. The
new profile must independently verify flags, response handling, runtime closure
and request accounting against the installed executable. Keep the existing
8,192-byte output and 60-second session ceilings; measure whether all ordinary
rows fit before registration. Do not silently raise a limit to fit the corpus.

The accepted `ffuf_content_discovery_v1` profile, its eight paths, parser,
invocation, limits and existing evidence remain unchanged. This candidate needs
a distinct profile, compiled corpus, parser version and evidence contract.

## Conclusions and native evidence required

The networkless evaluator must require twelve unique exact client result rows
and corroborating owner request records. Record each exact method/path and the
observed active-request high-water mark. Missing, duplicate, unexpected or
partial rows cannot claim complete discovery. Owner-sent responses cannot
substitute for missing client evidence.

Evaluate controls separately under each prefix. Two complete 404 controls can
support bounded resource observations there; an all-404 corpus completes as an
empty result for this universe. Wildcard, conflicting or unsupported controls
must suppress positive resource claims for the affected prefix and retain an
explicit ambiguity result. An observed nested resource does not prove a real
filesystem directory, exploitability or coverage beyond the twelve paths.

Before registration, the real secure executable must demonstrate:

1. Useful nested resources and an empty hierarchy, with zero unnecessary
   refusals in the declared ordinary corpus and every planned request accounted
   for. Record useful completion separately from process success.
2. Wildcard ambiguity, redirects, hostile links and traversal-like server text
   without extra requests, invented resources or expanded authority. With
   `-ignore-body`, do not claim response-body content was retained or interpreted.
3. Honest inconclusive results for malformed, incomplete and oversized output,
   inconsistent evidence, timeouts and cancellation. Denial must launch nothing.
4. Exact launcher authorization/audit/required approval enforcement, isolated
   execution, forbidden-destination checks, resource limits and complete cleanup.
5. Structured-result replay through both assessment inspectors without changing
   retained evidence, plus regressions preserving accepted profiles.

Only native evidence can establish actual request/concurrency behavior and
usefulness; source review supplies no timing, acceptance or execution claim.
Record latency and zero provider calls/cost without presenting a comparative
benchmark. T04 remains open until its G1–G6 gates are satisfied. Attached targets,
model credentials, paid/live calls, deeper workflows and comparative benchmarks
remain deferred; no installation or assessment traffic was performed for this
source review.

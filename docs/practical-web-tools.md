# Practical web-tool coverage

The current development batch adds **curl HTTPS retrieval and ffuf content
discovery** before deeper cross-tool workflows. The interactive cockpit already
uses both programs; secure integration reuses their enumeration semantics and
the existing authority infrastructure. The host interactive runner is not used
to execute agent proposals.

Implementation `3ec1ef0` runs both real executables through the secure path.
The batch is open for review in [PR #37](https://github.com/0xsl0th/recon-cockpit/pull/37).
Owned verification covers useful completion, negative cases, all approval gates,
bounded output, cancellation and cleanup. Fresh saved trials completed 2/2 useful
actions with zero unnecessary refusals and zero provider calls, then replayed
without modifying evidence. This is a small deterministic fixture result, not a
statistical model evaluation. See [verification.md](verification.md) and
[continue-here.md](continue-here.md) for receipts and review status.

| Tool | Fixed initial scope | Useful result |
| --- | --- | --- |
| `curl_https_get_v1` | One HTTPS GET to `harbordesk.test:8080/harbordesk/portal.html`, fixed mapping to owned `127.0.0.1`, synthetic fixture CA | Complete bounded response with verified TLS; normalized HTTP observations and raw replay evidence. |
| `ffuf_content_discovery_v1` | Eight pinned paths under `http://127.0.0.1:8080/harbordesk/`, serial requests, four requests/sec, one-second request timeout | All eight statuses recorded; conservative baseline check and observed matching paths. |

The initial dictionary is `portal.html`, `health`, `robots.txt`, `admin`, `api`,
`backup`, `status`, `missing-control`. The final control path helps identify
wildcard responses. It does not prove that every soft-404 pattern is detected.
No recursion, calibration, extensions, redirects, caller wordlists, credentials
or external targets are accepted.

Each trial makes one authority-approved action in a fresh disposable lab. It has
a 60-second session ceiling and an 8,192-byte combined tool output reservation.
curl has a three-second tool deadline; ffuf has a ten-second deadline. A separate
reviewed ffuf runtime permits bounded threads, with process and namespace
creation still prohibited. Its kernel ceiling is sixteen mapped-UID tasks,
including the private supervisor; a witness verifies that ceiling before exec.
ffuf has a 2 GiB virtual-address-space ceiling, five CPU seconds and 64 file
descriptors. `GOMEMLIMIT=64MiB` is an additional Go tuning setting, not a hard
memory guarantee. curl retains a 256 MiB address-space ceiling and prohibits
thread creation. The trusted new launcher accommodates the ffuf ceiling; accepted
Nmap and native profiles retain their limits.
Executable/library/data bytes are pinned and staged read-only; neither a shell
nor arbitrary executable/plugin selection is exposed.

ffuf receives a fixed empty, read-only scraper directory because the installed
binary requires it even with scrapers disabled. Host configuration, home files
and credentials are not mounted. Native ffuf JSON must identify exactly the
eight pinned inputs and positions; its internal hash and response text are
discarded from normalized observations. Protected paths returning 401/403 remain
visible in the status table. Absence of a successful response is not proof that
a path does not exist.

The CLI uses the same seven explicit gates as the accepted owned assessments:

```sh
python -m recon_cockpit.secure_agent \
  --web-tool-assessment curl-ok --owned-lab --execute \
  --policy examples/secure-agent-web-tools-policy.json \
  --isolated-audit --isolated-approvals --isolated-launch-admission \
  --isolated-launcher --require-launch-audit --require-launch-approval \
  --audit .secure-agent/NEW-curl-audit.jsonl \
  --assessment-dir .secure-agent/NEW-curl-evidence
```

Use a fresh path per run and `ffuf-normal` for the independent discovery trial.
The example policy requires the operator's fresh approval phrase. Automated
owned-lab checks use an explicitly labelled synthetic test policy/grant and do
not count as a human approval or product acceptance. Inspection is read-only:

```sh
python -m recon_cockpit.secure_agent \
  --inspect-assessment .secure-agent/NEW-curl-evidence
```

Completion requires actual owned execution, independent raw-output replay,
useful completion of normal cases, conservative results for malformed/partial
or wildcard responses, verified TLS refusal, scope/approval denial, deadline and
output bounds, cancellation and cleanup. Record latency and request counts;
provider calls and cost remain zero. An adapter that blocks all useful work
does not pass.

The accepted curl/ffuf batch is B0 of the current
[broader secure-tool coverage milestone](secure-tool-coverage.md). Continue the
next unchecked tool batch; deeper composition and comparative benchmarking wait
until that milestone is complete. Credential setup, paid calls and live-model
evaluation remain deferred until much later. This
batch does not reopen accepted offline R5/local R6 milestones, change the local
competition PDF or authorize external assessments or publication.

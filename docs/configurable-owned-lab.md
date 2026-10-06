# Configurable owned HTTP/SSH assessment

This slice lets an operator declare two synthetic endpoint fixtures with exact
private IPv4 addresses, unprivileged ports and one HTTP path. It prepares scope
and execution contracts for internal-network engagements with web services.
It does **not** attach to those addresses on the host, a VPN or a real network.
Each endpoint exists in its own disposable, disconnected network namespace.

The four actions are Nmap HTTP identification, the declared header GET, Nmap SSH
identification and RSA public host-key collection. Complete structured HTTP/SSH
identification gates the corresponding follow-up. Missing, malformed or mismatched
evidence stops the sequence; observed URLs, versions and keys never expand scope.
No login, password, arbitrary shell, NSE script or model call is available.

## Scope and authority

Start from [the scope example](../examples/secure-agent-configurable-scope.json)
and [matching approval-required policy](../examples/secure-agent-configurable-policy.json).
The [alternate scope](../examples/secure-agent-configurable-scope-alternate.json)
and [policy](../examples/secure-agent-configurable-policy-alternate.json) vary
both addresses, both ports and the HTTP path.

Only canonical RFC1918 IPv4 literals, ports 1024–65534, a short scope identifier
and a bounded origin-form HTTP path are accepted. Names, CIDRs, IPv6, credentials,
extra fields and caller arguments are rejected. The manifest defines the exact
endpoint pairs; the policy can narrow allowed actions but cannot broaden that
manifest. Session overrides can only shorten four steps, 60 seconds and 26,624
reserved output bytes. The native tools use pinned executables and library/data
closures; they receive no operator-selected arguments or environment.

All seven existing gates remain mandatory. Each action commits to the complete
scope, exact action, immutable policy, session limits, sequence, deadline, owner
identity and selected runtime. HTTP actions cannot access the SSH endpoint,
even though SSH is allowed elsewhere in the same assessment. Three actual
listening witnesses per action prove blocking of the other declared service,
a different address and a different port. Positive listener checks precede
filter installation. Only the selected endpoint pair is permitted afterward.

## Run and inspect

Use a fresh private directory under `.secure-agent`; never reuse an evidence
directory. The command below records proposals without executing tools:

```sh
python -m recon_cockpit.secure_agent \
  --configurable-assessment examples/secure-agent-configurable-scope.json \
  --policy examples/secure-agent-configurable-policy.json \
  --owned-lab --isolated-audit --isolated-approvals \
  --isolated-launch-admission --isolated-launcher \
  --require-launch-audit --require-launch-approval \
  --audit .secure-agent/NEW-AUDIT.jsonl \
  --assessment-dir .secure-agent/NEW-ASSESSMENT --dry-run
```

Replace `--dry-run` with `--execute` for an owned-fixture run. The supplied policy
requires the operator to personally approve each action in a controlling terminal.
Noninteractive use cannot grant those approvals. Automated validation uses an
explicit test policy permitting only these synthetic fixture actions without
human approval; this does not count as a personal walkthrough or acceptance.

```sh
python -m recon_cockpit.secure_agent --inspect-assessment .secure-agent/NEW-ASSESSMENT
```

Inspection replays original raw bytes through networkless parsers, validates
endpoint/runtime bindings, decisions and owner counters, then compares both saved
reports. It changes no files and restores no execution authority. Artifacts and
reports are private local files; no external publication is implied.

## Evidence and completion

Require two varied manifests to complete all four useful actions with original
endpoint values, 12/12 blocked destination attempts per run, zero unintended
refusals, owner teardown and unchanged read-only replay. Also require malformed
scope/action rejection, predecessor mismatch rejection, noninteractive approval
blocking, cancellation cleanup, unchanged accepted v1 behavior and green review
checks. Measure whole-session elapsed time and report zero actual model calls
and cost. Comparative baseline overhead remains deferred; local duration alone
does not measure authority overhead.

The registry adds three separately versioned configurable profiles using existing
Nmap, ssh-keyscan and native HTTP implementations. They add **no external program
families** and do not reopen B0–B8. HTTP header gaps are hardening observations;
service versions and SSH keys are unauthenticated metadata. Fixed synthetic
responses do not establish broad service compatibility or professional pentest
readiness. Real lab attachment, shared topology, richer workflows, authenticated
operations and GUI controls remain subsequent, separately reviewed slices.

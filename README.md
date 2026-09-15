# Recon Cockpit

For project direction, see the [development roadmap](docs/roadmap.md) and
[competition proposal](docs/competition-proposal.md). To resume work after an
interruption, start with [the current checkpoint](docs/continue-here.md).

## Secure Agent Mode — bounded mock sessions, fixture and routed HTTP

An additional entry point now accepts **deterministic mock agent** proposals and
enforces schema → policy → human approval when required → isolated execution →
structured result and JSONL audit. It uses no API keys or paid services. This
milestone does not validate an autonomous model.

Milestone 2 adds a bounded session loop: the fixed mock can propose follow-up
actions from the previous untrusted response, and every action passes the same
schema, policy, approval and audit checks. Session deadlines cover planning,
approval waiting, setup and execution; step and reserved-output budgets stop
further work. See [bounded sessions](docs/bounded-sessions.md) for the contract.

The planner isolation slice adds an explicit Linux planner sandbox and an offline OpenAI
Responses API codec. `--isolated-session-mock` runs the fixed mock with no network
or credentials. OpenAI live calls remain disabled; the codec has no transport.
See [planner isolation](docs/provider-isolation.md) for usage and remaining work.

`--openai-offline` now connects the codec to a trusted broker and a dedicated
Linux parser sandbox using framed pipes. It runs fixed synthetic API responses,
reserves call/output-token/request-byte allowances before each exchange, and
requires durable audit recording. Live calls and credential lookup remain
unavailable. See [the offline broker](docs/offline-openai-broker.md).

```bash
python -m recon_cockpit.secure_agent --openai-offline three_step --openai-model offline-fixture-model --dry-run
python scripts/secure_agent_openai_demo.py --execute-fixtures
```

The model name above is a fixture identifier, not a claim of an available API
model. Offline OpenAI mode requires Linux isolation even for tool dry-runs.

`--control-plane-mock` moves the session coordinator into a persistent Linux
sandbox. A host authority service owns policy, terminal approval, budgets and
audit, and sends bound launch requests to fresh fixture executors over separate
private pipes. Forged authority fields, replay and attempts to reset a session
fail closed. This first slice contains coordinator compromise; the authority's
approval, audit and launcher components still share a trusted host process.
See [control-plane authority and IPC](docs/control-plane.md) for the contract.

```bash
python -m recon_cockpit.secure_agent --control-plane-mock three_step --dry-run
python -m recon_cockpit.secure_agent --control-plane-mock three_step --fixture --execute
python scripts/secure_agent_control_plane_demo.py --execute-fixtures
```

This path requires Linux isolation even for dry-runs and currently uses fixed
mock scenarios and owned fixtures. Live API calls remain unavailable.

`--control-plane-openai-offline` combines that authority path with the offline
provider. The coordinator requests a plan, then submits the same plan for full
authorization. Trusted execution records supply provider observations; separate
provider and tool budgets share one session deadline. See the
[combined offline path](docs/offline-authority.md) for the protocol and limits.

```bash
python -m recon_cockpit.secure_agent --control-plane-openai-offline three_step --openai-model offline-fixture-model --dry-run
python scripts/secure_agent_offline_authority_demo.py --execute-fixtures
```

The demo uses twelve synthetic cases and an explicit unattended policy for
owned fixtures. Normal CLI fixture execution still requires fresh human
approval under the default policy. No live model or human approval is validated
by the demo.

The executable tool set is one bounded HTTP probe. `--fixture` reaches only its
owned `127.0.0.1` service inside a fresh Linux namespace. The separate `--routed`
backend reaches one explicitly authorized IPv4 literal and TCP port through an
isolated worker and a supervised slirp transport. Policy supports broader scopes,
but routed CIDR actions, IPv6, loopback, hostnames, TLS and Nmap remain unavailable.
The existing interactive workflow below is preserved and has a different,
human-operated security boundary.

### Quick start

From the repository, install Python 3.11+ and the project/test dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
python -m recon_cockpit.secure_agent --mock --dry-run
```

The basic `--mock --dry-run` works on macOS and Linux without isolation tools. Expected JSON:
`provider: deterministic-mock-no-model`, `decision: approval_required`,
`execution_status: dry_run`. No network request runs. Events go to the private
`.secure-agent/audit.jsonl`; override the path with trusted operator flag
`--audit /path/to/private-directory/audit.jsonl`.

For real fixture execution, use a dedicated Linux/Kali lab. Install the system
packages explicitly (this is operator setup, not an automatic privilege request):

```bash
sudo apt-get update
sudo apt-get install python3 python3-venv bubblewrap nftables libseccomp2 libc-bin
python -m recon_cockpit.secure_agent --mock --fixture --execute
```

Run the Python command as a normal user, from a terminal. Review the exact action
and policy digests, then type the displayed `approve <digest-prefix>` challenge.
Expected result: `execution_status: succeeded`, HTTP status 200 in
`result_metadata.results`, and an approval reference in the audit trail.
The approved address belongs to the owned fixture **inside** the sandbox. It does
not contact your host's port 8080. Raw response/rationale are not printed or logged.

The lab must permit unprivileged user/network namespaces and a compatible
non-setuid Bubblewrap. The backend creates ephemeral namespaces, installs a
default-deny nftables ruleset there, drops capabilities, and applies filesystem,
syscall and resource restrictions. It makes no changes to host routes, firewall,
forwarding, NAT or sysctls. Do not run secure mode with sudo, add broad mounts, or
expose a Docker socket to it.

### Routed HTTP

Install the additional rootless transport dependency as operator setup:

```bash
sudo apt-get install --no-install-recommends slirp4netns
```

The application runs as a normal user and uses existing operator routes. No host
firewall, routing, forwarding, NAT or sysctl changes are needed. Review the
[routed design and examples](docs/routed-http.md) before configuring a real
authorized destination. No real remote/VPN target or autonomous model has been
validated; the routed tests use owned services in a disconnected outer namespace.

To reproduce that lab and the human approval check (use fresh audit filenames):

```bash
python scripts/secure_agent_routed_demo.py --audit .secure-agent/routed-demo.jsonl
python scripts/secure_agent_routed_demo.py --interactive --audit .secure-agent/routed-human.jsonl
```

### Reproducible verification

GitHub Actions runs the portable suite on Ubuntu with Python 3.11–3.14 and on
macOS with Python 3.14 for pull requests into `main`, `feature/secure-agent-m2`
or `feature/secure-agent-provider-isolation`,
and pushes to the configured secure-agent branches and `main`. These jobs require zero skipped portable tests; Linux
integration tests are explicitly deselected. CI does not execute probes, supply
human approvals, or establish kernel isolation. The opted-in Kali tests and
human approval evidence in [verification.md](docs/verification.md) remain a
separate review requirement for execution-boundary changes.

```bash
# Portable control-plane tests and existing workflow regressions
python -m pytest -m 'not integration'

# Real Linux isolation tests: opted-in setup failures are failures, not passes
RECON_LINUX_INTEGRATION=1 python -m pytest -m integration -v

# Complete owned-fixture demo (Linux prerequisites above)
python scripts/secure_agent_linux_demo.py

# Multi-step owned-fixture demo: success, malicious follow-ups and stop limits
python scripts/secure_agent_session_demo.py
```

The unattended demos use a clearly labeled fixture-only policy with
`require_approval: false` for their allowed-action cases. The original
`secure_agent_linux_demo.py` also demonstrates approval-required failures;
neither demo fabricates a human approval. The example
policy used by the CLI requires human approval. Portable tests exercise missing,
expired, replayed and changed-action approvals and concurrent single use. Kernel
tests exercise real HTTP, malicious fixture output, redirects, timeouts/output
caps, and direct socket attempts toward listening out-of-scope IP/port witnesses.

Use `--proposal action.json` instead of `--mock` to submit untrusted JSON. See
[the mock action](recon_cockpit/secure_agent/planner.py) for the exact required
fields and [the example policy](examples/secure-agent-policy.json) for operator
configuration. Extra fields, booleans used as numbers, command strings, arbitrary
paths, headers, policy/approval overrides and unsupported tools are rejected.

### Expected failures and troubleshooting

- `noninteractive_approval_required`: an approval-required action was executed
  without an interactive terminal. Review it interactively; there is no `--yes`.
- `isolation_unavailable`: Linux, dependencies, user namespaces, sandbox setup,
  or backend target support is missing. Execution remains blocked; dry-run works.
  Use a dedicated compatible Linux/Kali VM rather than weakening host controls.
- `audit_unavailable` / exit 3: the audit directory/file must be private and owned
  by the controller user, writable, and a regular non-symlink file. Check disk
  space and permissions. Reconcile any start event without a completion event
  before retrying; a completion-write failure cannot undo an already sent request.
- Exit 2 reports a policy/schema/approval/isolation denial, execution failure,
  or a stopped session, including budget exhaustion and cancellation. Timeouts
  and output limits have distinct structured reasons.
- A suite with skipped Linux tests proves only the portable controls. The
  prompt-injection fixtures demonstrate that specific malicious follow-up
  proposals are rejected; they are not evidence of universal immunity.

Local JSONL logs are not tamper-proof and can be rewritten by the owner or a
compromised host. Approval hashes bind content; they do not protect host history.
See [architecture](docs/architecture.md), [threat model](docs/threat-model.md),
[Spanish competition draft](docs/competition-proposal.md), and
[verification record](docs/verification.md).
For continuation on Kali amd64, use the [Lenovo handover and session prompt](docs/handover-kali.md).

## Interactive Recon Cockpit

Recon Cockpit is an evidence-driven terminal UI for authorized HTB/THM-style
targets. Give it one IP address and it creates a durable case, lets you choose one
of three bounded Nmap profiles, parses the XML, and offers only the enumeration
paths supported by the ports and fingerprints it actually observed.

It does not exploit targets. It does not run service enumeration automatically.
Standard, Full TCP, custom, and service-enumeration actions are shown as exact
commands and require a fresh, default-no confirmation.

## Install

Requirements:

- Python 3.11 or newer
- Git and `uv` for the recommended install flow
- `nmap` for scanning
- Rich (installed with the project)
- OpenSSH client tools (`ssh`, `ssh-keyscan`) and `curl` for SSH credential/key
  checks, FTP, Docker API, and WinRM suggestions
- Optional tools for other commands you choose to run: `feroxbuster`, `ffuf`,
  NetExec (`nxc`), `smbclient`, `ldapsearch`, and `kerbrute`. The ffuf action
  prompts for a wordlist path; SecLists is one option but is not required.

Clone, install, and launch with Git and `uv`:

```bash
git clone https://github.com/0xsl0th/recon-cockpit.git
cd recon-cockpit
uv sync --python 3.13
source .venv/bin/activate
python recon.py 10.10.11.123
```

Python 3.13 is recommended for compatibility with the broader
offensive-security Python ecosystem.

Or use any Python environment manager and install the project with its normal
editable-install command.

## Start a case

```bash
python recon.py 10.10.11.123
```

For a new interactive case, choose a scan before any target command runs:

```text
Choose the initial Nmap scan

  [1] Quick                  Top 1,000 TCP ports; light version probes
  [2] Standard (recommended) Top 1,000 TCP ports; default scripts + versions
  [3] Full TCP               All TCP ports; scripts + versions on open services

Scan profile (2):
```

The Quick profile runs immediately after you choose it. Standard and Full TCP
display the exact generated command and require a second confirmation that
defaults to no. Full TCP explicitly warns that it will query all 65,535 TCP ports,
then run Nmap's default NSE scripts and version probes on discovered services.
Reopening an existing case reuses its saved evidence; pass `--rescan` to choose a
fresh scan profile.

With `--no-menu`, or when standard input is not interactive, the cockpit cannot
ask for a profile and falls back to Quick. It prints that decision before running.

The menu is derived from open-service evidence. For example:

```text
TARGET  10.10.11.123

PORT      SERVICE   VERSION / EVIDENCE
22/tcp    SSH       OpenSSH 9.2p1
80/tcp    HTTP      Microsoft IIS httpd 10.0
445/tcp   SMB       Microsoft Windows Server
5985/tcp  WinRM     Microsoft HTTPAPI httpd 2.0

Suggested next actions:

  [1] Enumerate HTTP
  [2] Enumerate SSH
  [3] Enumerate SMB
  [4] Inspect WinRM
  [5] Run standard Nmap scripts
  [6] Run full TCP Nmap scan
```

### Nmap scan profiles

Quick scans the 1,000 most common TCP ports with light version probes:

```text
nmap -Pn -sV --version-light --top-ports 1000 --reason \
  -oX cases/10.10.11.123/scans/quick-….xml \
  -oN cases/10.10.11.123/scans/quick-….nmap 10.10.11.123
```

Standard is the recommended starting point for an interactive lab case:

```text
nmap -Pn -sC -sV -vv --top-ports 1000 --reason \
  -oX cases/10.10.11.123/scans/standard-….xml \
  -oN cases/10.10.11.123/scans/standard-….nmap 10.10.11.123
```

Full TCP scans every TCP port, then applies the same scripts and version probes to
discovered services:

```text
nmap -Pn -p- -sC -sV -vv --reason \
  -oX cases/10.10.11.123/scans/full-….xml \
  -oN cases/10.10.11.123/scans/full-….nmap 10.10.11.123
```

The cockpit does not prepend `sudo`: these profiles work without automatic
elevation and will not leave root-owned files inside the case. If privileged Nmap
behavior is specifically needed, copy the displayed command and run it manually
with the appropriate authorization.

If ports 139/445 or an SMB fingerprint are absent, the SMB group does not exist.
HTTP evidence produces ready-to-review feroxbuster and ffuf commands; the ffuf
action asks for the wordlist path when selected. SMB evidence produces NetExec
anonymous-share, smbclient, and RID-enumeration commands. LDAP produces RootDSE
and base-DN queries; Kerberos produces a username-enumeration
command with prompted domain and user-list values. IIS + SMB + WinRM evidence is
identified as a probable Windows workflow and adjusts the wording and available
credential checks. Domain credentials use NetExec's domain mode; credentials
without a domain use `--local-auth`.

Linux/Unix evidence adds equally service-specific workflows:

- SSH offers host-key collection and algorithm enumeration.
- FTP offers bounded anonymous listing and fixed `ftp-anon,ftp-syst` NSE checks.
- RPC/NFS offers RPC program and export discovery without mounting anything.
- DNS offers a server-identity query; SMTP lists advertised commands without
  sending mail or enumerating users.
- An exposed Docker daemon API offers GET-only ping, version, info, and container
  metadata requests. Docker Registry fingerprints are not treated as daemon APIs.

SSH alone is not enough to label a target Linux because Windows can expose
OpenSSH. A Linux/Unix posture requires an OS/distribution fingerprint or a
corroborating SSH plus NFS/RPC stack. Generic HTTP discovery is suppressed for
Docker daemon and WinRM endpoints. These commands use Nmap's bundled NSE scripts,
`ssh-keyscan`, and `curl`; they do not require `showmount`, `rpcinfo`, `dig`, or
`swaks` to be installed.

Selecting a service group only displays its possible commands. Selecting one still
does not run it until you answer the final confirmation prompt. Nmap follow-up
actions display their exact generated command and then ask for the same default-no
confirmation. Commands execute as argument arrays, never through a shell, so
metacharacters cannot silently add a pipeline or second command. Long-running
output is streamed to the terminal and incrementally saved to a private transcript;
the in-memory parser buffer is bounded.

## Run a custom Nmap scan

Start or reopen the case in interactive mode. Do not pass `--no-menu`:

```bash
python recon.py 10.10.11.123
```

After the summary, choose **Run custom Nmap scan** from the Actions menu. Its
number changes depending on which service actions are available:

```text
Actions

  [1] Enumerate HTTP
  [2] Enumerate SSH
  [3] Enumerate SMB
  [4] Inspect WinRM
  [5] Run standard Nmap scripts
  [6] Run full TCP Nmap scan
  [7] Run custom Nmap scan
  [8] Add a credential
  [9] Open target notes
  [10] Ingest saved command output
  [11] Quit

Select: 7
Nmap options (blank cancels): -sT --top-ports 50 -sV -T4 -vv
```

The prompt accepts Nmap options, not a complete shell command. The cockpit then
constructs and displays:

```text
nmap -Pn -sT --top-ports 50 -sV -T4 -vv --reason \
  -oX cases/10.10.11.123/scans/custom-….xml \
  -oN cases/10.10.11.123/scans/custom-….nmap 10.10.11.123

Run this active custom nmap enumeration command? [y/n] (n):
```

Review the final command and enter `y` to run it. The XML and normal output are
saved under `cases/10.10.11.123/scans/`, parsed into the case, and reflected in
`notes.md`.

Enter options only: omit `nmap`, `sudo`, the target, output flags, pipes, and
redirection. The cockpit owns the canonical single target and private output paths.
It accepts common TCP/UDP scan types, numeric port selections, version and OS
detection, verbosity, timing templates through `-T4`, and bounded rate, retry, and
timeout controls. It rejects unknown flags, additional target sources, output
overrides, arbitrary NSE scripts, spoofing, decoys, proxies, and other options that
could escape the case scope. Use `-sC` for the fixed default NSE set.

Every custom scan receives a separate default-no confirmation and executes without
a shell. Raw-socket options such as `-sS`, `-sU`, or `-O` can fail when Nmap lacks
the required capabilities; the cockpit never elevates itself. For options outside
the safe custom builder, run Nmap separately and import its XML with `--nmap-xml`.

## Cases and notes

Each target gets a private case directory:

```text
cases/10.10.11.123/
├── case.json        # structured source of truth
├── notes.md         # regenerated human-readable notebook
├── scans/           # nmap XML and normal output
├── loot/            # ingested/captured command output and generated user lists
└── commands/        # redacted argv/exit-status audit records
```

`notes.md` contains hosts, ports and versions, findings, domains, usernames,
credentials, shares, and evidence-driven next actions. Text between the manual
notes markers is preserved whenever the generated sections are refreshed.

The interactive “Add a credential” action stores a manually entered identity and
secret. Secrets appear only in the Credentials table in generated Markdown and
are masked in command previews/audit records; `case.json` and the credentials
table intentionally contain the plaintext value you entered. Case directories
are written with owner-only permissions (`0700`) and generated files with `0600`,
but the whole case should still be treated as sensitive.

## Ingest command output

Capture NetExec output however you prefer:

```bash
nxc smb 10.10.11.123 -u users.txt -p passwords.txt | tee loot/nxc.txt
python recon.py --ingest loot/nxc.txt
```

The parser strips terminal color codes, requires a validated NetExec-style
protocol/IP/port/host prefix for structured findings, and extracts supported
evidence including:

- target IP, hostname, domain, and SMB/OS banner details;
- RID-enumerated usernames;
- successful `[+]` authentications, including administrative `(Pwn3d!)` status;
- shares, permissions, and remarks from an “Enumerated shares” table.

Failed `[-]` authentication attempts are never recorded as valid credentials, and
unrelated lines such as `[+] Download complete: …` are not mistaken for credentials.
IPv4 and IPv6 target addresses are canonicalized before case matching.
The case is selected from an ancestor `case.json`, a matching existing target, or
a single target IP found in the output. If the output is ambiguous, specify it:

```bash
python recon.py 10.10.11.123 --ingest loot/nxc.txt
```

Output produced by a command launched from the cockpit is also saved under
`loot/` and passed through the same parser automatically.

## Offline imports and automation

Import an existing scan without contacting the target:

```bash
python recon.py 10.10.11.123 --nmap-xml saved-scan.xml
```

Update a case and print its summary without opening the interactive menu:

```bash
python recon.py 10.10.11.123 --nmap-xml saved-scan.xml --no-menu
python recon.py --ingest loot/nxc.txt --no-menu
```

Use a different case root with `--cases-dir PATH`.

## Test

```bash
pytest
```

The tests cover nmap XML parsing, NetExec extraction, Markdown preservation and
deduplication, target validation, scan confirmations, service-gated Linux/Unix and
Windows suggestions, and conservative host-posture inference.

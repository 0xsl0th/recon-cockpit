# Recon Cockpit

Recon Cockpit started as a terminal notebook for reconnaissance on targets you are authorized to test. It keeps scan results, notes, and suggested next steps together in one case, so you can pick up where you left off instead of piecing a session together from terminal history.

The project now also explores a harder problem: **how can an agent help with security work without deciding its own permissions?** Secure Agent Mode puts policy, approval, execution limits, and audit outside the planner. Its demonstrations use owned services and synthetic provider responses, with evidence you can inspect afterward.

| If you want to… | Start here |
| --- | --- |
| Work through one lab target by hand | [Interactive cockpit](#interactive-cockpit) |
| See how an agent action is checked before execution | [Secure Agent Mode](#secure-agent-mode) |
| Review scope and saved evidence in a local window | [Offline desktop](#offline-desktop) |

## Install

Use Python 3.11 or newer. The interactive cockpit needs `nmap` on your path; the secure Linux demos have [additional requirements](#run-an-owned-linux-demo). You can install the Python package with any environment manager:

```bash
git clone https://github.com/0xsl0th/recon-cockpit.git
cd recon-cockpit
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

If you already use `uv`, `uv sync --python 3.13` is another setup path.

## Interactive cockpit

Give it one IP address in an authorized lab:

```bash
python recon.py 10.10.11.123
```

For a new case, choose a Quick, Standard, or Full TCP Nmap scan. Quick runs after you select it; Standard and Full show the command and ask for another confirmation. Full covers all TCP ports. The menu then shows only service paths supported by the evidence it found. Choosing an action shows its exact command, and active follow-up commands require a fresh confirmation that defaults to **no**. The cockpit does not exploit the target or run the whole menu automatically.

The case is saved under `cases/<target>/`. It contains Nmap output, a readable `notes.md`, structured case data, captured command output, and redacted command records. Your manual notes survive regeneration. Treat the folder as sensitive: credentials you enter are stored in plaintext in the case data and generated credentials table, although previews and command records mask known secrets.

Run the same command later to reopen the case. Use `--rescan` to choose a new scan, or import Nmap XML without contacting the target:

```bash
python recon.py 10.10.11.123 --nmap-xml saved-scan.xml
```

The menu also offers bounded custom Nmap options and service-specific suggestions for HTTP, SSH, SMB, DNS, LDAP, and other observed services. Some suggestions use optional tools such as `ffuf`, `feroxbuster`, or `nxc`; install those only if you plan to use them. See `python recon.py --help` for imports, alternate case directories, and noninteractive use. On a **new** case, `--no-menu` falls back to a Quick scan unless you import existing XML.

## Secure Agent Mode

An agent proposes a typed action; a separate controller validates its shape, checks an operator policy, requests human approval when needed, and records the decision. The tool runs in a constrained Linux environment only after the required checks pass. Follow-up proposals go through the same checks. Responses from services remain untrusted data, not permission to change scope.

You can inspect the accepted tool catalog and try a mock dry run without contacting a target:

```bash
python -m recon_cockpit.secure_agent --list-tools
python -m recon_cockpit.secure_agent --mock --dry-run
```

The mock is deterministic. The dry run validates and audits a proposal; it does not launch a network tool. The project has **55 accepted, narrowly scoped secure profiles** across 17 external programs, including bounded Nmap, HTTP, DNS, SSH, SMB, and TLS checks. A catalog entry describes a reviewed operation; it does not grant execution on arbitrary targets. Use `--describe-tool TOOL_ID` or the [secure tool catalog](docs/secure-tool-catalog.md) for exact limits.

### Run an owned Linux demo

Secure execution needs a compatible Linux or Kali environment with unprivileged user and network namespaces. On Debian-based systems, prepare the packages as the operator:

```bash
sudo apt-get update
sudo apt-get install python3 python3-venv bubblewrap nftables libseccomp2 libc-bin
python -m recon_cockpit.secure_agent --mock --fixture --execute
```

Run the final command as your **normal user**, in a terminal. It shows the action and policy digests, then asks you to type an `approve <digest-prefix>` challenge. The HTTP service at `127.0.0.1:8080` is created inside the sandbox; it is not a service on your host. If policy, audit, approval, or isolation is unavailable, execution blocks.

There are richer offline workflows: bounded sessions, owned HTTP and Nmap assessments, saved evidence reports, and repeated evaluation. They use fixed scenarios and disconnected owned services. Start with the [assessment guide](docs/http-assessment.md), [service and web workflow](docs/service-web-assessment.md), or [verification record](docs/verification.md) before running one. Assessment directories and audit filenames must be new for each run; saved reports can be inspected without resuming execution.

The separate routed HTTP backend can reach one explicitly authorized IPv4 address and port under its documented constraints. Read the [routed HTTP design](docs/routed-http.md) before configuring it. The accepted owned-lab profiles and routed backend do not make this a general-purpose autonomous pentester or a ready-to-use production engagement service.

## Offline desktop

The local Tk desktop lets you prepare the fixed owned-lab scope, start a dry run, inspect saved evidence, or execute a four-action disconnected HTTP/SSH lab. Each executed action needs fresh approval in a separate review window. The desktop makes no model calls and does not attach its owned lab to an external network.

From a Linux graphical session with Tk installed (on Debian/Kali, `python3-tk`):

```bash
python -m recon_cockpit.gui
```

See the [desktop guide](docs/desktop-gui.md) for the exact scope, approval, cancellation, and evidence behavior. Its dry run still needs the supported Linux isolation environment, even though it runs no tools.

## What is verified, and what comes next

The project has tested controlled Linux execution, blocked out-of-scope destinations, human approval flows, saved evidence replay, and offline workflows against owned fixtures. The [verification record](docs/verification.md) separates those results from portable tests and from work that is still planned.

Provider integration and cost controls have been exercised with synthetic responses, credentials, and prices. **Live model calls, paid provider use, and real-model behavior have not been validated or enabled.** The current [roadmap](docs/roadmap.md) also separates the accepted offline work from engagement-wide live enforcement and credential custody still to come. Local audit and evidence files need protection by the operator; they are not tamper-proof against the host owner or a compromised host.

## Run the tests

Install the test extra and run the portable suite:

```bash
python -m pip install -e '.[test]'
python -m pytest -m 'not integration'
```

On a prepared Linux lab, the opt-in integration suite checks real namespace and network enforcement:

```bash
RECON_LINUX_INTEGRATION=1 python -m pytest -m integration -v
```

Portable passes alone do not prove the Linux boundary. The [verification record](docs/verification.md) has the observed results, environments, and remaining limits.

## Project documents

- [Architecture](docs/architecture.md) and [threat model](docs/threat-model.md): how the secure boundaries are intended to work.
- [Secure tool catalog](docs/secure-tool-catalog.md) and [desktop guide](docs/desktop-gui.md): what you can run and inspect today.
- [Current checkpoint](docs/continue-here.md) and [roadmap](docs/roadmap.md): where development stands.
- [H4ck3d competition proposal](docs/competition-proposal.md): the problem, approach, and evaluation plan.
- [Previous README](docs/README-before-rewrite-2026-11-13.md): the full project log kept before this rewrite.

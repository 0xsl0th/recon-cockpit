# Recon Cockpit

Recon Cockpit is an evidence-driven terminal UI for authorized HTB/THM-style
targets. Give it one IP address and it creates a durable case, runs a conservative
initial nmap service scan, parses the XML, and offers only the enumeration paths
supported by the ports and fingerprints it actually observed.

It does not exploit targets. It does not run service enumeration automatically.
Every action after the initial scan is shown as an exact command and requires a
fresh, default-no confirmation.

## Install

Requirements:

- Python 3.11 or newer
- `nmap` for scanning
- Rich (installed with the project)
- Optional tools for the commands you choose to run: `feroxbuster`, `ffuf`,
  NetExec (`nxc`), `smbclient`, `ldapsearch`, and `kerbrute`

Using `uv`:

```bash
uv sync --python 3.13
source .venv/bin/activate
```

Python 3.13 is recommended for compatibility with the broader
offensive-security Python ecosystem.

Or use any Python environment manager and install the project with its normal
editable-install command.

## Start a case

```bash
python recon.py 10.10.11.123
```

For a new case, the only automatic target action is equivalent to:

```text
nmap -Pn -sV --version-light --top-ports 1000 --reason \
  -oX cases/10.10.11.123/scans/initial-….xml \
  -oN cases/10.10.11.123/scans/initial-….nmap 10.10.11.123
```

No NSE scripts, exploit checks, brute force, or all-port scan are part of that
automatic action. Reopening an existing case reuses its saved evidence; pass
`--rescan` to deliberately repeat the initial scan.

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
  [2] Enumerate SMB
  [3] Inspect WinRM
  [4] Run deeper nmap scan
```

If ports 139/445 or an SMB fingerprint are absent, the SMB group does not exist.
HTTP evidence produces ready-to-review feroxbuster and ffuf commands. SMB evidence
produces NetExec anonymous-share, smbclient, and RID-enumeration commands. LDAP
produces RootDSE and base-DN queries; Kerberos produces a username-enumeration
command with prompted domain and user-list values. IIS + SMB + WinRM evidence is
identified as a probable Windows workflow and adjusts the wording and available
credential checks. Domain credentials use NetExec's domain mode; credentials
without a domain use `--local-auth`.

Selecting a group only displays its possible commands. Selecting a command still
does not run it until you answer the final confirmation prompt. Commands execute
as argument arrays, never through a shell, so metacharacters cannot silently add
a pipeline or second command. Long-running output is streamed to the terminal and
incrementally saved to a private transcript; the in-memory parser buffer is bounded.

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
deduplication, target validation, service-gated suggestions, and the inferred
Windows workflow.

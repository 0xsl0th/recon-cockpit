# Routed HTTP execution

`--routed` selects `LinuxRoutedBackend`, independently of `--fixture`. It executes
one bounded HTTP GET or HEAD against one policy-authorized canonical IPv4 literal
and TCP port. The existing default-no approval workflow is preserved. No model,
DNS resolver, shell tool or legacy host runner is involved.

## Network path and authority

| Component | Network access | Filesystem and authority |
| --- | --- | --- |
| Controller | Its existing host/lab network namespace | Owns policy, grants and private audit; never hands these to the executable components |
| Worker | Fresh network namespace; exact IP/TCP destination rule on `tap0` | Minimal read-only Python runtime, zero capabilities, no-new-privileges and syscall filter |
| slirp transport | Uses the controller's existing routes for TCP translation | Separate minimal Bubblewrap filesystem and PID/IPC/UTS/cgroup namespaces; fixed executables, libraries and TUN access during bootstrap |

The transport joins the worker's **user** namespace for TAP setup while retaining
the controller's network namespace. Its setup capabilities confer no host network
administration rights. slirp subsequently applies its own mount sandbox and
seccomp filter, retaining only namespace-local `CAP_NET_BIND_SERVICE`. The worker
retains no capabilities.

Host `/etc` and `/run` are never mounted into the helper. It starts with empty
directories there, so slirp's internal sandbox retains only those empty
directories. Neither executable sees host homes, policy, approvals, audit,
credentials or Docker sockets. Only the helper receives the pinned network
namespace descriptor and readiness/exit pipes. These are trusted bootstrap
handles, never provider-configurable channels.

slirp4netns, libslirp and their dependencies join the trusted computing base.
The worker firewall does not contain a compromised transport with host-network
socket access. Transport, kernel and controller compromise remain outside this
security contract.

## Startup and teardown

1. The controller validates policy, consumes a required grant and fsyncs
   `execution_started` before backend launch.
2. The worker verifies private namespace identities and an initial `lo`-only
   network. It installs default-drop nftables input/output/forward chains.
   Output permits only TCP ORIGINAL traffic to the exact action IP/port on
   `tap0`; input permits only matching ESTABLISHED REPLY traffic on `tap0`.
3. After capability drop and resource/syscall restrictions, the worker emits
   `READY` and waits. No request has been sent.
4. The controller pins private namespaces using Bubblewrap's info pipe and starts
   the separate transport with fixed options. Host-loopback mapping, built-in
   DNS, IPv6, API sockets and port forwarding are disabled or omitted.
5. The helper must emit its exact readiness byte with both processes alive before
   the controller sends `GO`. The worker checks interfaces are precisely
   `lo,tap0`, closes its bootstrap input and performs one literal HTTP request.
6. A shared deadline and aggregate output budget cover both trees and all pipes.
   Bad gates, early exits, deadlines and excess output terminate/reap both trees.
   The exit pipe and Bubblewrap's parent-death behavior bind lifetime to the
   controller. Cleanup failure cannot report success.

The worker keeps the original 256 MiB address-space, 1 MiB file-size/private-temp,
64-descriptor, zero-core, CPU, process and syscall limits. Transport limits are
256 MiB address-space, 1 MiB file-size, 64 descriptors, 16 processes, zero cores
and bounded CPU; slirp's final filesystem is a small private tmpfs. Setup allowance
is 15 seconds plus the action timeout; HTTP retains its shorter action deadline
and byte cap. Redirects are never followed.

## Prerequisites and use

Validated on Kali amd64 with Bubblewrap 0.11.2, slirp4netns 1.3.3, libslirp 4.9.3,
nftables 1.1.5 and Python 3.14.6. Add `slirp4netns` and its dependency `libslirp0`
to the original prerequisites. util-linux supplies `prlimit` and `unshare`.
TUN, unprivileged namespaces, non-setuid Bubblewrap and the documented Debian/Kali
native-library layout are required.

```bash
sudo apt-get install --no-install-recommends slirp4netns
```

The application runs as a normal user. No host firewall, route, forwarding, NAT,
sysctl or interface changes are needed. Remote targets must already be reachable
through the operator's existing routes, such as an established lab VPN. This
backend does not configure those routes.

Examples use **documentation addresses**, not remote authorization. Review/edit
copies with your authorized target/port and retain `require_approval: true`:

```bash
.venv/bin/python -m recon_cockpit.secure_agent --routed \
  --policy examples/secure-agent-routed-policy.json \
  --proposal examples/secure-agent-routed-action.json --dry-run

# In a human terminal, after configuring the authorized destination:
.venv/bin/python -m recon_cockpit.secure_agent --routed \
  --policy /path/to/private-policy.json --proposal /path/to/action.json --execute
```

The challenge uses its displayed 16-character prefix; full action/policy digests
bind the grant. `--fixture` and `--routed` are mutually exclusive. There is no
approve-all flag, configurable helper/transport argument or fallback.

Actions reject all CIDRs (including `/32`), IPv6, hostnames, noncanonical IPv4,
loopback, link-local, unspecified/multicast/reserved high ranges and the fixed
slirp subnet `10.0.2.0/24`. The latter prevents gateway/DNS/guest aliases from
changing the approved destination's meaning. Policy scope may use CIDRs, but the
action must specify one allowed literal. Ports 1..65535 are remote destinations.

## Owned-service validation

The demo creates a disposable outer user/network/mount/PID namespace. It maps
the normal UID to itself, configures private loopback addresses and drops all
capabilities before starting services/controller. Target `192.0.2.10:8080` and
witnesses `192.0.2.11:8080` and `192.0.2.10:8081` are outside the execution
namespace and disconnected from the host/LAN. Requests cross the real worker
TAP, nftables and slirp translation path.

```bash
.venv/bin/python -m pytest -m 'not integration'
RECON_LINUX_INTEGRATION=1 .venv/bin/python -m pytest -m integration -v
.venv/bin/python scripts/secure_agent_routed_demo.py \
  --audit .secure-agent/routed-demo-new.jsonl
.venv/bin/python scripts/secure_agent_routed_demo.py --interactive \
  --audit .secure-agent/routed-human-new.jsonl
```

Use a new audit filename per demo. Each witness first succeeds through its own
separately authorized routed action. Restricted actions then attempt direct
sockets to forbidden IP/port witnesses; their accept counts must stay unchanged.
Cases cover GET/HEAD, malicious content, both redirects, output limits and
deadlines. Missing prerequisites fail opted-in Linux tests. Portable scripted
process tests separately cover failed handshakes, bounded capture and cleanup.

The unattended demo uses explicit lab-only allow policies. `--interactive` calls
the real CLI/controller/backend and asks the operator for the challenge; no grant
is scripted. See [verification.md](verification.md) for actual results. No real
remote/VPN target or autonomous model was exercised. TLS, Nmap, multi-target/CIDR
execution and real providers remain future work.

Design references: [slirp manual](https://github.com/rootless-containers/slirp4netns/blob/master/slirp4netns.1.md),
[slirp sandbox](https://github.com/rootless-containers/slirp4netns/blob/master/sandbox.c),
[Bubblewrap source](https://github.com/containers/bubblewrap/blob/main/bubblewrap.c).

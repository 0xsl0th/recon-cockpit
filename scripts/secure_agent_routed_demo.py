"""Validate routed HTTP against owned services in a disposable Linux network.

The outer lab has no interface to the host network. Its documentation-address
listeners sit outside the execution namespace, so requests traverse the real
routed backend. The default policy explicitly permits these lab actions without
approval. --interactive instead invokes the real terminal approval interface.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from uuid import uuid4

from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.isolation import _capture_bounded, _trusted_program
from recon_cockpit.secure_agent.models import parse_policy
from recon_cockpit.secure_agent.worker import INJECTION_FIXTURE, _status, drop_privileges
if __package__:
    from .secure_agent_linux_demo import _require_boundary_checks
else:
    from secure_agent_linux_demo import _require_boundary_checks


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TARGET = "192.0.2.10"
IP_WITNESS = "192.0.2.11"
UNAUTHORIZED_TARGET = "192.0.2.12"
PORT = 8080
PORT_WITNESS = 8081
CASES = (
    ("normal", "/", "GET", "succeeded"),
    ("head", "/", "HEAD", "succeeded"),
    ("injection", "/injection", "GET", "succeeded"),
    ("redirect_ip", "/redirect-ip", "GET", "succeeded"),
    ("redirect_port", "/redirect-port", "GET", "succeeded"),
    ("large", "/large", "GET", "output_limit"),
    ("slow", "/slow", "GET", "timeout"),
)


def lab_policy(target: str = TARGET, port: int = PORT, *, approval: bool = False):
    return parse_policy({
        "schema_version": "1", "policy_version": "owned-routed-lab-v1",
        "allowed_targets": [target + "/32"], "allowed_tools": ["http_probe"],
        "allowed_ports": [port], "allowed_methods": ["GET", "HEAD"],
        "max_timeout_seconds": 3, "max_output_bytes": 4096, "max_targets": 1,
        "require_approval": approval, "approval_ttl_seconds": 60,
    })


def lab_action(target: str = TARGET, port: int = PORT, *, path: str = "/", method: str = "GET") -> dict:
    return {
        "schema_version": "1", "action_id": str(uuid4()), "tool_id": "http_probe",
        "target": target, "parameters": {
            "port": port, "method": method, "path": path,
            "timeout_seconds": 1, "max_output_bytes": 4096,
        },
        "rationale": "Owned HTTP service in the disposable routed validation lab.",
    }


def _response(path: str) -> tuple[int, bytes, bytes]:
    if path == "/injection":
        return 200, INJECTION_FIXTURE, b""
    if path == "/large":
        return 200, b"x" * (65536 + 4096), b""
    if path == "/slow":
        time.sleep(35)
    if path == "/redirect-ip":
        return 302, b"Owned redirect witness", f"Location: http://{IP_WITNESS}:{PORT}/forbidden\r\n".encode("ascii")
    if path == "/redirect-port":
        return 302, b"Owned redirect witness", f"Location: http://{TARGET}:{PORT_WITNESS}/forbidden\r\n".encode("ascii")
    return 200, b"Recon Cockpit owned routed fixture\n", b""


class OwnedRoutedServices:
    """Fixed, explicitly bound lab servers; accept counts expose any leakage."""

    def __init__(self) -> None:
        self.listeners: dict[str, socket.socket] = {}
        self.threads: list[threading.Thread] = []
        self.counts = {"allowed": 0, "forbidden_ip": 0, "forbidden_port": 0}
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        try:
            for name, address in (("allowed", (TARGET, PORT)), ("forbidden_ip", (IP_WITNESS, PORT)),
                                  ("forbidden_port", (TARGET, PORT_WITNESS))):
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.listeners[name] = listener
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(address)
                listener.listen(8)
                listener.settimeout(0.2)
            for name, listener in self.listeners.items():
                thread = threading.Thread(target=self._serve, args=(name, listener), daemon=True)
                thread.start()
                self.threads.append(thread)
        except Exception:
            self.close()
            raise

    def _serve(self, name: str, listener: socket.socket) -> None:
        while not self.stopped.is_set():
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with self.lock:
                self.counts[name] += 1
            with connection:
                try:
                    connection.settimeout(1)
                    request = bytearray()
                    while b"\r\n\r\n" not in request and len(request) < 4096:
                        chunk = connection.recv(4096 - len(request))
                        if not chunk:
                            break
                        request.extend(chunk)
                    line = bytes(request).split(b"\r\n", 1)[0].split(b" ")
                    if len(line) != 3:
                        continue
                    status, body, extra = _response(line[1].decode("ascii"))
                    headers = (f"HTTP/1.1 {status} Owned\r\nContent-Length: {len(body)}\r\n"
                               "Connection: close\r\n").encode("ascii") + extra + b"\r\n"
                    connection.sendall(headers + (b"" if line[0] == b"HEAD" else body))
                except (OSError, UnicodeError):
                    pass

    def snapshot(self) -> dict[str, int]:
        with self.lock:
            return dict(self.counts)

    def close(self) -> None:
        self.stopped.set()
        for listener in self.listeners.values():
            listener.close()
        # The deliberately slow daemon has no state outside the disposable lab.
        for thread in self.threads:
            thread.join(timeout=0.3)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def _prepare_private_network(host_userns: str, host_netns: str) -> dict:
    if sys.platform != "linux" or os.geteuid() == 0:
        raise RuntimeError("The owned routed lab requires an unprivileged Linux user")
    for name, original in (("user", host_userns), ("net", host_netns)):
        if (not re.fullmatch(name + r":\[\d+\]", original)
                or os.readlink(f"/proc/self/ns/{name}") == original):
            raise RuntimeError("Refusing lab network setup outside its private namespaces")
    mappings = [tuple(map(int, line.split())) for line in Path("/proc/self/uid_map").read_text().splitlines()]
    if mappings != [(os.getuid(), os.getuid(), 1)]:
        raise RuntimeError("The lab requires the original unprivileged UID identity mapping")
    if [name for _, name in socket.if_nameindex()] != ["lo"]:
        raise RuntimeError("The owned lab must have only its disconnected loopback interface")
    ip = _trusted_program("ip")
    subprocess.run([ip, "link", "set", "lo", "up"], check=True, timeout=3,
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for address in (TARGET, IP_WITNESS, UNAUTHORIZED_TARGET):
        subprocess.run([ip, "address", "add", address + "/32", "dev", "lo"], check=True, timeout=3,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    drop_privileges()
    status = _status()
    caps_zero = all(int(status[key], 16) == 0 for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
    if not caps_zero or os.geteuid() == 0:
        raise RuntimeError("Lab controller privileges were not dropped")
    return {"private_user_namespace": True, "private_network_namespace": True,
            "controller_uid": os.geteuid(), "controller_capabilities_zero": True,
            "host_network_changes": False}


def _assert_result(result: dict, expected: str) -> dict:
    if result["execution_status"] != expected:
        raise RuntimeError(f"Expected {expected}; execution returned {result['execution_status']}")
    payload = result.get("untrusted_result")
    if type(payload) is not dict:
        raise RuntimeError("Missing routed execution evidence")
    return payload


def _run_validation(audit_path: Path, services: OwnedRoutedServices, lab_evidence: dict) -> dict:
    from recon_cockpit.secure_agent.routed import LinuxRoutedBackend

    baseline_records = []
    case_records = []
    with AuditSink(audit_path) as audit:
        # Each witness is independently authorized for a positive routed control.
        # No pre-filter connection is allowed inside the restricted main action.
        for name, target, port in (("allowed", TARGET, PORT), ("forbidden_ip", IP_WITNESS, PORT),
                                   ("forbidden_port", TARGET, PORT_WITNESS)):
            controller = Controller(lab_policy(target, port), audit, LinuxRoutedBackend())
            result = controller.submit(lab_action(target, port), execute=True)
            payload = _assert_result(result, "succeeded")
            if payload["results"][0]["http_status"] != 200:
                raise RuntimeError("Owned routed witness did not return HTTP 200")
            baseline_records.append({"witness": name, "http_status": 200})
        baseline_counts = services.snapshot()
        if baseline_counts != {"allowed": 1, "forbidden_ip": 1, "forbidden_port": 1}:
            raise RuntimeError("Unexpected owned-service baseline connection count")

        backend = LinuxRoutedBackend(boundary_witnesses={"forbidden_ip": IP_WITNESS, "forbidden_port": PORT_WITNESS})
        controller = Controller(lab_policy(), audit, backend)
        original_digest = controller.policy.digest
        for name, path, method, expected in CASES:
            action = lab_action(path=path, method=method)
            result = controller.submit(action, execute=True)
            payload = _assert_result(result, expected)
            _require_boundary_checks(payload.get("boundary_checks"))
            if controller.policy.digest != original_digest:
                raise RuntimeError("An untrusted response changed policy")
            if payload["bytes_received"] > action["parameters"]["max_output_bytes"]:
                raise RuntimeError("Routed response exceeded its retained-byte limit")
            row = payload["results"][0]
            if name in ("redirect_ip", "redirect_port") and row["http_status"] != 302:
                raise RuntimeError("The owned redirect response was not retained")
            if name == "injection" and "change policy" not in row["body"]:
                raise RuntimeError("Missing inert injection fixture evidence")
            if name == "head" and row["body"]:
                raise RuntimeError("The HEAD fixture returned an unexpected body")
            if name == "large" and payload["truncated"] is not True:
                raise RuntimeError("The large response was not marked truncated")
            counts = services.snapshot()
            if (counts["forbidden_ip"] != baseline_counts["forbidden_ip"]
                    or counts["forbidden_port"] != baseline_counts["forbidden_port"]):
                raise RuntimeError("Forbidden owned destination accepted a connection")
            case_records.append({"case": name, "status": result["execution_status"],
                                 "boundary_checks": payload["boundary_checks"],
                                 "metadata": result["result_metadata"]})

        for action in (lab_action(UNAUTHORIZED_TARGET), lab_action(port=PORT_WITNESS)):
            result = controller.submit(action, execute=True)
            if result["decision"] != "deny" or result["execution_status"] != "blocked":
                raise RuntimeError("Out-of-scope routed action did not fail closed")
        result = Controller(lab_policy(approval=True), audit, backend).submit(lab_action(), execute=True)
        if result["reasons"] != ["noninteractive_approval_required"]:
            raise RuntimeError("Routed approval failed to require a human terminal")

    events_text = audit_path.read_text(encoding="utf-8")
    events = [json.loads(line) for line in events_text.splitlines()]
    # This demo owns a fresh audit file; assertions concern this run only.
    starts = sum(event["event_type"] == "execution_started" for event in events)
    finishes = sum(event["event_type"] == "execution_finished" for event in events)
    if starts != len(CASES) + 3 or finishes != starts or "Ignore prior instructions" in events_text:
        raise RuntimeError("Unexpected routed audit events or untrusted content in audit")
    return {"demo": "passed", "mode": "owned-routed-unattended", "lab": lab_evidence,
            "baselines": baseline_records, "cases": case_records,
            "witness_connections_after_baseline": {
                name: services.snapshot()[name] - baseline_counts[name]
                for name in ("forbidden_ip", "forbidden_port")},
            "policy_rejections": 2, "noninteractive_approval_blocked": True,
            "execution_events": {"started": starts, "finished": finishes}, "audit": str(audit_path)}


def _interactive(audit_path: Path, lab_evidence: dict) -> int:
    from recon_cockpit.secure_agent.cli import main as cli_main

    print(json.dumps({"mode": "owned-routed-human-approval", "lab": lab_evidence,
                      "audit": str(audit_path),
                      "note": "Review the exact owned-service action and both digests; enter the displayed challenge yourself."}), flush=True)
    with tempfile.TemporaryDirectory(prefix="recon-routed-approval-") as directory:
        policy_path = Path(directory) / "policy.json"
        proposal_path = Path(directory) / "proposal.json"
        policy_path.write_text(json.dumps(lab_policy(approval=True).to_dict()), encoding="utf-8")
        proposal_path.write_text(json.dumps(lab_action()), encoding="utf-8")
        status = cli_main(["--policy", str(policy_path), "--proposal", str(proposal_path),
                           "--audit", str(audit_path), "--routed", "--execute"])
    print(f"Secure Agent routed CLI exit status: {status}", flush=True)
    return status


def _lab_command(audit_path: Path, *, interactive: bool = False) -> list[str]:
    if sys.platform != "linux" or os.geteuid() == 0:
        raise RuntimeError("Run the owned routed lab as an unprivileged Linux user")
    argv = [_trusted_program("unshare"), "--user", "--map-current-user", "--keep-caps", "--net",
            "--mount", "--pid", "--fork", "--mount-proc", "--kill-child",
            sys.executable, str(Path(__file__).resolve()), "--_inside", "--audit", str(audit_path.resolve()),
            "--_host-userns", os.readlink("/proc/self/ns/user"), "--_host-netns", os.readlink("/proc/self/ns/net")]
    if interactive:
        argv.append("--interactive")
    return argv


def run_owned_lab(*, audit: Path) -> subprocess.CompletedProcess:
    """Bounded noninteractive entry point shared by the demo and opted-in tests."""
    argv = _lab_command(audit)
    # Fixed helper script and absolute paths do not depend on a caller's cwd.
    code, stdout, stderr, reason = _capture_bounded(argv, b"", 60, 131072)
    if reason:
        raise RuntimeError("Owned routed lab exceeded its " + reason + " bound")
    return subprocess.CompletedProcess(argv, code, stdout, stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, help="retain evidence in a new operator-selected audit file")
    parser.add_argument("--interactive", action="store_true", help="request a real one-time human terminal approval")
    parser.add_argument("--_inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--_host-userns", help=argparse.SUPPRESS)
    parser.add_argument("--_host-netns", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    audit_path = args.audit or Path(tempfile.mkdtemp(prefix="recon-routed-demo-")) / "audit.jsonl"
    try:
        if not args._inside:
            if audit_path.exists():
                raise RuntimeError("Choose a new audit path so this run's evidence is unambiguous")
            if args.interactive:
                return subprocess.call(_lab_command(audit_path, interactive=True), cwd=PROJECT_ROOT)
            result = run_owned_lab(audit=audit_path)
            sys.stdout.buffer.write(result.stdout)
            sys.stdout.buffer.flush()
            if result.returncode:
                print(json.dumps({"demo": "failed", "reason": "owned_lab_setup_or_validation_failed",
                                  "exit_status": result.returncode}), flush=True)
            return result.returncode
        evidence = _prepare_private_network(args._host_userns or "", args._host_netns or "")
        with OwnedRoutedServices() as services:
            if args.interactive:
                return _interactive(audit_path, evidence)
            result = _run_validation(audit_path, services, evidence)
            print(json.dumps(result, sort_keys=True), flush=True)
            return 0
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({"demo": "failed", "detail": str(exc)}, ensure_ascii=True), flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Native custody gates in sealed disconnected namespaces.

The adversarial executable is explicitly a test fixture, not stock compatibility
evidence. Ordinary key-exchange cases execute the actual installed stock images.
"""

import array
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import time

import pytest

from recon_cockpit.secure_agent import network_tools_ssh_fixture as fixture
from recon_cockpit.secure_agent import stock_ssh_spec as spec, stock_ssh_runtime as runtime
from recon_cockpit.secure_agent import stock_ssh_process as process_contract
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import _runtime_files

pytestmark = pytest.mark.integration

PRODUCER = '''import array,fcntl,socket,struct
control=socket.socket(fileno=0)
probe=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
flags=fcntl.ioctl(probe,0x8913,struct.pack('16sh',b'lo',0))
fcntl.ioctl(probe,0x8914,struct.pack('16sh',b'lo',struct.unpack('16sh',flags[:18])[1]|1))
probe.close()
listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM,socket.IPPROTO_TCP)
listener.bind(('127.0.0.1',19022));listener.listen(1)
client=socket.socket(socket.AF_INET,socket.SOCK_STREAM,socket.IPPROTO_TCP)
client.connect(listener.getsockname());server,_=listener.accept();listener.close()
control.sendmsg([b'ready'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[client.fileno(),server.fileno()]))])
'''
OWNER = '''import array,json,os,socket,sys,time
sys.path.insert(0,'/app')
from recon_cockpit.secure_agent import stock_ssh_custodian as custody,worker
control=socket.socket(fileno=0)
raw,ancillary,_,_=control.recvmsg(32768,socket.CMSG_SPACE(4))
request=json.loads(raw);manifest=request['manifest'];fds=array.array('i')
for level,kind,data in ancillary:
 if (level,kind)==(socket.SOL_SOCKET,socket.SCM_RIGHTS):fds.frombytes(data)
assert len(fds)==1
server=socket.socket(fileno=fds[0]);worker.drop_privileges()
if request.get('observe_death'):
 class ObservedLedger(custody.process.ProcessLedger):
  def exec_completed(self,pid,image):
   super().exec_completed(pid,image)
   if self.execs==3:
    control.send(json.dumps({'before_death':self.receipt()}).encode())
 custody.process.ProcessLedger=ObservedLedger
deadline=time.monotonic()+request['seconds']
cancel_at=time.monotonic()+.05 if request['cancel'] else None
result=custody.run_instance(server.fileno(),manifest,deadline=deadline,
 cancelled=(lambda:time.monotonic()>=cancel_at) if cancel_at else None)
server.close();control.send(json.dumps(result).encode())
'''


@pytest.fixture(scope="module", autouse=True)
def opted_in():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for confined native SSH custody")
    assert sys.platform == "linux" and os.geteuid() != 0


@pytest.fixture(scope="module")
def prepared(tmp_path_factory):
    directory = tmp_path_factory.mktemp("ssh-process-native")
    producer, owner = directory / "producer.py", directory / "owner.py"
    producer.write_text(PRODUCER)
    owner.write_text(OWNER)
    bootstrap = _runtime_files("/usr/bin/python3", None)
    manifests = {configuration: runtime.inspect_runtime(configuration, "O2",
        control=ExecutionControl(deadline=time.monotonic()+15)) for configuration in ("A", "B")}
    return directory, producer, owner, bootstrap, manifests


def _base(bootstrap, *, owner=False):
    stdlib, files = bootstrap
    argv = ["/usr/bin/bwrap", "--unshare-all", "--uid", "65534" if owner else "0", "--gid", "65534" if owner else "0",
        "--cap-drop", "ALL", "--cap-add", "CAP_SETPCAP" if owner else "CAP_NET_ADMIN", "--die-with-parent",
        "--new-session", "--as-pid-1", "--clearenv", "--proc", "/proc", "--dev", "/dev", "--ro-bind", stdlib, stdlib]
    for source, destination in files:
        argv += ["--ro-bind", source, destination]
    return argv


def _pair(prepared):
    _, source, _, bootstrap, _ = prepared
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    argv = _base(bootstrap) + ["--ro-bind", str(source), "/producer.py", "--remount-ro", "/",
                              "/usr/bin/python3", "-I", "-S", "/producer.py"]
    process = subprocess.Popen(argv, stdin=child, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    child.close()
    try:
        parent.settimeout(5)
        data, ancillary, flags, _ = parent.recvmsg(100, socket.CMSG_SPACE(8))
        descriptors = array.array("i")
        for level, kind, raw in ancillary:
            assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
            descriptors.frombytes(raw)
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == 0 and len(descriptors) == 2 and data == b"ready" and flags == 0, stderr
        return socket.socket(fileno=descriptors[0]), descriptors[1]
    finally:
        parent.close()
        if process.poll() is None:
            process.kill(); process.wait(timeout=2)


def _host_tree(root):
    result = []
    pending = [root]
    while pending:
        pid = pending.pop()
        try:
            status = (Path("/proc") / str(pid) / "status").read_text()
            children = (Path("/proc") / str(pid) / "task" / str(pid) / "children").read_text()
        except FileNotFoundError:
            continue
        result.append((pid, status))
        pending.extend(map(int, children.split()))
    return result


def _kill_custodian_and_verify_no_survivors(process, parent):
    before = json.loads(parent.recv(65536))["before_death"]
    assert (before["exec_attempts"], before["fork_attempts"], before["server_identities"]) == (3, 2, 3)
    assert [row["image"] for row in before["events"] if row["operation"] == "exec_completed"] == list(process_contract.EXECUTABLES)
    tree = _host_tree(process.pid)
    owners = [pid for pid, status in tree if any(line.startswith("NSpid:") and line.split()[-1] == "1"
                                               for line in status.splitlines())]
    assert len(owners) == 1
    owner = owners[0]
    descendants = _host_tree(owner)
    # The writer normally exited already; the session and auth images remain
    # alive waiting for NEWKEYS, which this test never sends.
    assert len(descendants) >= 3
    descriptors = [os.pidfd_open(pid) for pid, _ in descendants]
    try:
        signal.pidfd_send_signal(descriptors[0], signal.SIGKILL)
        process.communicate(timeout=3)
        poller = select.poll()
        for fd in descriptors: poller.register(fd, select.POLLIN)
        remaining = set(descriptors)
        deadline = time.monotonic() + 2
        while remaining and time.monotonic() < deadline:
            for fd, flags in poller.poll(50):
                if flags & select.POLLIN:
                    remaining.discard(fd); poller.unregister(fd)
        assert not remaining, "a server descendant survived custodian death"
        assert not _host_tree(owner), "the dead namespace retained process identities"
        assert process.returncode != 0
        return {"custodian_killed": True, "descendant_pidfds_terminated": len(descriptors) - 1,
                "predeath_graph": before}
    finally:
        for fd in descriptors: os.close(fd)


def run_owned(prepared, *, configuration="A", attack=None, cancel=False, stall=False, kill_custodian=False):
    directory, _, source, bootstrap, manifests = prepared
    manifest = json.loads(json.dumps(manifests[configuration]))
    binary = None
    if attack:
        binary_path = directory / attack
        subprocess.run(["/usr/bin/cc", "-O0", "-DPROBE=" + json.dumps(attack),
                        str(Path(__file__).with_name("stock_ssh_custodian_probe.c")), "-o", str(binary_path)],
                       check=True, capture_output=True, timeout=10)
        binary = binary_path.read_bytes()
    descriptors = []
    compiled = {destination: raw for _, destination, raw in spec.compiled_files(configuration, "O2")}
    argv = _base(bootstrap, owner=True)
    package = Path(runtime.__file__).parent.parent
    argv += ["--ro-bind", str(package), "/app/recon_cockpit", "--ro-bind", str(source), "/owner.py"]
    try:
        for row in manifest["files"]:
            # Explicit adversarial fixture substitution; these manifests are
            # never exported as stock daemon compatibility evidence.
            raw = (binary if binary is not None and row["destination"] in manifest["executables"] else
                   compiled[row["destination"]] if row["destination"] in compiled else Path(row["source"]).read_bytes())
            row["size"], row["sha256"] = len(raw), hashlib.sha256(raw).hexdigest()
            fd = os.memfd_create("ssh-custody-test", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            descriptors.append(fd)
            offset = 0
            while offset < len(raw): offset += os.write(fd, raw[offset:])
            os.lseek(fd, 0, os.SEEK_SET)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
            mode = "0555" if row["destination"] in manifest["executables"] or row["destination"] == manifest["interpreter"] else "0400" if row["destination"] == spec.HOST_KEY_PATH else "0444"
            argv += ["--perms", mode, "--ro-bind-data", str(fd), row["destination"]]
        argv += ["--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
                 "/usr/bin/python3", "-I", "-S", "/owner.py"]
        connection, server = _pair(prepared)
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        process = subprocess.Popen(argv, stdin=child, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   pass_fds=tuple(descriptors))
        child.close()
        parent.settimeout(6)
        parent.sendmsg([json.dumps({"manifest": manifest, "seconds": .1 if stall else 4.8, "cancel": cancel,
                                   "observe_death": kill_custodian}).encode()],
                       [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [server]))])
        os.close(server)
        try:
            if attack or cancel or stall:
                receipt = json.loads(parent.recv(65536))
            else:
                deadline = time.monotonic()+3
                banner = fixture._read_banner(connection, deadline)
                connection.sendall(b"SSH-2.0-ReconOwnedProbe\r\n")
                server_init = fixture._read_packet(connection, deadline)
                names = tuple(b"rsa-sha2-512" if configuration == "B" and name == b"rsa-sha2-256" else name for name in fixture.KEX_NAMES)
                init = b"\x14" + b"\0"*16 + b"".join(fixture.ssh_string(name) for name in names) + b"\0"*5
                connection.sendall(fixture._packet(init))
                connection.sendall(fixture._packet(b"\x1e" + fixture.mpint(pow(2, 12345, fixture.GROUP14_P))))
                reply = fixture._read_packet(connection, deadline)
                assert reply[0] == 31 and fixture._take_string(reply, 1)[0] == fixture.public_blob()
                if kill_custodian:
                    return _kill_custodian_and_verify_no_survivors(process, parent)
                connection.close()  # no NEWKEYS or userauth is ever sent
                receipt = json.loads(parent.recv(65536))
                receipt["observed_banner"] = banner.decode("ascii")
                receipt["exact_public_fixture_key_received"] = True
            stdout, stderr = process.communicate(timeout=6)
            assert process.returncode == 0, stderr
            assert receipt["all_server_processes_reaped"] is True
            process_contract.validate_receipt({key: value for key, value in receipt.items()
                if key not in ("observed_banner", "exact_public_fixture_key_received")})
            return receipt
        finally:
            connection.close(); parent.close()
            if process.poll() is None:
                process.kill(); process.wait(timeout=2)
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


@pytest.mark.parametrize("configuration", ("A", "B"))
def test_stock_three_images_two_forks_and_key_exchange_reaped(prepared, configuration):
    receipt = run_owned(prepared, configuration=configuration)
    assert receipt["stop_reason"] == "processes_exited"
    assert (receipt["exec_attempts"], receipt["fork_attempts"], receipt["server_identities"]) == (3, 2, 3)
    assert receipt["observed_banner"] == "SSH-2.0-OpenSSH_10.2p1" + (" Owned-lab-B" if configuration == "B" else "")


@pytest.mark.parametrize("attack", ("extra_fork", "auth_fork", "extra_exec", "wrong_argv", "wrong_environment"))
def test_adversarial_process_request_is_stopped_before_kernel_execution(prepared, attack):
    receipt = run_owned(prepared, attack=attack)
    assert receipt["stop_reason"] == ("stock_ssh_fork_denied" if "fork" in attack else "stock_ssh_exec_denied")
    assert receipt["server_identities"] <= 3 and receipt["fork_attempts"] <= 2 and receipt["exec_attempts"] <= 3


@pytest.mark.parametrize("attack", ("socket", "socketpair", "connect", "shared_mmap", "sysv_shm", "thread_clone",
                                   "ptrace", "pidfd_open", "pidfd_peer", "pidfd_getfd", "pidfd_send_signal",
                                   "execveat", "host_interpreter", "namespace"))
def test_adversarial_escape_syscall_denied_after_full_process_budget(prepared, attack):
    receipt = run_owned(prepared, attack=attack)
    assert receipt["stop_reason"] == "processes_exited"
    assert base64.b64decode(receipt["stderr_base64"]) == ("blocked:" + attack + "\n").encode()
    assert (receipt["exec_attempts"], receipt["fork_attempts"], receipt["server_identities"]) == (3, 2, 3)


@pytest.mark.parametrize("cancel", (False, True))
def test_stalled_stock_instance_cancellation_or_deadline_reaps_every_child(prepared, cancel):
    receipt = run_owned(prepared, cancel=cancel, stall=not cancel)
    assert receipt["stop_reason"] == ("stock_ssh_instance_cancelled" if cancel else "stock_ssh_instance_timeout")


def test_killed_custodian_leaves_no_server_descendant_after_complete_stock_kex(prepared):
    receipt = run_owned(prepared, kill_custodian=True)
    assert receipt["custodian_killed"] and receipt["descendant_pidfds_terminated"] >= 2

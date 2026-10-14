"""Exercise the emitted adversarial probe's denial handling without sockets."""

from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import stock_http_spec as spec
from test_stock_http_budget_linux import _probe_source as diagnostic_source
from test_stock_http_production_budget_linux import _probe_source


HARNESS = '''def run_probe():
    if request:
        if request["target"]:
            result = probe_headers_at_deadline(request, deadline)
            return result
'''


def run_probe(*, stage=None, error=None, response=b""):
    calls = []
    completed = object()
    request = spec.action("A", "O1")
    deadline = object()

    class Channel:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            calls.append(("close",))

        def operation(self, name, *arguments):
            calls.append((name, *arguments))
            if name == stage:
                raise error

        def settimeout(self, seconds):
            self.operation("settimeout", seconds)

        def connect(self, destination):
            self.operation("connect", destination)

        def sendall(self, raw):
            self.operation("sendall", raw)

        def recv(self, size):
            self.operation("recv", size)
            return response

    def first_probe(action, bound):
        assert action is request and bound is deadline
        calls.append(("legitimate_probe",))
        return completed

    def connection(family, kind):
        assert (family, kind) == (2, 1)
        calls.append(("socket", family, kind))
        return Channel()

    def remaining(bound, cap):
        assert bound is deadline and cap == 0.2
        return cap

    namespace = {"socket": SimpleNamespace(AF_INET=2, SOCK_STREAM=1, socket=connection),
        "request": request, "deadline": deadline, "selected": {"configuration": "A", "case": "O1"},
        "worker": SimpleNamespace(_remaining=remaining), "spec": spec,
        "probe_headers_at_deadline": first_probe}
    exec(compile(_probe_source(HARNESS, "O1"), "production-budget-probe", "exec"), namespace)
    result = namespace["run_probe"]()
    assert result is completed
    assert calls.count(("legitimate_probe",)) == calls.count(("socket", 2, 1)) == 1
    assert calls[0] == ("legitimate_probe",) and calls[-1] == ("close",)
    assert ("settimeout", 0.2) in calls
    assert ("connect", (request["target"], request["parameters"]["port"])) in calls
    return calls


@pytest.mark.parametrize("stage", ("connect", "sendall", "recv"))
@pytest.mark.parametrize("error", (ConnectionResetError, BrokenPipeError))
def test_expected_denial_at_each_socket_stage_preserves_first_result(stage, error):
    calls = run_probe(stage=stage, error=error("denied"))
    if stage == "connect":
        assert not any(item[0] == "sendall" for item in calls)
    else:
        assert ("sendall", spec.request_bytes("A", "O1")) in calls


@pytest.mark.parametrize("stage", ("connect", "sendall", "recv"))
@pytest.mark.parametrize("error", (TimeoutError, ConnectionRefusedError, PermissionError, RuntimeError))
def test_unexpected_errors_still_fail_probe(stage, error):
    with pytest.raises(error):
        run_probe(stage=stage, error=error("unexpected"))


def test_empty_denial_passes_but_any_response_still_fails():
    assert ("sendall", spec.request_bytes("A", "O1")) in run_probe()
    with pytest.raises(RuntimeError, match="stock_extra_request_produced_response"):
        run_probe(response=b"x")


def test_nmap_probe_instrumentation_stays_identical_to_accepted_diagnostic():
    source = 'def main():\n    if True:\n        os.execve(argv[0], argv, native.execution_environment(manifest["tool_id"]))\n'
    assert _probe_source(source, "O5") == diagnostic_source(source, "O5")

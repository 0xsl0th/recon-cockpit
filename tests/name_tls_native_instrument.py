"""Fixed test source variants inspected and sealed by the ordinary runtime."""

import hashlib

from recon_cockpit.secure_agent import name_tls_python_runtime as sources


def variant(tmp_path, monkeypatch, module, transform):
    original_path = sources.source_path
    original = original_path(module)
    candidate = tmp_path / (module + ".py")
    raw = transform(original.read_text())
    compile(raw, str(candidate), "exec")
    candidate.write_text(raw)
    monkeypatch.setattr(sources, "source_path", lambda name: candidate if name == module else original_path(name))
    return {"module": module, "original_sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
            "instrumented_sha256": hashlib.sha256(candidate.read_bytes()).hexdigest()}

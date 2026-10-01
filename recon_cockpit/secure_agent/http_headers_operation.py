"""One fixed HTTP GET; retain bounded wire bytes without interpreting them."""

import base64
import hashlib
import signal
import socket

from . import worker


def probe(target, parameters, *, deadline=None):
    expected = {"port": 8080, "method": "GET", "path": "/harbordesk/portal.html",
                "timeout_seconds": 1, "max_output_bytes": 2048}
    if (target != "127.0.0.1" or type(parameters) is not dict or parameters != expected
            or any(type(parameters[key]) is not int for key in ("port", "timeout_seconds", "max_output_bytes"))):
        raise ValueError("invalid_http_headers_operation")
    limit = parameters["max_output_bytes"]
    response = bytearray()
    timeout = worker._remaining(deadline, parameters["timeout_seconds"])
    previous = signal.signal(signal.SIGALRM, worker._deadline)
    signal.setitimer(signal.ITIMER_REAL, timeout)
    status = "succeeded"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            connection.connect((target, parameters["port"]))
            connection.sendall(b"GET /harbordesk/portal.html HTTP/1.1\r\n"
                               b"Host: 127.0.0.1:8080\r\nConnection: close\r\n\r\n")
            while len(response) <= limit:
                chunk = connection.recv(min(4096, limit + 1 - len(response)))
                if not chunk:
                    break
                response.extend(chunk)
                if len(response) > limit:
                    status = "output_limit"
                    break
            if not response:
                status = "failed"
    except TimeoutError:
        status = "timeout"
    except OSError:
        status = "failed"
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    retained = bytes(response[:limit])
    row = {"target": target, "port": 8080, "bytes_received": len(retained),
           "truncated": len(response) > limit, "raw_response": base64.b64encode(retained).decode("ascii"),
           "response_sha256": hashlib.sha256(retained).hexdigest()}
    return {"status": status, "results": [row], "bytes_received": len(retained), "truncated": row["truncated"]}

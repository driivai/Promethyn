"""Per-request monotonic socket deadlines and a killable, secret-free resolver.

No global socket monkeypatches, signal handlers, or abandoned worker threads.
As with socket timeouts generally, scheduling and OS process cleanup can add
overhead; this is not a hard real-time guarantee against a stalled kernel.
"""

from __future__ import annotations

import io
import ipaddress
import json
import math
import socket
import subprocess
import sys
import time
from pathlib import Path


def remaining(deadline: float) -> float:
    if not math.isfinite(deadline):
        raise ValueError("HTTP exchange deadline must be finite")
    budget = deadline - time.monotonic()
    if budget <= 0:
        raise TimeoutError("HTTP exchange deadline exceeded")
    return budget


def _resolver_command() -> list[str]:
    return [sys.executable, "-I", str(Path(__file__).with_name("_dns_worker.py"))]


def resolve(host: str, port: int, deadline: float) -> list:
    remaining(deadline)
    request = json.dumps([host, port]).encode("ascii")
    if len(request) > 4096:
        raise OSError("DNS lookup request exceeds limit")
    # Do not run resolver Python code in a forked copy of the runtime. Exec a
    # fresh isolated interpreter with no ambient secrets, import overrides or FDs.
    with subprocess.Popen(
        _resolver_command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, env={}, close_fds=True,
    ) as process:
        try:
            response, _ = process.communicate(request, timeout=remaining(deadline))
        except (subprocess.TimeoutExpired, TimeoutError) as exc:
            process.kill()
            process.communicate()  # reap; no resolver may continue after return
            raise TimeoutError("HTTP exchange deadline exceeded during DNS") from exc
        except BaseException:
            process.kill()
            process.communicate()
            raise
        remaining(deadline)
        if process.returncode != 0 or len(response) > 65536:
            raise OSError("DNS lookup failed")
    try:
        records = json.loads(response)
        if not isinstance(records, list) or not 1 <= len(records) <= 256:
            raise ValueError
        for family, kind, protocol, canonname, address in records:
            if (family not in (socket.AF_INET, socket.AF_INET6)
                    or kind != socket.SOCK_STREAM or protocol not in (0, socket.IPPROTO_TCP)
                    or not isinstance(address, list)
                    or len(address) != (2 if family == socket.AF_INET else 4)
                    or address[1] != port):
                raise ValueError
            ip = ipaddress.ip_address(address[0])
            if ip.version != (4 if family == socket.AF_INET else 6):
                raise ValueError
    except (ValueError, TypeError, IndexError) as exc:
        raise OSError("DNS lookup returned invalid addresses") from exc
    remaining(deadline)
    return records


class _DeadlineReader(io.RawIOBase):
    def __init__(self, raw, sock, deadline: float) -> None:
        self._raw = raw
        self._sock = sock
        self._deadline = deadline

    def readable(self) -> bool:
        return True

    def readinto(self, buffer):
        self._sock.settimeout(remaining(self._deadline))
        result = self._raw.readinto(buffer)
        remaining(self._deadline)
        return result

    def close(self) -> None:
        try:
            self._raw.close()
        finally:
            super().close()


class DeadlineSocket:
    """Wrap reads below buffering, so every header/framing receive is timed.

    The underlying socket's makefile owns its normal I/O reference, preserving
    http.client/urllib's deferred-close semantics while a response is alive.
    """

    def __init__(self, sock, deadline: float) -> None:
        self.socket = sock
        self.deadline = deadline

    def __getattr__(self, name):
        return getattr(self.socket, name)

    def makefile(self, mode="rb", buffering=None):
        if mode != "rb" or buffering not in (None, -1):
            raise OSError("unsupported HTTP socket file mode")
        remaining(self.deadline)
        raw = self.socket.makefile("rb", buffering=0)
        return io.BufferedReader(_DeadlineReader(raw, self.socket, self.deadline))

    def sendall(self, data):
        self.socket.settimeout(remaining(self.deadline))
        self.socket.sendall(data)
        remaining(self.deadline)


def connect(address, deadline: float, source_address=None) -> DeadlineSocket:
    if source_address is not None:
        raise OSError("HTTP source-address overrides are not supported")
    host, port = address
    records = resolve(host, port, deadline)
    last_error: OSError = OSError("DNS lookup returned no usable addresses")
    for family, kind, protocol, canonname, sockaddr in records:
        remaining(deadline)
        sock = socket.socket(family, kind, protocol)
        try:
            sock.settimeout(remaining(deadline))
            sock.connect(tuple(sockaddr))
            remaining(deadline)
            return DeadlineSocket(sock, deadline)
        except OSError as exc:
            last_error = exc
            sock.close()
        except BaseException:
            sock.close()
            raise
    remaining(deadline)
    raise last_error

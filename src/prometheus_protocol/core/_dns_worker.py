"""One disposable DNS lookup. Run as an isolated script, not a package import.

The parent supplies only host/port on stdin, with an empty environment and no
inherited descriptors. Never put credentials or a full URL in this protocol.
"""

import json
import socket
import sys


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(4097)
        if len(raw) > 4096:
            return 1
        host, port = json.loads(raw)
        if not isinstance(host, str) or not isinstance(port, int) or isinstance(port, bool):
            return 1
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        if not records or len(records) > 256:
            return 1
        result = json.dumps(records).encode("ascii")
        if len(result) > 65536:
            return 1
        sys.stdout.buffer.write(result)
        return 0
    except (OSError, ValueError, TypeError):
        # No resolver diagnostics (or tracebacks) cross the protocol.
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Exercise the fault injector's wire behavior without claiming DB coverage."""

import socket
import struct
import threading

import pytest
from _pg_fault_proxy import DropCommitResponse, frame, read_exact

from prometheus_protocol.chokepoint import DbTarget


@pytest.mark.parametrize("acknowledged", [True, False])
def test_only_second_commit_response_is_dropped(acknowledged):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(5)
    received, errors = [], []

    def server():
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(5)
                assert read_exact(connection, 8) == struct.pack("!II", 8, 196608)
                for i in range(2):
                    tag, body, _ = frame(connection)
                    received.append((tag, body))
                    if i == 0 or acknowledged:
                        connection.sendall(b"C" + struct.pack("!I", 11) + b"COMMIT\x00")
                    connection.sendall(b"Z" + struct.pack("!I", 5) + b"I")
        except (AssertionError, OSError, EOFError) as exc:
            errors.append(str(exc))

    thread = threading.Thread(target=server)
    thread.start()
    target = DbTarget("127.0.0.1", listener.getsockname()[1], "unused", "unused", "")
    try:
        with DropCommitResponse(target) as proxy, socket.create_connection(
            ("127.0.0.1", proxy.port), timeout=5
        ) as client:
            # TLS and GSS negotiation must not reach the plaintext fixture.
            for code in (80877103, 80877104):
                client.sendall(struct.pack("!II", 8, code))
                assert read_exact(client, 1) == b"N"
            client.sendall(struct.pack("!II", 8, 196608))
            commit = b"Q" + struct.pack("!I", 11) + b"COMMIT\x00"
            client.sendall(commit)
            assert frame(client)[:2] == (b"C", b"COMMIT\x00")
            assert frame(client)[:2] == (b"Z", b"I")
            client.sendall(commit)
            assert client.recv(1) == b""
            assert proxy.dropped.is_set() is acknowledged
            assert bool(proxy.errors) is not acknowledged
    finally:
        listener.close()
        thread.join(5)
    assert not thread.is_alive() and not errors
    assert received == [(b"Q", b"COMMIT\x00")] * 2

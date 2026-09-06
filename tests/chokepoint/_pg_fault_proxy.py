"""Test-only plaintext PostgreSQL proxy that loses one real COMMIT response.

Only loopback clients connect. TLS/GSS negotiation is refused for this synthetic
test endpoint so PostgreSQL wire messages can be inspected. No production use.
"""

import socket
import struct
import threading


def read_exact(sock, size):
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise EOFError
        chunks.extend(chunk)
    return bytes(chunks)


def frame(sock):
    tag = read_exact(sock, 1)
    size = read_exact(sock, 4)
    length = struct.unpack("!I", size)[0]
    if not 4 <= length <= 16_000_000:
        raise ValueError("invalid PostgreSQL test frame length")
    body = read_exact(sock, length - 4)
    return tag, body, tag + size + body


class DropCommitResponse:
    def __init__(self, target):
        self.target = target
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        self.dropped = threading.Event()
        self.errors = []
        self.connections = []
        self.threads = []
        self.armed = True
        self.lock = threading.Lock()

    def __enter__(self):
        self.acceptor = threading.Thread(target=self.accept, daemon=True)
        self.acceptor.start()
        return self

    def accept(self):
        while not self.stop.is_set():
            try:
                client, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self.connections.append(client)
            thread = threading.Thread(target=self.relay, args=(client,), daemon=True)
            self.threads.append(thread)
            thread.start()

    def relay(self, client):
        upstream = None
        drop = threading.Event()
        try:
            client.settimeout(10)
            upstream = socket.create_connection(
                (self.target.host, self.target.port), timeout=10
            )
            self.connections.append(upstream)
            # Negotiation/startup packets do not have a one-byte message tag.
            while True:
                size = read_exact(client, 4)
                length = struct.unpack("!I", size)[0]
                if not 8 <= length <= 100_000:
                    raise ValueError("invalid startup packet")
                body = read_exact(client, length - 4)
                if length == 8 and struct.unpack("!I", body)[0] in (80877103, 80877104):
                    client.sendall(b"N")
                    continue
                upstream.sendall(size + body)
                break

            def responses():
                acknowledged_commit = False
                try:
                    while True:
                        tag, body, packet = frame(upstream)
                        if drop.is_set():
                            acknowledged_commit |= tag == b"C" and body == b"COMMIT\x00"
                            if tag == b"Z":
                                if not acknowledged_commit:
                                    self.errors.append(
                                        "server did not acknowledge COMMIT"
                                    )
                                else:
                                    self.dropped.set()
                                client.shutdown(socket.SHUT_RDWR)
                                return
                            continue
                        client.sendall(packet)
                except (EOFError, OSError):
                    return
                except (ValueError, struct.error) as exc:
                    self.errors.append(type(exc).__name__)

            response_thread = threading.Thread(target=responses, daemon=True)
            self.threads.append(response_thread)
            response_thread.start()
            commits = 0
            while True:
                tag, body, packet = frame(client)
                if tag == b"Q" and body.rstrip(b"\x00").strip().upper() == b"COMMIT":
                    commits += 1
                    # First COMMIT bootstraps the receipt table. Lose the second,
                    # which atomically commits the artifact and its receipt.
                    if commits == 2:
                        with self.lock:
                            if self.armed:
                                self.armed = False
                                drop.set()
                upstream.sendall(packet)
        except (EOFError, OSError):
            pass
        except (ValueError, struct.error) as exc:
            self.errors.append(type(exc).__name__)
        finally:
            client.close()
            if upstream is not None:
                upstream.close()

    def __exit__(self, *args):
        self.stop.set()
        self.listener.close()
        for sock in self.connections:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        self.acceptor.join(2)
        for thread in self.threads:
            thread.join(2)

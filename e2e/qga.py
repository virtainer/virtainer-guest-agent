# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Virtainer authors
"""Host-side QGA client over Cloud Hypervisor hybrid vsock.

Speaks to a guest agent the way the Virtainer host does: a fresh connection per
call, `CONNECT <port>` to the hybrid-vsock socket, a 0xFF-prefixed
`guest-sync-delimited`, then one request and one reply line.
"""

import json
import random
import socket
import time


# `reset-failed` clears a start-limit trip left by a crash loop.
RESTART_AGENT = (
    "if [ -d /run/systemd/system ]; then systemctl reset-failed virtainer-guest-agent 2>/dev/null;"
    " systemctl restart virtainer-guest-agent; else rc-service virtainer-guest-agent restart; fi"
)


class QgaError(Exception):
    def __init__(self, error):
        super().__init__(f"{error.get('class')}: {error.get('desc')}")
        self.error_class = error.get("class")
        self.desc = error.get("desc")


class Qga:
    def __init__(self, vsock_path, port=100, timeout=10.0):
        self.vsock_path = vsock_path
        self.port = port
        self.timeout = timeout

    def _connect(self, timeout):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(self.vsock_path)
        stream = sock.makefile("rwb", buffering=0)
        sock.sendall(f"CONNECT {self.port}\n".encode())
        ack = stream.readline()
        if not ack.startswith(b"OK "):
            sock.close()
            raise ConnectionRefusedError(f"guest not listening on port {self.port}: {ack!r}")
        sync_id = random.randint(1, 2**62)
        sock.sendall(
            b"\xff"
            + json.dumps({"execute": "guest-sync-delimited", "arguments": {"id": sync_id}}).encode()
            + b"\n"
        )
        while True:
            byte = stream.read(1)
            if not byte:
                raise ConnectionResetError("agent closed the connection during sync")
            if byte == b"\xff":
                break
        reply = json.loads(stream.readline())
        if reply.get("return") != sync_id:
            raise RuntimeError(f"sync id mismatch: {reply}")
        return sock, stream

    def open_stream(self, timeout=None):
        """A synced connection for tests that speak the wire protocol themselves."""
        return self._connect(timeout or self.timeout)

    def raw(self, request, timeout=None, expect_reply=True):
        """Send one request object; return the decoded reply dict (or None)."""
        sock, stream = self._connect(timeout or self.timeout)
        try:
            sock.sendall(json.dumps(request).encode() + b"\n")
            if not expect_reply:
                try:
                    return stream.readline() or None
                except (socket.timeout, OSError):
                    return None
            line = stream.readline()
            if not line:
                raise ConnectionResetError("agent closed the connection without replying")
            return json.loads(line)
        finally:
            sock.close()

    def call(self, command, arguments=None, timeout=None):
        request = {"execute": command}
        if arguments is not None:
            request["arguments"] = arguments
        reply = self.raw(request, timeout=timeout)
        if "error" in reply:
            raise QgaError(reply["error"])
        return reply["return"]

    def restart_agent(self, ready_s=60):
        """Restart the agent through the guest's service manager, then wait for it.

        The restart runs as a guest-exec child that outlives the agent (the
        service does not kill its children). An open connection tells when
        the old agent is gone, so the wait cannot be satisfied by it.
        """
        sock, _ = self._connect(self.timeout)
        try:
            self.call("guest-exec", {"path": "/bin/sh", "arg": ["-c", RESTART_AGENT]})
            sock.settimeout(30)
            try:
                while sock.recv(4096):
                    pass
            except socket.timeout:
                raise TimeoutError("the agent did not go down after the restart command") from None
            except OSError:
                pass
        finally:
            sock.close()
        return self.wait_ready(ready_s, 1)

    def wait_ready(self, deadline_s, poll_s=2.0):
        start = time.monotonic()
        last = None
        while time.monotonic() - start < deadline_s:
            try:
                self.call("guest-ping", timeout=3)
                return time.monotonic() - start
            except Exception as e:  # noqa: BLE001 - any failure means "not yet"
                last = e
                time.sleep(poll_s)
        raise TimeoutError(f"agent not ready after {deadline_s}s: {last}")

    def exec(self, argv, input_data=None, timeout=60):
        """guest-exec and wait; returns (exitcode, stdout, stderr)."""
        import base64

        args = {"path": argv[0], "arg": argv[1:], "capture-output": True}
        if input_data is not None:
            args["input-data"] = base64.b64encode(input_data).decode()
        pid = self.call("guest-exec", args)["pid"]
        start = time.monotonic()
        while True:
            status = self.call("guest-exec-status", {"pid": pid})
            if status["exited"]:
                out = base64.b64decode(status.get("out-data", ""))
                err = base64.b64decode(status.get("err-data", ""))
                return status.get("exitcode", -status.get("signal", 0)), out, err
            if time.monotonic() - start > timeout:
                raise TimeoutError(f"{argv} did not finish in {timeout}s")
            time.sleep(0.2)

    def sh(self, script, timeout=60, check=True):
        code, out, err = self.exec(["/bin/sh", "-c", script], timeout=timeout)
        if check and code != 0:
            raise RuntimeError(f"guest command failed ({code}): {script}\n{out.decode()}{err.decode()}")
        return out.decode()


class Shell:
    """A Shell session (`__io.virtainer_shell`): frames over a QGA connection.

    Frame: type byte, little-endian u32 length, payload. Type 0 is terminal
    data; type 1 is a JSON object (resize from us, exitcode/signal from the
    agent).
    """

    def __init__(self, qga, user, rows=24, cols=80, term="xterm-256color", timeout=10.0):
        sock, stream = qga._connect(timeout)
        request = {"execute": "__io.virtainer_shell",
                   "arguments": {"user": user, "rows": rows, "cols": cols, "term": term}}
        sock.sendall(json.dumps(request).encode() + b"\n")
        reply = json.loads(stream.readline())
        if "error" in reply:
            sock.close()
            raise QgaError(reply["error"])
        self.pid = reply["return"]["pid"]
        self.sock = sock
        self.output = b""
        self.exit = None
        self.closed = False
        self._pending = b""

    def _frame(self, kind, payload):
        self.sock.sendall(bytes([kind]) + len(payload).to_bytes(4, "little") + payload)

    def send(self, data):
        self._frame(0, data)

    def resize(self, rows, cols):
        self._frame(1, json.dumps({"resize": [rows, cols]}).encode())

    def text(self):
        return self.output.decode(errors="replace")

    def read_until(self, predicate, timeout=20):
        """Collect frames until predicate(self) holds or the session ends."""
        deadline = time.monotonic() + timeout
        while not predicate(self) and not self.closed:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            self.sock.settimeout(remaining)
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                break
            except OSError:
                chunk = b""
            if not chunk:
                self.closed = True
                break
            self._pending += chunk
            while len(self._pending) >= 5:
                size = int.from_bytes(self._pending[1:5], "little")
                if len(self._pending) < 5 + size:
                    break
                kind, payload = self._pending[0], self._pending[5:5 + size]
                self._pending = self._pending[5 + size:]
                if kind == 0:
                    self.output += payload
                elif kind == 1:
                    self.exit = json.loads(payload)
        return predicate(self)

    def wait_exit(self, timeout=20):
        self.read_until(lambda s: s.exit is not None, timeout)
        return self.exit

    def close(self):
        self.sock.close()

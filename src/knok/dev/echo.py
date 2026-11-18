"""Minimal echo bridge for the slice-0 conformance harness (spec §6, Form 1).

Listens on 127.0.0.1 only and echoes the ``Message`` inside a received
envelope back to the sender, unchanged, inside a fresh Form 1 envelope
(``from``/``to`` swapped, ``seq`` incremented). It exists so the conformance
harness has something to talk to before any real bridge exists.

Deliberately out of scope for slice 0 — see ``tests/conformance/README.md``:

* No envelope signature is produced or verified. Signing is slice 1
  (identity); the echo bridge has no keys at all.
* No queue, ack, dedupe or resend. Delivery guarantees are slice 2.
* No policy or handshake. That is slice 3.

Run it with::

    python -m knok.dev.echo --port 0

``--port 0`` picks an ephemeral port and prints it as
``knok-echo listening on 127.0.0.1:<port>``; the harness reads that line.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from knok.message import MessageValidationError, validate_message

__all__ = ["build_echo_envelope", "main", "validate_envelope"]

#: Binding address, hardcoded: the echo bridge never listens anywhere else.
_HOST = "127.0.0.1"
#: Default TTL for the echoed envelope, per spec §6 (72 hours).
_TTL = timedelta(hours=72)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _require(cond: bool, what: str) -> None:
    if not cond:
        raise ValueError(what)


def validate_envelope(obj: object) -> dict:
    """Validate a Form 1 envelope (minus signature — slice 1) and return it.

    The envelope's transport fields are checked for presence and type; the
    embedded ``Message`` is checked strictly by :func:`knok.message.validate_message`,
    so an invented field inside the ``Message`` is a 400, not a shrug.
    Extra top-level envelope fields are tolerated: they are transport, not
    the ``Message``, and later slices may add them.
    """
    if not isinstance(obj, dict):
        raise ValueError("envelope must be a JSON object")
    if obj.get("envelopeVersion") != 1:
        raise ValueError(f"envelopeVersion must be 1, got {obj.get('envelopeVersion')!r}")
    if not isinstance(obj.get("seq"), int) or isinstance(obj.get("seq"), bool) or obj["seq"] < 0:
        raise ValueError("seq must be a non-negative integer")
    if not isinstance(obj.get("from"), str) or not obj["from"]:
        raise ValueError("from must be a non-empty string")
    to = obj.get("to")
    if not isinstance(to, list) or not to or not all(isinstance(r, str) and r for r in to):
        raise ValueError("to must be a non-empty list of non-empty strings")
    for field in ("sentAt", "expiresAt"):
        if not isinstance(obj.get(field), str) or not obj[field]:
            raise ValueError(f"{field} must be a non-empty string")
    turn = obj.get("turn")
    if not isinstance(turn, dict):
        raise ValueError("turn must be an object")
    for field in ("expectsReply", "closesThread"):
        if not isinstance(turn.get(field), bool):
            raise ValueError(f"turn.{field} must be a boolean")
    if "message" not in obj:
        raise ValueError("envelope has no message field (Form 1 carries message, not sealed)")
    try:
        validate_message(obj["message"])
    except MessageValidationError as exc:
        raise ValueError(f"invalid message: {exc}") from exc
    return obj


def build_echo_envelope(envelope: dict) -> dict:
    """Build the reply envelope: same ``Message`` verbatim, roles swapped."""
    now = datetime.now(timezone.utc)
    return {
        "envelopeVersion": 1,
        "seq": envelope["seq"] + 1,
        "message": envelope["message"],
        "from": envelope["to"][0],
        "to": [envelope["from"]],
        "sentAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expiresAt": (now + _TTL).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "turn": dict(envelope["turn"]),
        # No "signature": the echo bridge holds no keys. Slice 1 adds it.
    }


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:  # keep test output clean
        pass

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        if self.path == "/health":
            self._send_json(200, {"status": "ok"})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - http.server naming
        if self.path != "/":
            self._send_json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            envelope = validate_envelope(json.loads(raw))
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json(400, {"error": str(exc)})
            return
        self._send_json(200, build_echo_envelope(envelope))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Knok echo bridge (slice-0 dev tool)")
    parser.add_argument("--port", type=int, default=0, help="port to listen on (0 = ephemeral)")
    args = parser.parse_args(argv)
    server = ThreadingHTTPServer((_HOST, args.port), _Handler)
    port = server.server_address[1]
    print(f"knok-echo listening on {_HOST}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

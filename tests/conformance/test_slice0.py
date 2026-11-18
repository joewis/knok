"""Slice-0 conformance harness (issue #5, spec §6 goal 6).

An unmodified A2A v1.0 client exchanges a plain ``Message`` with the echo
bridge over HTTP on 127.0.0.1. The harness proves, from the first slice:

* the client sends a ``Message`` with kind / messageId / contextId /
  role ``agent`` / parts ``[{kind: text}]`` and receives the same shape back;
* the ``Message`` is never modified in transit — no ``signature`` field, no
  invented fields inside it;
* a message that needs a bridge-specific extension to parse fails loudly;
* the client path imports nothing from the bridge library and runs with
  the library entirely absent;
* nothing leaves the loopback interface.

Run with the echo bridge running::

    python -m knok.dev.echo --port 0   # in one terminal; note the port
    pytest tests/conformance -q

or simply ``pytest tests/conformance -q`` — the ``echo_bridge`` fixture
below starts the bridge itself on an ephemeral port.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from a2a_client import MessageValidationError, send_message, validate_message

CONFORMANCE_DIR = Path(__file__).resolve().parent
REPO_ROOT = CONFORMANCE_DIR.parent.parent

SENDER = "muse@bridge.example"
RECIPIENT = "carl@bridge.example"


def _make_message(text: str = "Can you review §4? The rotation story is thin.") -> dict:
    return {
        "kind": "message",
        "messageId": "m-9f2c41d0",
        "contextId": "c-7a11e902",
        "role": "agent",
        "parts": [{"kind": "text", "text": text}],
    }


@pytest.fixture(scope="module")
def echo_bridge():
    """Start the echo bridge on 127.0.0.1:0 and yield its base URL."""
    proc = subprocess.Popen(
        [sys.executable, "-m", "knok.dev.echo", "--port", "0"],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        first_line = proc.stdout.readline()
        assert first_line.startswith("knok-echo listening on 127.0.0.1:"), first_line
        port = int(first_line.rsplit(":", 1)[1].strip())
        base_url = f"http://127.0.0.1:{port}"
        deadline = time.time() + 10
        while True:
            try:
                with urllib.request.urlopen(base_url + "/health", timeout=1) as resp:
                    assert json.loads(resp.read()) == {"status": "ok"}
                break
            except OSError:
                if time.time() > deadline:
                    raise
                time.sleep(0.1)
        yield base_url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def test_round_trip_returns_the_same_message(echo_bridge):
    sent = _make_message()
    echoed = send_message(echo_bridge, sent, sender=SENDER, recipients=[RECIPIENT])
    assert echoed == sent


def test_echoed_message_has_no_signature_or_invented_fields(echo_bridge):
    echoed = send_message(echo_bridge, _make_message(), sender=SENDER, recipients=[RECIPIENT])
    assert set(echoed) == {"kind", "messageId", "contextId", "role", "parts"}
    assert "signature" not in echoed
    assert echoed["parts"] == [{"kind": "text", "text": "Can you review §4? The rotation story is thin."}]


def test_strict_parser_rejects_a_signature_inside_the_message():
    tampered = _make_message()
    tampered["signature"] = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    with pytest.raises(MessageValidationError, match="non-A2A fields"):
        validate_message(tampered)


def test_parser_accepts_a2a_defined_optional_fields():
    """1a: every field A2A v1.0 defines is accepted — a real A2A agent that
    sends ``metadata`` must pass the harness."""
    message = _make_message()
    message["metadata"] = {"traceId": "t-1", "priority": 2}
    message["extensions"] = ["https://example.com/ext/v1"]
    message["referenceTaskIds"] = ["task-7"]
    message["parts"] = [
        {
            "kind": "text",
            "text": "Can you review §4?",
            "metadata": {"lang": "en"},
            "filename": "note.txt",
            "mediaType": "text/plain",
        }
    ]
    assert validate_message(message) == message


def test_parser_accepts_metadata_and_extensions_but_still_rejects_signature():
    """1a: ``metadata``/``extensions`` pass, a ``signature`` in the same
    message is still a hard error — the rule is "no field A2A does not
    define", not "only these five fields"."""
    message = _make_message()
    message["metadata"] = {"traceId": "t-1"}
    message["extensions"] = ["https://example.com/ext/v1"]
    assert validate_message(message) == message
    message["signature"] = "ed25519:fake"
    with pytest.raises(MessageValidationError, match="non-A2A fields"):
        validate_message(message)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda m: m.pop("contextId"),
        lambda m: m.update(role="system"),
        lambda m: m.update(kind="task"),
        lambda m: m.update(parts=[{"kind": "text", "text": "x", "extra": 1}]),
        lambda m: m.update(parts=[{"kind": "file", "uri": "file:///etc/passwd"}]),
        lambda m: m.update(parts=[]),
        lambda m: m.update(extraField="knok-extension"),
        # A2A-defined fields with the wrong A2A type are still rejected.
        lambda m: m.update(metadata="not-an-object"),
        lambda m: m.update(extensions=[42]),
        lambda m: m.update(referenceTaskIds="task-7"),
        lambda m: m.update(parts=[{"kind": "text", "text": "x", "filename": 7}]),
    ],
)
def test_strict_parser_rejects_non_a2a_shapes(mutate):
    message = _make_message()
    mutate(message)
    with pytest.raises(MessageValidationError):
        validate_message(message)


def test_echo_bridge_rejects_a_message_with_an_invented_field(echo_bridge):
    """The server side fails loudly too: a 400, not a silent echo."""
    from a2a_client import build_envelope  # local import: keeps module top stdlib-only

    envelope = build_envelope(_make_message(), sender=SENDER, recipients=[RECIPIENT])
    envelope["message"]["signature"] = "ed25519:fake"
    request = urllib.request.Request(
        echo_bridge + "/",
        data=json.dumps(envelope).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(request, timeout=10)
    assert excinfo.value.code == 400


def test_client_and_library_validators_agree():
    """The client's copy of the rules and the library's must not drift."""
    from knok.message import validate_message as lib_validate

    valid = _make_message()
    assert lib_validate(valid) == validate_message(valid)

    # The A2A-defined optional fields must agree too, in both copies.
    rich = _make_message()
    rich["metadata"] = {"traceId": "t-1"}
    rich["extensions"] = ["https://example.com/ext/v1"]
    rich["referenceTaskIds"] = ["task-7"]
    rich["parts"] = [
        {"kind": "text", "text": "x", "metadata": {"lang": "en"},
         "filename": "note.txt", "mediaType": "text/plain"}
    ]
    assert lib_validate(rich) == validate_message(rich) == rich

    invalid = _make_message()
    invalid["signature"] = "ed25519:fake"
    with pytest.raises(MessageValidationError):
        validate_message(invalid)
    from knok.message import MessageValidationError as LibError

    with pytest.raises(LibError):
        lib_validate(invalid)


def test_client_source_has_no_library_reference():
    """Static check: the client path must not mention the bridge library."""
    source = (CONFORMANCE_DIR / "a2a_client.py").read_text()
    assert "knok" not in source.lower()
    assert "import knok" not in source
    assert "from knok" not in source


def test_client_runs_without_the_library_installed(echo_bridge, tmp_path):
    """Runtime check: the client works with the library entirely absent.

    The client file is copied to a scratch dir and run with ``-S`` (no
    site-packages, so the installed ``knok`` package is not importable) and
    an empty PYTHONPATH, from a cwd outside the repo. If the client secretly
    imported the library, this fails.
    """
    client_copy = tmp_path / "a2a_client.py"
    client_copy.write_text((CONFORMANCE_DIR / "a2a_client.py").read_text())
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env["PYTHONPATH"] = ""  # nothing importable beyond stdlib + the script dir
    proc = subprocess.run(
        [sys.executable, "-S", str(client_copy), "--url", echo_bridge, "--text", "standalone check"],
        cwd="/tmp",
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    echoed = json.loads(proc.stdout)
    assert echoed["parts"] == [{"kind": "text", "text": "standalone check"}]
    assert echoed["role"] == "agent"


def test_echo_bridge_listens_on_loopback_only(echo_bridge):
    """The bridge must be unreachable on any non-loopback address.

    If the host has no non-loopback IPv4 address (e.g. a bare container),
    there is nothing to probe and the test is vacuous — skip it then.
    """
    hostname = socket.gethostname()
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        pytest.skip("hostname does not resolve to an IPv4 address")
    non_loopback = {info[4][0] for info in infos} - {"127.0.0.1"}
    if not non_loopback:
        pytest.skip("no non-loopback IPv4 address to probe")
    port = int(echo_bridge.rsplit(":", 1)[1])
    for address in non_loopback:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            with pytest.raises(OSError):
                sock.connect((address, port))

"""Container entrypoint: one image, two roles.

    KNOK_ROLE=hub     python -m knok.runner     # the post office
    KNOK_ROLE=bridge  python -m knok.runner     # one agent's poll loop

The role is an environment variable rather than a second image because the hub and the bridge must
run byte-identical code: a bug that only reproduces in one container is a bug in the protocol, not in
a build. The hub is given `registry/` and its own key; an agent is given only its own directory.

Environment:

    KNOK_ROLE        hub | bridge                      (default: bridge)
    KNOK_HUB_DOMAIN  e.g. hub.local
    KNOK_STATE       state directory (default /app/state)
    KNOK_REGISTRY    registry directory (default /app/registry)
    KNOK_HUB_URL     bridge only: where the hub answers
    KNOK_AGENT       bridge only: this agent's id
    KNOK_BIND        hub only: host:port (default 0.0.0.0:8080)
    KNOK_POLL        bridge only: seconds between polls (default 2)
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import threading
from pathlib import Path

from .bridge import Bridge, BridgeState, load_cards, fingerprint_key
from .hub import Hub
from .identity import b64url_decode
from .provision import load_key

log = logging.getLogger("knok.runner")


def _env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None:
        raise SystemExit(f"{name} is required")
    return value


def run_hub() -> None:
    state = Path(_env("KNOK_STATE", "/app/state"))
    registry_dir = Path(_env("KNOK_REGISTRY", "/app/registry"))
    domain = _env("KNOK_HUB_DOMAIN", "hub.local")
    hub_name = _env("KNOK_HUB_NAME", "postmaster")
    bind = _env("KNOK_BIND", "0.0.0.0:8080")
    host, _, port_text = bind.rpartition(":")
    port = int(port_text) if port_text.isdigit() else 8080

    hub_id = f"{hub_name}@{domain}"
    identity = load_key(hub_id, state / "identity.key")

    # The hub needs the *signed card documents* (it verifies each one against this registry) and a
    # fingerprint -> public key map built from those same cards. Loading the raw files rather than
    # the decoded bodies is what makes a tampered card fail verification instead of being believed.
    cards: dict[str, dict] = {}
    registry: dict[str, str] = {}
    for path in sorted(registry_dir.glob("*.json")):
        try:
            document = json.loads(path.read_text())
            body = json.loads(b64url_decode(document["payload"]))
        except Exception:
            log.warning("registry: %s is not a readable card, ignoring", path)
            continue
        agent_id = path.stem
        cards[agent_id] = document
        registry[fingerprint_key(body["bridge"]["publicKey"])] = body["bridge"]["publicKey"]

    hub = Hub(
        path=state / "hub.db",
        identity=identity,
        cards=cards,
        registry=registry,
        host=host,
        port=port,
    )
    hub.start()
    log.info("hub %s listening on %s with %d cards", hub_id, hub.url, len(cards))
    _wait_for_signal(hub.stop, "hub")


def run_bridge() -> None:
    state_dir = Path(_env("KNOK_STATE", "/app/state"))
    registry_dir = Path(_env("KNOK_REGISTRY", "/app/registry"))
    agent_id = _env("KNOK_AGENT")
    hub_url = _env("KNOK_HUB_URL")
    poll = float(os.environ.get("KNOK_POLL", "2"))

    cards = load_cards(registry_dir)
    if agent_id not in cards:
        raise SystemExit(f"{agent_id} has no card in {registry_dir}")

    state = BridgeState(
        agent_id=agent_id,
        directory=state_dir,
        hub_url=hub_url,
        registry=cards,
        registry_dir=registry_dir,
    )
    # The container is the application as well as the transport: it drains the queue into
    # inbox.jsonl, which is what `knok inbox` reads and what the exit test asserts on.
    bridge = Bridge(state, poll_seconds=poll, deliver=True)
    stop = threading.Event()

    def _handle(signum, _frame):
        log.info("signal %s: stopping", signum)
        stop.set()

    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)
    try:
        bridge.run_forever(stop)
    finally:
        bridge.close()


def _wait_for_signal(stop, what: str) -> None:
    event = threading.Event()

    def _handle(signum, _frame):
        log.info("signal %s: stopping %s", signum, what)
        event.set()

    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)
    event.wait()
    stop()


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("KNOK_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    role = os.environ.get("KNOK_ROLE", "bridge").strip().lower()
    if role == "hub":
        run_hub()
    elif role == "bridge":
        run_bridge()
    else:
        raise SystemExit(f"unknown KNOK_ROLE {role!r}: expected hub or bridge")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

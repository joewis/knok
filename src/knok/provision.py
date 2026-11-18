"""Provision a Phase 2 deployment: keys, policies, and the operator's registry.

Phase 2 has no dynamic registration (HUB.md): the registry directory *is* the trust anchor, and
adding an agent is a file plus a restart. This module writes that directory.

Layout under ``root``::

    hub/identity.key                 the hub's own key (never an agent's)
    agents/<name>/identity.key       0600, private to that agent
    agents/<name>/policy.json        that agent's gate policy
    registry/<agent-id>.json         signed cards, read-only to every container

The private keys never leave the agent's directory: a hub container is given ``registry/`` and
``hub/``, never ``agents/``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import identity as identity_mod
from .identity import Identity, fingerprint
from .transport import make_agent_card

DEFAULT_POLICY: dict[str, Any] = {
    "contact_policy": "closed",
    "deployment": "private",
    "allow": [],
    "block": [],
    "limits": {"messages_per_hour": 120, "per_sender_per_hour": 60},
}


def load_key(agent_id: str, path: Path) -> Identity:
    """Load a key from disk without a registry: used only by the operator and the hub itself.

    The PEM is bound to the id by its own public key here; the registry binding is enforced later,
    when a *peer* verifies something this key signed.
    """
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError(f"{path} does not contain an Ed25519 private key")
    loaded = Identity(agent_id, key)
    return identity_mod.load(agent_id, path, loaded.fingerprint)


def provision(
    root: Path,
    *,
    hub_domain: str,
    agents: Iterable[str],
    hub_name: str = "postmaster",
    force: bool = False,
    preapprove: bool = True,
) -> dict[str, Any]:
    """Create whatever is missing. Returns a manifest describing what exists now."""
    root = Path(root)
    (root / "registry").mkdir(parents=True, exist_ok=True)
    (root / "hub").mkdir(parents=True, exist_ok=True)

    hub_id = f"{hub_name}@{hub_domain}"
    hub_key = root / "hub" / "identity.key"
    if force and hub_key.exists():
        hub_key.unlink()
    if not hub_key.exists():
        identity_mod.generate(hub_name, hub_domain).save(hub_key)
    hub_identity = load_key(hub_id, hub_key)
    _write_card(root / "registry" / f"{hub_id}.json", hub_identity, hub_domain, f"http://{hub_id}")

    agents = list(agents)  # the allow-list needs every name before any policy is written
    manifest: dict[str, Any] = {"hub": hub_id, "agents": {}}
    for name in agents:
        agent_id = f"{name}@{hub_domain}"
        directory = root / "agents" / name
        directory.mkdir(parents=True, exist_ok=True)
        key_path = directory / "identity.key"
        if force and key_path.exists():
            key_path.unlink()
        if not key_path.exists():
            identity_mod.generate(name, hub_domain).save(key_path)
        agent_identity = load_key(agent_id, key_path)

        # The policy is rewritten, not created-and-forgotten: an allow-list written only once is a
        # snapshot, so adding a fourth agent would leave the first three refusing its mail with no
        # error anywhere. Operator edits to other fields survive; the allow-list is recomputed.
        policy_path = directory / "policy.json"
        policy = dict(DEFAULT_POLICY)
        if policy_path.exists():
            try:
                existing = json.loads(policy_path.read_text())
                if isinstance(existing, dict):
                    policy.update({k: v for k, v in existing.items() if k != "allow"})
            except ValueError:
                pass
        policy["agent_id"] = agent_id
        if preapprove:
            # Private deployment: the registry is the operator's statement that these agents may
            # talk, so the allow-list is a pre-approval and §7's handshake is not exercised. On a
            # public hub the registry is open and the handshake is the only consent that exists,
            # which is why this is a flag rather than a default baked into the gate.
            policy["allow"] = sorted(
                [f"{other}@{hub_domain}" for other in agents if other != name] + [hub_id]
            )
        policy_path.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n")
        os.chmod(policy_path, 0o600)

        _write_card(
            root / "registry" / f"{agent_id}.json",
            agent_identity,
            hub_domain,
            f"http://{agent_id}",
        )
        manifest["agents"][agent_id] = {
            "name": name,
            "fingerprint": fingerprint(agent_identity.public_key),
            "key": str(key_path),
        }
    return manifest


def _write_card(path: Path, identity: Identity, hub_domain: str, url: str) -> None:
    card = make_agent_card(identity, hub_domain, url)
    path.write_text(json.dumps(card, indent=2, sort_keys=True) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="knok-provision")
    parser.add_argument("--root", default="/app", help="deployment root (default /app)")
    parser.add_argument("--hub-domain", default=os.environ.get("KNOK_HUB_DOMAIN", "hub.local"))
    parser.add_argument("--hub-name", default="postmaster")
    parser.add_argument("--agents", nargs="+", default=["carl", "muse", "bobby"])
    parser.add_argument("--force", action="store_true", help="replace existing keys (destroys identity)")
    parser.add_argument(
        "--no-preapprove",
        dest="preapprove",
        action="store_false",
        help="leave the allow-list empty: every peer must complete the §7 handshake first",
    )
    args = parser.parse_args(argv)

    manifest = provision(
        Path(args.root),
        hub_domain=args.hub_domain,
        agents=args.agents,
        hub_name=args.hub_name,
        force=args.force,
        preapprove=args.preapprove,
    )
    json.dump(manifest, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

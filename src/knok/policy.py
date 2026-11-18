"""The policy file: who may reach this agent, and under what limits (SPEC §3, §9).

Contract: ``load`` is strict. An unknown key is fatal, because a typo that silently disables a rule
looks exactly like a rule that works — the agent keeps running and stops refusing anyone. A crash at
startup is the cheaper failure.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .identity import IdentityError, validate_agent_id

KNOWN_KEYS = {"agent_id", "contact_policy", "allow", "block", "limits"}
KNOWN_LIMITS = {"contact_requests_per_day", "messages_per_hour"}
#: "open" is deliberately absent: §9 says a public hub refuses it, and a private agent that wants
#: direct delivery says so in its allow list instead of disabling the handshake for everyone.
CONTACT_POLICIES = {"request", "closed"}


class PolicyError(ValueError):
    """Raised when a policy file cannot be trusted."""


@dataclass(frozen=True)
class Policy:
    agent_id: str
    contact_policy: str
    allow: frozenset[str]
    block: frozenset[str]
    limits: dict[str, int]

    def may_send(self, peer: str) -> bool:
        return peer in self.allow and peer not in self.block


def _identifiers(value: Any, field: str) -> frozenset[str]:
    if not isinstance(value, list):
        raise PolicyError(f"{field} must be a list of agent ids")
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            raise PolicyError(f"{field} must contain strings")
        try:
            validate_agent_id(item)
        except IdentityError as exc:
            raise PolicyError(f"{field}: {exc}") from exc
        seen.add(item)
    return frozenset(seen)


def parse(document: Any) -> Policy:
    if not isinstance(document, dict):
        raise PolicyError("policy must be a JSON object")
    unknown = set(document) - KNOWN_KEYS
    if unknown:
        raise PolicyError("unknown policy keys: " + ", ".join(sorted(unknown)))
    missing = {"agent_id", "contact_policy"} - set(document)
    if missing:
        raise PolicyError("missing policy keys: " + ", ".join(sorted(missing)))

    agent_id = document["agent_id"]
    if not isinstance(agent_id, str):
        raise PolicyError("agent_id must be a string")
    try:
        validate_agent_id(agent_id)
    except IdentityError as exc:
        raise PolicyError(str(exc)) from exc

    contact_policy = document["contact_policy"]
    if contact_policy not in CONTACT_POLICIES:
        raise PolicyError(f"contact_policy must be one of {sorted(CONTACT_POLICIES)}, got {contact_policy!r}")

    limits_raw = document.get("limits", {})
    if not isinstance(limits_raw, dict):
        raise PolicyError("limits must be an object")
    unknown_limits = set(limits_raw) - KNOWN_LIMITS
    if unknown_limits:
        raise PolicyError("unknown limit names: " + ", ".join(sorted(unknown_limits)))
    for name, value in limits_raw.items():
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise PolicyError(f"limit {name} must be a non-negative integer")

    return Policy(
        agent_id=agent_id,
        contact_policy=contact_policy,
        allow=_identifiers(document.get("allow", []), "allow"),
        block=_identifiers(document.get("block", []), "block"),
        limits=dict(limits_raw),
    )


def load(path: str | Path) -> Policy:
    try:
        document = json.loads(Path(path).read_text())
    except OSError as exc:
        raise PolicyError(f"cannot read policy: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PolicyError(f"policy is not valid JSON: {exc}") from exc
    return parse(document)

"""The policy file: who may reach this agent, and under what limits (SPEC §9).

Contract: ``load`` is strict. An unknown key or limit name is fatal, because a typo that silently
disables a rule looks exactly like a rule that works. ``direct`` delivery is only legal off a public
hub (§9), so it carries an explicit deployment marker rather than being inferred.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .identity import IdentityError, validate_agent_id

KNOWN_KEYS = {"agent_id", "contact_policy", "deployment", "allow", "block", "limits", "probation"}
#: §9 names four numbers: 100 messages/hour, 20/hour from one sender, and the probation pair
#: (20 contact requests and 50 messages a day). All four are policy, not protocol constants.
KNOWN_LIMITS = {
    "messages_per_hour",
    "per_sender_per_hour",
    "messages_per_day",
    "contact_requests_per_day",
}
CONTACT_POLICIES = {"closed", "direct"}
DEPLOYMENTS = {"public", "private", "local"}


class PolicyError(ValueError):
    """Raised when a policy file cannot be trusted."""


@dataclass(frozen=True)
class Policy:
    agent_id: str
    contact_policy: str
    deployment: str
    allow: frozenset[str]
    block: frozenset[str]
    limits: dict[str, int]
    probation: bool = False

    @property
    def direct_delivery(self) -> bool:
        return self.contact_policy == "direct"


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
        raise PolicyError(
            f"contact_policy must be one of {sorted(CONTACT_POLICIES)}, got {contact_policy!r}"
        )

    deployment = document.get("deployment", "public")
    if deployment not in DEPLOYMENTS:
        raise PolicyError(f"deployment must be one of {sorted(DEPLOYMENTS)}, got {deployment!r}")
    if contact_policy == "direct" and deployment == "public":
        # §9: there is no open mode on a public hub. Saying "direct" on a public deployment is the
        # configuration error that would turn a hub into an open relay.
        raise PolicyError("contact_policy 'direct' is not allowed on a public deployment")

    limits_raw = document.get("limits", {})
    if not isinstance(limits_raw, dict):
        raise PolicyError("limits must be an object")
    unknown_limits = set(limits_raw) - KNOWN_LIMITS
    if unknown_limits:
        raise PolicyError("unknown limit names: " + ", ".join(sorted(unknown_limits)))
    for name, value in limits_raw.items():
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise PolicyError(f"limit {name} must be a non-negative integer")

    probation = document.get("probation", False)
    if not isinstance(probation, bool):
        raise PolicyError("probation must be a boolean")

    return Policy(
        agent_id=agent_id,
        contact_policy=contact_policy,
        deployment=deployment,
        allow=_identifiers(document.get("allow", []), "allow"),
        block=_identifiers(document.get("block", []), "block"),
        limits=dict(limits_raw),
        probation=probation,
    )


def load(path: str | Path) -> Policy:
    try:
        document = json.loads(Path(path).read_text())
    except OSError as exc:
        raise PolicyError(f"cannot read policy: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PolicyError(f"policy is not valid JSON: {exc}") from exc
    return parse(document)

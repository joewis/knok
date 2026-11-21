"""The drop record is a diagnostic, not a copy of the rejected envelope (#122).

A dropped item is one the bridge could not verify or handle — including one from a sender with no
trusted card, or whose envelope failed verification. Retaining the complete item in
``dropped.jsonl`` would let anyone able to read the agent's state reconstruct the body of a message
the bridge never accepted, and the file is append-only with no expiry. The record therefore keeps
only what diagnoses the drop: the key, the time, the sender/kind/messageId when the item safely
carries them, and a digest of the item for correlation with a hub-side copy.
"""

from __future__ import annotations

import json

from knok.bridge import MAX_HANDLE_ATTEMPTS

from test_phase2 import deployment, send  # noqa: F401  (fixture used by name)


def test_a_dropped_item_keeps_metadata_only_not_the_envelope(deployment):
    hub, bridges, root = deployment
    carl, muse = bridges["carl"], bridges["muse"]
    del muse.state.registry[carl.identity.agent_id]
    send(carl, muse.identity.agent_id, "never verifiable body text", context="c-4",
         message_id="m-doomed")

    for _ in range(MAX_HANDLE_ATTEMPTS):
        muse.poll_once()

    path = muse.state.directory / "dropped.jsonl"
    assert path.exists(), "the drop must still be recorded"
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])

    assert "item" not in record, "the complete rejected envelope must not be retained"
    assert "never verifiable body text" not in path.read_text(encoding="utf-8"), (
        "no part of the rejected body may survive in the drop record"
    )
    assert record["key"] == "m-doomed"
    assert record["messageId"] == "m-doomed"
    assert record["from"] == carl.identity.agent_id
    assert record["kind"] == "message"
    assert record["at"], "the drop time is part of the diagnostic"
    assert record["itemDigest"].startswith("sha256:"), (
        "the digest is what correlates the record with a hub-side copy"
    )

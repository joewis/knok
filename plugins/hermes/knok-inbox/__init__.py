"""Put unread knok mail into the session the agent is already talking in.

The bridge already writes every delivered message to ``~/.knok/inbox.jsonl``; nothing read
that file on a turn. The alternative shape, a cron job polling the inbox, wakes a *new*
session each run, so a reply to Muse starts with no memory of the conversation that prompted
her message. This hook keeps the mail where the conversation is.

Design constraints, each earned from the hook skill:

- **Return context, never touch the system prompt.** ``pre_llm_call``'s return value is
  appended to the current turn's user message; that is the only injection point that
  survives prompt caching.
- **Fail open.** Any exception returns ``None``. A mailbox is not worth a broken turn.
- **Bounded.** At most ``MAX_MESSAGES`` per turn, ``MAX_CHARS`` each, read from the tail of
  the file rather than parsing the whole thing every turn.
- **At-most-once, and only when actually emitted.** Ids enter the seen-set only after the
  context string is built, so a turn that fails before the model call does not eat the mail.
- **Interactive turns only.** A cron run or a background completion must not consume mail:
  it would land in a one-shot session, which is the exact failure this replaces. The hook
  receives ``platform``; it also refuses the envelope prefixes Hermes generates itself.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from pathlib import Path

logger = logging.getLogger("plugins.knok-inbox")

INBOX = Path(os.environ.get("KNOK_INBOX_PATH", "/home/carl/.knok/inbox.jsonl"))
STATE = Path(
    os.environ.get(
        "KNOK_HOOK_STATE", "/home/carl/.hermes/state/knok-hook-seen.json"
    )
)

MAX_MESSAGES = 3
MAX_CHARS = 1400
TAIL_BYTES = 256 * 1024
#: How long an injection may sit unconfirmed before it is believed anyway. The mail was put in
#: front of the model in the previous turn; if the conversation no longer shows it (compaction is
#: the ordinary reason), re-offering it forever would be worse than believing it landed.
PENDING_TTL_SECONDS = 900
#: How many trailing messages to search for the previous injection's marker.
HISTORY_TAIL = 6

# Platforms whose turns are a conversation Carl is having. Everything else (cron, webhook,
# a subagent) would take the mail into a session nobody reads.
INTERACTIVE_PLATFORMS = {"telegram", "cli", "desktop", "tui", "discord", "signal"}

# Hermes' own envelopes are not turns: injecting mail behind a cron notice puts it in a
# session that ends when the job does.
SKIP_PREFIXES = (
    "[IMPORTANT: Background process",
    "[IMPORTANT: You are running as a scheduled cron",
    "[ASYNC DELEGATION",
    "[CONTEXT COMPACTION",
    "[System:",
    "[System note:",
    "[The user sent a document",
)


def _load_state() -> dict:
    """The seen set plus the injection that is still waiting to be confirmed."""
    try:
        data = json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"seen": [], "pending": None}
    if isinstance(data, list):
        return {"seen": [str(x) for x in data], "pending": None}
    if isinstance(data, dict):
        seen = data.get("seen") if isinstance(data.get("seen"), list) else []
        pending = data.get("pending") if isinstance(data.get("pending"), dict) else None
        return {"seen": [str(x) for x in seen], "pending": pending}
    return {"seen": [], "pending": None}


def _load_seen() -> set[str]:
    return {str(x) for x in _load_state()["seen"]}


def _save_state(seen: set[str], pending: dict | None) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    # Keep the file from growing without bound; the mailbox itself is the archive.
    ordered = sorted(seen)[-5000:]
    fd, tmp = tempfile.mkstemp(dir=str(STATE.parent), prefix=".knok-seen-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"seen": ordered, "pending": pending}, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, STATE)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _save_seen(seen: set[str]) -> None:
    """Keep the injection in flight when only the seen set is being written (tests, migration)."""
    _save_state(seen, _load_state()["pending"])


def _history_shows(history: object, ids: list[str]) -> bool:
    """Whether the conversation still contains the block injected for *ids*.

    The marker is the first line of the block the hook returns, so this asks the only question
    that matters: did the text this hook built actually reach the model's context? Searching the
    tail rather than the whole history keeps an old, compacted-away block from being mistaken
    for a delivered one — and PENDING_TTL_SECONDS bounds the case where compaction ate it.
    """
    if not isinstance(history, list) or not ids:
        return False
    tail = history[-HISTORY_TAIL:]
    try:
        rendered = json.dumps(tail, default=str)
    except (TypeError, ValueError):
        return False
    return f"knok mail {ids[0]}" in rendered


def _resolve_pending(state: dict, history: object, now: float) -> tuple[set[str], list[str]]:
    """Decide what the previous injection's ids are now: delivered, or still owed a turn.

    Ids used to enter the seen set the moment the block was *built*, so a turn that failed after
    the hook and before the model call lost that mail permanently. Now the block is written as
    ``pending`` and only moves into ``seen`` once the conversation shows it, or once the TTL says
    the history cannot answer the question any more.
    """
    seen = {str(x) for x in state["seen"]}
    pending = state.get("pending")
    if not isinstance(pending, dict):
        return seen, []
    ids = [str(x) for x in (pending.get("ids") or []) if x]
    if not ids:
        return seen, []
    if history is None:
        # A caller that cannot show what the model saw: the old contract applies. The real hook
        # always passes conversation_history.
        return seen | set(ids), []
    if _history_shows(history, ids):
        return seen | set(ids), []
    try:
        at = float(pending.get("at") or 0.0)
    except (TypeError, ValueError):
        at = 0.0
    if now - at > PENDING_TTL_SECONDS:
        logger.warning(
            "knok-inbox: %d message(s) never seen in the conversation after %ds; "
            "believing the injection rather than offering it forever", len(ids), PENDING_TTL_SECONDS
        )
        return seen | set(ids), []
    # Not delivered: leave these ids out of `seen` so they are selected again below.
    return seen, ids


def _tail_rows(path: Path) -> list[dict]:
    """Parse the last TAIL_BYTES of the inbox, oldest first. Unparseable lines are skipped."""
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - TAIL_BYTES))
            blob = handle.read().decode("utf-8", "replace")
    except OSError:
        return []
    rows: list[dict] = []
    for line in blob.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue  # a partial first line from the seek
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    return rows


def _text_of(message: dict) -> str:
    parts = message.get("parts") or []
    chunks = [str(p.get("text", "")) for p in parts if isinstance(p, dict)]
    return "\n".join(c for c in chunks if c).strip()


def _handle(user_message: str, platform: str, history: object = None,
            session_id: str = "") -> str | None:
    if platform and platform.lower() not in INTERACTIVE_PLATFORMS:
        return None
    if user_message.startswith(SKIP_PREFIXES):
        return None

    state = _load_state()
    seen, _still_owed = _resolve_pending(state, history, time.time())
    seen_changed = seen != {str(x) for x in state["seen"]}
    rows = _tail_rows(INBOX)
    if not rows:
        return None

    # Oldest unread first, and the cap falls on the *newest* mail, not the oldest.
    # Taking the newest three left the oldest unread sitting at the back of the queue
    # indefinitely whenever the backlog exceeded MAX_MESSAGES — and the oldest is the
    # mail most likely to be waiting on an answer. A turn that arrives with four
    # unread must not deliver 15:59 and leave 12:12 for later.
    picked: list[tuple[str, str]] = []
    new_ids: list[str] = []
    for envelope in rows:  # oldest first, as written
        message = envelope.get("message")
        if not isinstance(message, dict):
            continue
        message_id = str(message.get("messageId") or "")
        if not message_id or message_id in seen:
            continue
        text = _text_of(message)
        if not text:
            continue
        new_ids.append(message_id)
        picked.append((message_id, text))
        if len(picked) >= MAX_MESSAGES:
            break

    if not picked:
        # A pending injection that has now been confirmed still has to be written, or the next
        # call would offer it again.
        if seen_changed:
            _save_state(seen, None)
        return None
    sender = None
    blocks = []
    for message_id, text in picked:
        # Sender/context come from the same envelope; look them up rather than re-parsing.
        for envelope in rows:
            message = envelope.get("message") or {}
            if message.get("messageId") == message_id:
                sender = envelope.get("from") or "unknown"
                context_id = message.get("contextId") or ""
                sent_at = envelope.get("sentAt") or ""
                break
        body = text if len(text) <= MAX_CHARS else text[:MAX_CHARS] + "\n[... truncated]"
        blocks.append(
            f"--- knok mail {message_id} from {sender} at {sent_at} "
            f"(context {context_id}) ---\n{body}"
        )

    context = (
        "Unread knok mail arrived while you were working. It is below, oldest first, and is\n"
        "part of this conversation now: answer it in this session, and reply with\n"
        "  knok.cli send --to <sender> --context <contextId> ...\n"
        "so the thread stays attached (omitting --context mints a new one).\n\n"
        + "\n\n".join(blocks)
    )

    # Written as *pending*: the ids move into `seen` on a later call, once the conversation shows
    # the block this turn is about to carry (see _resolve_pending).
    _save_state(seen, {"ids": new_ids, "at": time.time(), "session": session_id})
    logger.info("knok-inbox: injected %d message(s) into the turn", len(picked))
    return context


def pre_llm_call(
    session_id: str = "", user_message: str = "", platform: str = "",
    conversation_history: object = None, **kwargs
) -> dict | None:
    """Hermes hook: append unread knok mail to this turn's user message."""
    try:
        context = _handle(
            user_message or "", platform or kwargs.get("platform", "") or "",
            kwargs.get("conversation_history", conversation_history),
            session_id,
        )
    except Exception as exc:  # fail open: mail must never break a turn
        logger.warning("knok-inbox: %s: %s", type(exc).__name__, exc)
        return None
    return {"context": context} if context else None


def post_llm_call(session_id: str = "", platform: str = "", **kwargs) -> None:
    """Confirm the injection this turn carried: the model call happened, so the mail reached it.

    The block is merged into the user message *after* `pre_llm_call` returns and is not persisted
    to the conversation, so the next turn's history cannot show it — that is why the history check
    is only a secondary signal. `post_llm_call` is the evidence that exists: it fires after the
    call that carried the block. If the turn dies before that call, nothing confirms and the ids
    stay unread, which is the behaviour that matters.
    """
    try:
        state = _load_state()
        pending = state.get("pending")
        if not isinstance(pending, dict):
            return
        owner = pending.get("session")
        if isinstance(owner, str) and owner and session_id and owner != session_id:
            return  # a different conversation's turn cannot speak for this injection
        ids = [str(x) for x in (pending.get("ids") or []) if x]
        if not ids:
            _save_state({str(x) for x in state["seen"]}, None)
            return
        seen = {str(x) for x in state["seen"]} | set(ids)
        _save_state(seen, None)
        logger.info("knok-inbox: confirmed %d message(s) reached the model", len(ids))
    except Exception as exc:  # a confirmation must never break a turn's finalisation
        logger.warning("knok-inbox: confirmation failed (%s: %s)", type(exc).__name__, exc)


def register(ctx) -> None:
    ctx.register_hook("pre_llm_call", pre_llm_call)
    ctx.register_hook("post_llm_call", post_llm_call)
    logger.info("knok-inbox: registered (inbox=%s)", INBOX)

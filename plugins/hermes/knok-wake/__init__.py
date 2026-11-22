"""Start a turn when knok mail lands, so the mailbox has a ringer.

`knok-inbox` injects unread mail into a turn, but only when a turn exists — and nothing in the
knok path starts one, because knok is harness-agnostic on purpose. Before this plugin a message
waited for Jörg's next message: measured at 36, 40, 43 and 73 minutes on 2026-11-22, and the
two-minute cron poller that used to wake the agent was disabled because every run opened a fresh
session with no memory of the conversation.

This is the harness half of that split. It watches the file the bridge already writes, and when
mail has been sitting unread through a quiet window it asks the gateway to start a turn **in the
Telegram DM that owns the conversation** (`PluginContext.inject_message` with an `origin`). The
turn is an ordinary one, so `knok-inbox` attaches the actual mail and the answer lands in the
same session — the two properties the cron poller could not hold at once.

Three properties matter, each learned the hard way:

- **One wake per burst, not per message.** A peer sending four messages in a row is one event to
  answer. The quiet window absorbs the burst; the minimum gap stops a trickle from stacking turns
  the agent has to answer one after another.
- **Never wake for mail that is already spoken for.** Unread is read from the injector's own
  seen-set rather than tracked here, so this plugin cannot disagree with `knok-inbox` about what
  is new. It only ever reads that file.
- **A wake the host refused is not recorded.** The id is remembered only after
  `inject_message` returns True, because recording it first would be the same "delivered without
  evidence" mistake that lost messages in knok itself.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
import types
from pathlib import Path
from typing import Any, Mapping

logger = logging.getLogger("plugins.knok-wake")

HOME = Path(os.environ.get("HERMES_HOME") or (Path.home() / ".hermes"))
INBOX = Path(os.environ.get("KNOK_INBOX_PATH") or (Path.home() / ".knok" / "inbox.jsonl"))
#: The injector's own record of what it has already put in front of the model. Read-only here.
SEEN_STATE = Path(os.environ.get("KNOK_HOOK_STATE") or (HOME / "state" / "knok-hook-seen.json"))
STATE = Path(os.environ.get("KNOK_WAKE_STATE") or (HOME / "state" / "knok-wake.json"))

POLL_SECONDS = int(os.environ.get("KNOK_WAKE_POLL_SECONDS", "15"))
#: The inbox must be untouched this long before waking: one burst, one turn.
QUIET_SECONDS = int(os.environ.get("KNOK_WAKE_QUIET_SECONDS", "20"))
#: At most one wake per this interval, so a slow trickle cannot stack turns.
MIN_GAP_SECONDS = int(os.environ.get("KNOK_WAKE_MIN_GAP_SECONDS", "120"))
#: If mail is still unread this long after a wake, try once more — the wake may have landed in a
#: session that could not finish. Not a retry loop: the mark is replaced, not duplicated.
RETRY_AFTER_SECONDS = int(os.environ.get("KNOK_WAKE_RETRY_AFTER_SECONDS", "600"))

TAIL_BYTES = 512 * 1024
MAX_IDS_IN_WAKE = 5

#: The chat a wake belongs in: the session the conversation is already happening in. The origin
#: path resolves through the adapter's normal session machinery, so the mail is answered in place
#: rather than in a new one-off session.
_CHAT_ID = os.environ.get("KNOK_WAKE_CHAT_ID", "")
ORIGIN: dict[str, str] = {
    "platform": os.environ.get("KNOK_WAKE_PLATFORM", "telegram"),
    "chat_id": _CHAT_ID,
    "chat_type": os.environ.get("KNOK_WAKE_CHAT_TYPE", "dm"),
    "user_id": os.environ.get("KNOK_WAKE_USER_ID") or _CHAT_ID,
}


def _tail_rows(path: Path) -> list[dict]:
    """Parse the last TAIL_BYTES of the inbox, oldest first. Unreadable lines are skipped."""
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


def _injectable_ids(rows: list[dict]) -> list[str]:
    """The ids `knok-inbox` would inject, in the order it would offer them.

    Keeping this identical to the injector's own selection is what stops a wake for something the
    injector will then decline to show — a turn that opens with nothing in it.
    """
    ids: list[str] = []
    for row in rows:
        message = row.get("message")
        if not isinstance(message, dict):
            continue
        message_id = str(message.get("messageId") or "")
        if not message_id:
            continue
        parts = message.get("parts") or []
        text = "\n".join(str(p.get("text", "")) for p in parts if isinstance(p, dict)).strip()
        if not text:
            continue
        ids.append(message_id)
    return ids


def _load_seen() -> set[str]:
    try:
        data = json.loads(SEEN_STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    if isinstance(data, dict):
        return {str(x) for x in data.get("seen", [])}
    if isinstance(data, list):
        return {str(x) for x in data}
    return set()


def _pending_ids() -> set[str]:
    """Ids the injector has put in a turn that has not confirmed yet.

    In flight is not unread: waking for them again is how the same message started three turns in
    a row (10 min apart, the retry window) while it waited for confirmation.
    """
    try:
        data = json.loads(SEEN_STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    pending = data.get("pending") if isinstance(data, dict) else None
    if not isinstance(pending, dict):
        return set()
    return {str(x) for x in (pending.get("ids") or []) if x}


def _load_state() -> dict:
    try:
        data = json.loads(STATE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return {"woke": {}, "last_wake": 0.0}


def _save_state(state: Mapping[str, Any]) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(state), encoding="utf-8")
        os.replace(tmp, STATE)
    except OSError as exc:  # a state write must never take the watcher down
        logger.warning("knok-wake: cannot write state %s: %s", STATE, exc)


def due_ids(
    mail_ids: list[str],
    seen: set[str],
    pending: set[str],
    woke: Mapping[str, float],
    *,
    now: float,
    last_activity: float,
    last_wake: float,
) -> list[str]:
    """Which unread ids justify a turn now. Pure, so the rules can be argued with in a test.

    ``mail_ids`` is oldest-first. An id counts as unread until the *injector* says otherwise, so
    this plugin can never mark something read that the model has not been shown.
    """
    unread = [m for m in mail_ids if m not in seen and m not in pending]
    if not unread:
        return []
    if now - last_activity < QUIET_SECONDS:
        return []  # a burst is still arriving; one turn after it settles beats four turns inside it
    if now - last_wake < MIN_GAP_SECONDS:
        return []
    return [
        message_id
        for message_id in unread
        if message_id not in woke or now - float(woke[message_id]) > RETRY_AFTER_SECONDS
    ]


def wake_text(ids: list[str]) -> str:
    """The turn's opening line. The mail itself rides behind it, injected by `knok-inbox`."""
    shown = ", ".join(ids[:MAX_IDS_IN_WAKE])
    more = "" if len(ids) <= MAX_IDS_IN_WAKE else f" (+{len(ids) - MAX_IDS_IN_WAKE} more)"
    return (
        f"[knok wake] {len(ids)} unread knok message(s): {shown}{more}.\n"
        "The mail is attached to this turn by knok-inbox. Answer what needs answering, reply on "
        "knok rather than only here when a peer is waiting, and keep it short. If none of it needs "
        "a reply, say so in one line."
    )


def tick(ctx: Any, *, now: float | None = None) -> int:
    """One watcher pass. Returns how many ids were woken for — 0 means nothing happened."""
    now = time.time() if now is None else now
    rows = _tail_rows(INBOX)
    if not rows:
        return 0
    ids = _injectable_ids(rows)
    if not ids:
        return 0
    try:
        last_activity = INBOX.stat().st_mtime
    except OSError:
        last_activity = now

    state = _load_state()
    woke = state.get("woke") if isinstance(state.get("woke"), dict) else {}
    fresh = due_ids(
        ids,
        _load_seen(),
        _pending_ids(),
        woke,
        now=now,
        last_activity=last_activity,
        last_wake=float(state.get("last_wake") or 0.0),
    )
    if not fresh:
        return 0

    try:
        accepted = ctx.inject_message(wake_text(fresh), origin=dict(ORIGIN))
    except Exception as exc:  # a watcher must not take the plugin host down
        logger.warning("knok-wake: inject_message raised %s: %s", type(exc).__name__, exc)
        accepted = False
    if not accepted:
        # Not recorded: the next pass may try again. A refusal here is a wiring problem (the
        # plugin is not allowed to start turns), and inventing a record of a turn that never
        # opened is exactly how mail goes missing with every log saying it was delivered.
        logger.warning(
            "knok-wake: the host refused to start a turn for %d message(s); "
            "check plugins.entries.knok-wake.allow_gateway_injection", len(fresh)
        )
        return 0

    # Only ids that have not been woken before are stamped; a retry keeps its original time so it
    # can be retried again later instead of being pushed forever into the future.
    for message_id in fresh:
        woke.setdefault(message_id, now)
    state["woke"] = {k: v for k, v in woke.items() if now - float(v) < 24 * 3600}
    state["last_wake"] = now
    _save_state(state)
    logger.info("knok-wake: started a turn for %d unread message(s)", len(fresh))
    return len(fresh)


def _loop(ctx: Any, stop: threading.Event) -> None:
    logger.info("knok-wake: watching %s every %ss", INBOX, POLL_SECONDS)
    while not stop.wait(POLL_SECONDS):
        try:
            tick(ctx)
        except Exception as exc:  # keep watching: a bad pass is not a dead watcher
            logger.warning("knok-wake: pass failed (%s: %s)", type(exc).__name__, exc)


def _is_gateway_process() -> bool:
    """Only the long-lived gateway can start a turn, so only it should watch.

    Plugin discovery runs in every process — each cron run and CLI invocation imports this module.
    A watcher started there spends its life calling `inject_message` against a host that does not
    exist and logging the refusal. The gateway's own cmdline carries the `gateway run` pair; that is
    the cheapest reliable answer for a process that has not been handed a runner yet.
    """
    try:
        raw = Path("/proc/self/cmdline").read_bytes()
    except OSError:
        return False
    parts = [part.decode("utf-8", "replace") for part in raw.split(b"\0") if part]
    return "gateway" in parts and "run" in parts


def _shared() -> types.ModuleType:
    """Process-wide slot that survives a plugin reload.

    `reload-plugins` evicts this module and imports it again; without a slot outside it, the old
    watcher thread would keep running beside the new one and every burst would wake twice.
    """
    module = sys.modules.get("_knok_wake_shared")
    if module is None:
        module = types.ModuleType("_knok_wake_shared")
        module.stop = threading.Event()  # type: ignore[attr-defined]
        module.thread = None  # type: ignore[attr-defined]
        sys.modules["_knok_wake_shared"] = module
    return module


def pre_llm_call(session_id: str = "", user_message: str = "", platform: str = "", **kwargs):
    """A no-op hook, registered so this plugin is *activated* rather than merely imported.

    `reload-plugins` re-runs `register()` only for plugins that declare a capability; a plugin with
    none is re-imported and skipped, leaving the previous watcher thread (and its old code) alive
    in the gateway. Declaring one hook makes the reload replace the thread, which is how a change
    to this file reaches the running process without restarting the lifeline.
    """
    return None


def register(ctx: Any) -> None:
    ctx.register_hook("pre_llm_call", pre_llm_call)
    if not ORIGIN["chat_id"]:
        logger.error("knok-wake: KNOK_WAKE_CHAT_ID is not set; no wake can be placed. "
                     "Set it to the chat a turn should start in (see plugins/hermes/README.md).")
        return
    if not _is_gateway_process():
        logger.debug("knok-wake: not the gateway process; no watcher started")
        return
    shared = _shared()
    previous = getattr(shared, "thread", None)
    if previous is not None and previous.is_alive():
        shared.stop.set()
        previous.join(timeout=5)
    stop = threading.Event()
    thread = threading.Thread(target=_loop, args=(ctx, stop), name="knok-wake", daemon=True)
    thread.start()
    shared.stop = stop
    shared.thread = thread
    logger.info("knok-wake: registered (inbox=%s, origin=%s/%s)",
                INBOX, ORIGIN["platform"], ORIGIN["chat_id"])

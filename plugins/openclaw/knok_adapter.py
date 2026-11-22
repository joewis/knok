#!/usr/bin/env python3
"""Wake an OpenClaw agent when Knok mail arrives, and send its answer back.

This is the harness half of Knok. Knok delivers to a mailbox and knows nothing about sessions; this
process owns everything specific to OpenClaw:

  * when to wake        — a new line in the bridge's inbox.jsonl
  * which session       — one per peer, ``knok:<sender-local-part>``, so a correspondent keeps its
                          own history and none of it lands in the agent's main or Telegram session
  * who sends the reply — this adapter, not the agent. The incoming envelope carries the thread's
                          contextId; the agent only decides what to say. An agent that calls
                          ``knok send`` itself has to invent a context, and the thread fragments into
                          one conversation per message (measured: five replies from one peer, five
                          contexts).

Two durability rules, both learned from the mailbox it sits on:

  * The inbox is append-only and the offset is ours, so a crash between reading and acting would
    skip mail. Every line is therefore *staged to a file first*, and only then is the offset
    advanced — the same shape as the bridge's own "write, then ack".
  * A staged file is only moved to ``processed/`` after the reply is accepted by the hub. A failed
    turn leaves the file in place (with an attempt count) and it is offered again.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HOME = Path(os.path.expanduser("~"))
AGENT_ID = os.environ.get("KNOK_ADAPTER_AGENT", "")
OPENCLAW_AGENT = os.environ.get("KNOK_ADAPTER_OPENCLAW_AGENT", "")
STATE_DIR = Path(os.environ.get("KNOK_ADAPTER_STATE", HOME / ".knok" / "adapter"))
INBOX = Path(os.environ.get("KNOK_ADAPTER_INBOX", HOME / ".knok" / "inbox.jsonl"))
KNOK_STATE = os.environ.get("KNOK_STATE", str(HOME / ".knok"))
KNOK_REGISTRY = os.environ.get("KNOK_REGISTRY", str(HOME / ".knok" / "registry"))
KNOK_HUB_URL = os.environ.get("KNOK_HUB_URL", "http://127.0.0.1:18443")
PYTHONPATH = os.environ.get("KNOK_ADAPTER_PYTHONPATH", "")
REPO = os.environ.get("KNOK_ADAPTER_REPO", "")
PYTHON = os.environ.get("KNOK_ADAPTER_PYTHON", "/usr/bin/python3")
TURN_TIMEOUT = int(os.environ.get("KNOK_ADAPTER_TURN_TIMEOUT", "300"))
MAX_ATTEMPTS = int(os.environ.get("KNOK_ADAPTER_MAX_ATTEMPTS", "3"))
POLL_SECONDS = float(os.environ.get("KNOK_ADAPTER_POLL", "2"))

STAGING = STATE_DIR / "inbox"
PROCESSED = STATE_DIR / "processed"
FAILED = STATE_DIR / "failed"
CURSOR = STATE_DIR / "cursor.json"
LOG = STATE_DIR / "adapter.log"

for directory in (STATE_DIR, STAGING, PROCESSED, FAILED):
    directory.mkdir(parents=True, exist_ok=True)


def require(name: str, value: str) -> str:
    if not value:
        sys.exit(f"{name} is not set; see plugins/openclaw/README.md")
    return value


AGENT_ID = require("KNOK_ADAPTER_AGENT", AGENT_ID)
OPENCLAW_AGENT = require("KNOK_ADAPTER_OPENCLAW_AGENT", OPENCLAW_AGENT)


def log(message: str) -> None:
    line = f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} {message}"
    print(line, flush=True)
    try:
        with LOG.open("a") as handle:
            handle.write(line + "\n")
    except OSError:
        pass


def load_cursor() -> dict:
    try:
        data = json.loads(CURSOR.read_text())
        if isinstance(data, dict) and isinstance(data.get("offset"), int):
            return data
    except (OSError, ValueError):
        pass
    return {"offset": 0, "inode": None, "staged": []}


def save_cursor(cursor: dict) -> None:
    cursor["staged"] = cursor.get("staged", [])[-500:]
    tmp = CURSOR.with_suffix(".tmp")
    tmp.write_text(json.dumps(cursor, sort_keys=True))
    tmp.replace(CURSOR)


def stage_new(cursor: dict) -> int:
    """Move new inbox lines into the staging directory, then advance the offset."""
    if not INBOX.exists():
        return 0
    stat = INBOX.stat()
    inode = getattr(stat, "st_ino", None)
    if cursor.get("inode") not in (None, inode) or stat.st_size < cursor.get("offset", 0):
        cursor["offset"] = 0  # rotated or rewritten file: start over rather than mid-file
    cursor["inode"] = inode

    staged = 0
    with INBOX.open("rb") as handle:
        handle.seek(cursor["offset"])
        for raw in handle:
            if not raw.endswith(b"\n"):
                break  # partial line; the bridge is mid-write
            try:
                envelope = json.loads(raw)
            except ValueError:
                log(f"skipped unparseable line: {raw[:120]!r}")
                cursor["offset"] += len(raw)
                continue
            message_id = ((envelope.get("message") or {}).get("messageId") or "")
            if not message_id:
                log(f"skipped envelope without messageId: {raw[:120]!r}")
                cursor["offset"] += len(raw)
                continue
            if message_id in cursor.get("staged", []) or (STAGING / f"{message_id}.json").exists():
                cursor["offset"] += len(raw)
                continue
            tmp = STAGING / f".{message_id}.tmp"
            tmp.write_text(json.dumps(envelope, sort_keys=True))
            tmp.replace(STAGING / f"{message_id}.json")
            cursor.setdefault("staged", []).append(message_id)
            cursor["offset"] += len(raw)
            staged += 1
    if staged:
        save_cursor(cursor)
        log(f"staged {staged} new envelope(s)")
    return staged


def build_prompt(envelope: dict, sender: str, context: str, expects_reply: bool) -> str:
    text = ""
    for part in (envelope.get("message") or {}).get("parts") or []:
        if isinstance(part, dict) and part.get("kind") == "text":
            text += part.get("text", "")
    instruction = (
        "Write your reply as your final message: the adapter sends it back in this thread, so do "
        "not call knok send and do not try to send anything yourself — a second send double-posts "
        "and loses the thread. Reading is not acting: you may read files and run read-only "
        "commands before answering."
        + (f" The repository clone is at {REPO}." if REPO else "")
        + " Do not take actions with side effects on anyone's behalf."
        if expects_reply
        else "No reply is expected in this thread. Do not write a reply; just note what you read. "
             "Reading files and running read-only commands is fine."
    )
    return (
        f"Knok mail from {sender} (thread {context}).\n\n"
        f"{text}\n\n"
        f"---\n{instruction}"
    )


def run_turn(session_key: str, prompt: str) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
        handle.write(prompt)
        prompt_path = handle.name
    try:
        result = subprocess.run(
            ["openclaw", "agent", "--agent", OPENCLAW_AGENT, "--session-key", session_key,
             "--message-file", prompt_path, "--json", "--timeout", str(TURN_TIMEOUT - 30)],
            capture_output=True, text=True, timeout=TURN_TIMEOUT,
        )
    finally:
        try:
            os.unlink(prompt_path)
        except OSError:
            pass
    if result.returncode != 0:
        raise RuntimeError(f"openclaw agent exited {result.returncode}: {result.stderr[-400:]}")
    return _final_text(json.loads(result.stdout))


def _final_text(payload) -> str:
    """Pull the assistant's final text out of the CLI's JSON without depending on its shape."""
    if isinstance(payload, dict):
        for key in ("finalAssistantMessageRawText", "finalAssistantMessage", "text"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        for value in payload.values():
            found = _final_text(value)
            if found:
                return found
    elif isinstance(payload, list):
        for value in payload:
            found = _final_text(value)
            if found:
                return found
    return ""


def send_reply(to: str, context: str, text: str, reply_to: str) -> dict:
    env = dict(os.environ, KNOK_AGENT=AGENT_ID, KNOK_STATE=KNOK_STATE,
               KNOK_REGISTRY=KNOK_REGISTRY, KNOK_HUB_URL=KNOK_HUB_URL)
    if PYTHONPATH:
        env["PYTHONPATH"] = PYTHONPATH
    result = subprocess.run(
        [PYTHON, "-m", "knok.cli", "send", "--to", to, "--context", context,
         "--reply-to", reply_to, "--text", text],
        capture_output=True, text=True, timeout=60, env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(f"knok send exited {result.returncode}: {result.stderr[-400:]}")
    return json.loads(result.stdout.strip().splitlines()[-1])


def handle(envelope: dict, staged_file: Path) -> str:
    sender = envelope.get("from", "")
    message = envelope.get("message") or {}
    message_id = message.get("messageId", "")
    context = message.get("contextId", "")
    expects_reply = bool((envelope.get("turn") or {}).get("expectsReply", True))
    if sender == AGENT_ID:
        return "own message"
    peer = sender.split("@")[0]
    session_key = f"knok:{peer}"
    answer_file = staged_file.with_suffix(".answer")
    if answer_file.exists():
        # A previous attempt got an answer out of the agent and then failed to send it. Re-running
        # the turn would spend a model call to produce a second, different answer for the same
        # message; the stored one is the reply that belongs to this message.
        answer = answer_file.read_text()
        log(f"reusing stored answer for {message_id}")
    else:
        log(f"wake {session_key} for {message_id} thread={context} expects_reply={expects_reply}")
        answer = run_turn(session_key, build_prompt(envelope, sender, context, expects_reply))
        if expects_reply:
            if not answer:
                raise RuntimeError("the agent returned no text to send")
            tmp = answer_file.with_suffix(".answer.tmp")
            tmp.write_text(answer)
            tmp.replace(answer_file)
    if not expects_reply:
        return f"noted, no reply expected ({session_key})"
    result = send_reply(sender, context, answer, message_id)
    return f"replied in {context}: {result}"


def attempts_for(message_id: str) -> int:
    marker = FAILED / f"{message_id}.attempts"
    try:
        return int(marker.read_text().strip())
    except (OSError, ValueError):
        return 0


def record_attempt(message_id: str, count: int) -> None:
    (FAILED / f"{message_id}.attempts").write_text(str(count))


def main() -> int:
    log(f"adapter for {AGENT_ID} watching {INBOX} (openclaw agent {OPENCLAW_AGENT})")
    cursor = load_cursor()
    while True:
        try:
            stage_new(cursor)
        except OSError as exc:
            log(f"cannot read inbox: {exc}")
        for staged_file in sorted(STAGING.glob("*.json"), key=lambda p: p.stat().st_mtime):
            message_id = staged_file.stem
            if attempts_for(message_id) >= MAX_ATTEMPTS:
                continue
            try:
                envelope = json.loads(staged_file.read_text())
                outcome = handle(envelope, staged_file)
            except Exception as exc:  # noqa: BLE001 — one bad message must not stop the adapter
                count = attempts_for(message_id) + 1
                record_attempt(message_id, count)
                log(f"failed {message_id} (attempt {count}/{MAX_ATTEMPTS}): {exc}")
                if count >= MAX_ATTEMPTS:
                    shutil.move(str(staged_file), str(FAILED / staged_file.name))
                    log(f"gave up on {message_id}; left in {FAILED}")
                continue
            shutil.move(str(staged_file), str(PROCESSED / staged_file.name))
            try:
                staged_file.with_suffix(".answer").unlink()
            except OSError:
                pass
            log(f"done {message_id}: {outcome}")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    sys.exit(main())

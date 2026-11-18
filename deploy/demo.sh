#!/usr/bin/env bash
# Phase 2 demo without the compose plugin (this box has docker but no `docker compose`).
#
# It builds one image, provisions keys into per-container volumes, starts a hub and three bridges,
# then runs the §11 exit criterion for real — with assertions, not printouts:
#
#   1. muse's bridge is stopped; carl sends
#   2. the hub holds the envelope (asserted against the hub's store)
#   3. a "crash" run fetches the message and exits before acking (the at-least-once case)
#   4. muse starts; it must receive the message exactly once
#   5. the hub's mailbox must be empty after the ack, and stay empty
#
# Every wait polls for the condition; no step relies on a sleep being long enough.
#
# Usage: deploy/demo.sh [--keep]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE=knok:phase2
NET=knok-net
PREFIX=knok
KEEP=${1:-}

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32mPASS\033[0m %s\n' "$*"; }
die()  { printf '   \033[31mFAIL\033[0m %s\n' "$*"; exit 1; }

fail_logs() {
  for c in "$PREFIX-carl" "$PREFIX-muse" "$PREFIX-bobby" "$PREFIX-hub"; do
    docker logs --tail 20 "$c" 2>&1 | sed "s/^/    [$c] /" || true
  done
}

mailbox_count() {
  docker exec -i "$PREFIX-hub" python -c '
import sqlite3
print(sqlite3.connect("/app/state/hub.db").execute("SELECT COUNT(*) FROM mail").fetchone()[0])'
}
inbox_lines() {
  docker exec "$PREFIX-muse" sh -c 'cat /app/state/inbox.jsonl 2>/dev/null | wc -l'
}

wait_until() {  # wait_until "<description>" <expected> <command...>
  local what=$1 expected=$2; shift 2
  local value=""
  for _ in $(seq 1 60); do
    value=$("$@" 2>/dev/null | tr -d ' \n')
    [ "$value" = "$expected" ] && return 0
    sleep 0.5
  done
  die "timed out waiting for $what (last value: '$value')"
}

cleanup() {
  if [ "$KEEP" = "--keep" ]; then
    say "left running: docker ps --filter name=$PREFIX"
    return
  fi
  for c in carl muse bobby hub prepare; do docker rm -f "$PREFIX-$c" >/dev/null 2>&1 || true; done
  docker network rm "$NET" >/dev/null 2>&1 || true
}
on_exit() {
  local rc=$?
  if [ $rc -ne 0 ]; then echo; echo "--- container logs ---"; fail_logs; fi
  cleanup
}
trap on_exit EXIT

say "build"
docker build -q -t "$IMAGE" -f "$ROOT/deploy/Dockerfile" "$ROOT"

say "network + volumes"
docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
for v in hub carl muse bobby registry; do docker volume create "$PREFIX-$v" >/dev/null; done

say "provision (keys, policies, registry)"
# A fresh volume root is root-owned and the containers run as uid 10001, so prepare is the one step
# that runs as root: it writes the keys and then hands the volumes to the runtime user.
docker run --rm --name "$PREFIX-prepare" --network "$NET" --user 0:0 --entrypoint sh \
  -e KNOK_HUB_DOMAIN=hub.local \
  -v "$PREFIX-hub:/srv/hub" \
  -v "$PREFIX-carl:/srv/agents/carl" \
  -v "$PREFIX-muse:/srv/agents/muse" \
  -v "$PREFIX-bobby:/srv/agents/bobby" \
  -v "$PREFIX-registry:/srv/registry" \
  "$IMAGE" -c 'python -m knok.provision --root /srv --agents carl muse bobby > /srv/manifest.json
              python -c "import json;m=json.load(open(\"/srv/manifest.json\"));print(\"  agents:\", *sorted(m[\"agents\"]))"
              chown -R 10001:10001 /srv'

say "hub"
docker run -d --name "$PREFIX-hub" --network "$NET" --network-alias hub \
  -e KNOK_ROLE=hub -e KNOK_HUB_DOMAIN=hub.local \
  -e KNOK_STATE=/app/state -e KNOK_REGISTRY=/app/registry -e KNOK_BIND=0.0.0.0:8080 \
  -v "$PREFIX-hub:/app/state" -v "$PREFIX-registry:/app/registry:ro" \
  -p 127.0.0.1:18080:8080 "$IMAGE" knok.runner >/dev/null
for _ in $(seq 1 40); do
  docker exec "$PREFIX-hub" python -c "import socket,sys; s=socket.socket(); sys.exit(0 if s.connect_ex(('127.0.0.1',8080))==0 else 1)" 2>/dev/null && break
  sleep 0.5
done

start_agent() {
  local name=$1
  docker run -d --name "$PREFIX-$name" --network "$NET" \
    -e KNOK_ROLE=bridge -e KNOK_AGENT="$name@hub.local" -e KNOK_HUB_URL=http://hub:8080 \
    -e KNOK_HUB_DOMAIN=hub.local -e KNOK_STATE=/app/state -e KNOK_REGISTRY=/app/registry \
    -e KNOK_POLL=1 \
    -v "$PREFIX-$name:/app/state" -v "$PREFIX-registry:/app/registry:ro" \
    "$IMAGE" knok.runner >/dev/null
}

say "start carl and bobby; muse stays down"
start_agent carl
start_agent bobby
for _ in $(seq 1 40); do
  docker exec "$PREFIX-carl" sh -c 'pgrep -f knok.runner >/dev/null' 2>/dev/null && break
  sleep 0.5
done

say "carl sends to the absent muse"
docker exec "$PREFIX-carl" python -m knok.cli send \
  --to muse@hub.local --text "Phase 2 exit test: are you there?" --context c-exit-1

say "the hub holds it (muse has no bridge polling)"
wait_until "the hub to hold exactly one envelope" 1 mailbox_count
ok "hub mailbox contains 1 envelope"
docker exec -i "$PREFIX-hub" python -c '
import sqlite3
for row in sqlite3.connect("/app/state/hub.db").execute(
        "SELECT recipient, sender, message_id, kind FROM mail"):
    print("  row:", row)'

say "at-least-once: fetch, then crash before the ack"
docker run --rm --network "$NET" --entrypoint python \
  -e KNOK_AGENT=muse@hub.local -e KNOK_STATE=/app/state -e KNOK_REGISTRY=/app/registry \
  -e KNOK_HUB_URL=http://hub:8080 \
  -v "$PREFIX-muse:/app/state" -v "$PREFIX-registry:/app/registry:ro" \
  "$IMAGE" -c '
import os
from knok.bridge import load_cards, fingerprint_key
from knok.identity import load
from knok.hubclient import HubClient
cards = load_cards(os.environ["KNOK_REGISTRY"])
agent = os.environ["KNOK_AGENT"]
identity = load(agent, os.environ["KNOK_STATE"] + "/identity.key",
                fingerprint_key(cards[agent]["bridge"]["publicKey"]))
page = HubClient(os.environ["KNOK_HUB_URL"], identity).fetch()
print("  fetched", len(page["messages"]), "message(s), exiting before ack")
'
wait_until "the hub to still hold the unacked envelope" 1 mailbox_count
ok "the hub still holds it: the ack never happened"

say "muse comes back"
start_agent muse
wait_until "muse to receive exactly one message" 1 inbox_lines
ok "muse's inbox has exactly 1 message"

say "the hub deletes only on ack"
wait_until "the hub mailbox to empty" 0 mailbox_count
ok "hub mailbox is empty after the ack"

say "no duplicate on a further poll"
sleep 3
[ "$(inbox_lines | tr -d ' ')" = "1" ] && ok "inbox still has exactly 1 message after another poll" \
  || die "duplicate delivery: inbox has $(inbox_lines) lines"

docker exec "$PREFIX-muse" python -m knok.cli inbox
printf '\n\033[32mPhase 2 exit criterion: PASS\033[0m\n'

#!/usr/bin/env bash
# Phase 2 demo without the compose plugin (this box has docker but no `docker compose`).
#
# It builds one image, provisions keys into per-container volumes, starts a hub and three bridges,
# then runs the §11 exit criterion for real:
#
#   1. stop agent-muse
#   2. carl sends
#   3. the hub holds the envelope (nobody polls for muse)
#   4. start agent-muse
#   5. muse receives exactly one copy, and the hub's mailbox is empty afterwards
#
# Usage: deploy/demo.sh [--keep]     (--keep leaves the stack running for poking at)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE=knok:phase2
NET=knok-net
PREFIX=knok
KEEP=${1:-}

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

say "build"
docker build -q -t "$IMAGE" -f "$ROOT/deploy/Dockerfile" "$ROOT"

cleanup() {
  if [ "$KEEP" = "--keep" ]; then
    say "left running: docker ps --filter name=$PREFIX"
    return
  fi
  for c in carl muse bobby hub; do docker rm -f "$PREFIX-$c" >/dev/null 2>&1 || true; done
  docker rm -f "$PREFIX-prepare" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

say "network + volumes"
docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
for v in hub carl muse bobby registry; do docker volume create "$PREFIX-$v" >/dev/null; done

say "provision (keys, policies, registry)"
# Docker creates a fresh volume root-owned; the containers run as uid 10001, so the prepare step is
# the one thing that runs as root: it writes the keys and then hands the volumes to the runtime user.
docker run --rm --name "$PREFIX-prepare" --network "$NET" --user 0:0 --entrypoint sh \
  -e KNOK_HUB_DOMAIN=hub.local \
  -v "$PREFIX-hub:/srv/hub" \
  -v "$PREFIX-carl:/srv/agents/carl" \
  -v "$PREFIX-muse:/srv/agents/muse" \
  -v "$PREFIX-bobby:/srv/agents/bobby" \
  -v "$PREFIX-registry:/srv/registry" \
  "$IMAGE" -c 'python -m knok.provision --root /srv --agents carl muse bobby > /srv/manifest.json; echo "agents:"; python -c "import json;m=json.load(open(\"/srv/manifest.json\"));print(*sorted(m[\"agents\"]),sep=\"  \")"; chown -R 10001:10001 /srv'

say "hub"
docker run -d --name "$PREFIX-hub" --network "$NET" --network-alias hub \
  -e KNOK_ROLE=hub -e KNOK_HUB_DOMAIN=hub.local \
  -e KNOK_STATE=/app/state -e KNOK_REGISTRY=/app/registry -e KNOK_BIND=0.0.0.0:8080 \
  -v "$PREFIX-hub:/app/state" -v "$PREFIX-registry:/app/registry:ro" \
  -p 127.0.0.1:18080:8080 "$IMAGE" knok.runner >/dev/null
for _ in $(seq 1 20); do
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
    -e KNOK_AGENT="$name@hub.local" \
    "$IMAGE" knok.runner >/dev/null
}

say "start carl and bobby; muse stays down"
start_agent carl
start_agent bobby
sleep 2

say "carl sends to the absent muse"
docker exec "$PREFIX-carl" python -m knok.cli send \
  --to muse@hub.local --text "Phase 2 exit test: are you there?" --context c-exit-1

say "the hub is holding it (muse has no bridge to poll it out)"
docker exec -i "$PREFIX-hub" python - <<'PY'
import sqlite3
rows = sqlite3.connect("/app/state/hub.db").execute(
    "SELECT recipient, sender, message_id, kind FROM mail").fetchall()
print("mailbox:", rows or "empty")
PY

say "muse comes back"
start_agent muse
sleep 3

say "muse's inbox"
docker exec "$PREFIX-muse" python -m knok.cli inbox

say "hub mailbox after the ack"
docker exec -i "$PREFIX-hub" python - <<'PY'
import sqlite3
rows = sqlite3.connect("/app/state/hub.db").execute(
    "SELECT recipient, sender, message_id, kind FROM mail").fetchall()
print("mailbox:", rows or "empty")
PY

say "no duplicate: muse polls again and its inbox still has one line"
sleep 3
docker exec "$PREFIX-muse" sh -c 'wc -l < /app/state/inbox.jsonl'

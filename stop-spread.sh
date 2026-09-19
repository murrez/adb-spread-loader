#!/bin/bash
ROOT="$(cd "$(dirname "$0")" && pwd)"
PORT="${ADB_PORT:-5555}"
pkill -f "${ROOT}/spread.sh" 2>/dev/null || true
pkill -f "spread.sh" 2>/dev/null || true
pkill -f "zmap -p ${PORT} " 2>/dev/null || true
pkill -f "./adb ${PORT} " 2>/dev/null || true
rm -f "${ROOT}"/.spread.* 2>/dev/null || true
echo "spread stopped"

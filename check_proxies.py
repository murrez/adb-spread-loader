#!/usr/bin/env python3
"""Quick SOCKS5 liveness check (same protocol as adb proxy main.go)."""
import socket
import struct
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

TIMEOUT = 12
TEST_HOST = b"1.1.1.1"
TEST_PORT = 5555


def parse_line(line: str):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    at = line.rfind("@")
    if at <= 0:
        return None
    hostport = line[at + 1 :]
    userpass = line[:at]
    if ":" not in hostport:
        return None
    host, port_s = hostport.rsplit(":", 1)
    colon = userpass.find(":")
    if colon <= 0:
        return None
    user = userpass[:colon]
    password = userpass[colon + 1 :]
    return host, int(port_s), user, password


def socks5_check(host, port, user, password):
    s = socket.create_connection((host, port), timeout=TIMEOUT)
    s.settimeout(TIMEOUT)
    try:
        s.sendall(b"\x05\x02\x00\x02")
        buf = s.recv(2)
        if len(buf) < 2 or buf[0] != 0x05:
            return False, "bad version"
        method = buf[1]
        if method == 0xFF:
            return False, "no acceptable auth"
        if method == 0x02:
            u, p = user.encode(), password.encode()
            s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            auth = s.recv(2)
            if len(auth) < 2 or auth[1] != 0x00:
                return False, "auth rejected"
        elif method != 0x00:
            return False, f"auth method {method}"

        req = (
            b"\x05\x01\x00\x03"
            + bytes([len(TEST_HOST)])
            + TEST_HOST
            + struct.pack("!H", TEST_PORT)
        )
        s.sendall(req)
        resp = s.recv(10)
        if len(resp) < 2 or resp[1] != 0x00:
            code = resp[1] if len(resp) > 1 else -1
            if code == 0x02:
                return False, "ruleset blocks port (ADB needs :5555 allowed)"
            return False, f"connect code {code}"
        return True, "ok (5555 allowed)"
    finally:
        s.close()


def check_one(idx, line):
    parsed = parse_line(line)
    if not parsed:
        return idx, line[:60], False, "parse error"
    host, port, user, password = parsed
    label = f"{host}:{port}"
    try:
        ok, msg = socks5_check(host, port, user, password)
        return idx, label, ok, msg
    except Exception as e:
        return idx, label, False, str(e)[:80]


def main():
    path = Path(__file__).with_name("proxies.txt")
    lines = path.read_text(encoding="utf-8").splitlines()
    tasks = [(i + 1, ln) for i, ln in enumerate(lines) if parse_line(ln)]

    ok_list = []
    fail_list = []
    with ThreadPoolExecutor(max_workers=12) as ex:
        futs = [ex.submit(check_one, i, ln) for i, ln in tasks]
        for fut in as_completed(futs):
            idx, label, ok, msg = fut.result()
            row = (idx, label, msg)
            if ok:
                ok_list.append(row)
            else:
                fail_list.append(row)

    ok_list.sort()
    fail_list.sort()
    print(f"Checked {len(tasks)} proxies (SOCKS5 -> {TEST_HOST.decode()}:{TEST_PORT})\n")
    print(f"OK ({len(ok_list)}):")
    for idx, label, msg in ok_list:
        print(f"  L{idx:2d} {label}  [{msg}]")
    print(f"\nFAIL ({len(fail_list)}):")
    for idx, label, msg in fail_list:
        print(f"  L{idx:2d} {label}  [{msg}]")
    return 0 if ok_list else 1


if __name__ == "__main__":
    sys.exit(main())

"""Capture a TLS ClientHello without completing a handshake.

Usage:
    python3 peek.py --port 18443 --out captures --label chrome-stable

The ClientHello is the client's first flight, so no server certificate is
needed: the tool accepts the connection, buffers the first handshake record,
writes a fixture, and closes. The client reports a connection error; the
capture is already saved at that point.
"""

import argparse
import datetime
import json
import os
import socket
import sys

import clienthello


def capture_clienthello(conn, timeout=5.0):
    conn.settimeout(timeout)
    try:
        header = recv_exact(conn, 5)
    except (socket.timeout, ConnectionError):
        return None
    if header[0] != 0x16:
        return None
    rec_len = int.from_bytes(header[3:5], "big")
    body = recv_exact(conn, rec_len)
    raw = header + body
    # A ClientHello longer than one record is legal; keep reading until the
    # handshake message is complete.
    hs_len = int.from_bytes(body[1:4], "big")
    while len(body) < hs_len:
        header2 = recv_exact(conn, 5)
        rec_len2 = int.from_bytes(header2[3:5], "big")
        chunk = recv_exact(conn, rec_len2)
        raw += header2 + chunk
        body += chunk
    return raw


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return buf


def build_fixture(raw, label, peer):
    parsed = clienthello.parse_clienthello(raw)
    ja4, ja4_r = clienthello.compute_ja4(parsed)
    return {
        "schema": 1,
        "tool": "clienthello_peek",
        "label": label,
        "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "peer": peer,
        "raw": raw.hex(),
        "ja4": ja4,
        "ja4_r": ja4_r,
        "fields": parsed,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=18443)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--out", default="captures", help="directory for fixture files")
    ap.add_argument("--label", default="client", help="fixture name prefix")
    ap.add_argument("--count", type=int, default=1, help="stop after N captures")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(8)
    if not args.quiet:
        print("listening on %s:%d, capturing %d ClientHello(s) into %s" %
              (args.host, args.port, args.count, args.out), file=sys.stderr)

    done = 0
    while done < args.count:
        conn, addr = srv.accept()
        try:
            raw = capture_clienthello(conn)
        finally:
            try:
                conn.close()
            except OSError:
                pass
        if raw is None:
            continue
        fixture = build_fixture(raw, args.label, "%s:%d" % addr[:2])
        name = "%s-%d.json" % (args.label, done + 1)
        with open(os.path.join(args.out, name), "w") as f:
            json.dump(fixture, f, indent=2)
            f.write("\n")
        done += 1
        print("%s  %s" % (fixture["ja4"], name), file=sys.stderr if args.quiet else sys.stdout)

    srv.close()


if __name__ == "__main__":
    main()

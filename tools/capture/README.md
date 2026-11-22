# Capture a ClientHello

`peek.py` listens on a local port, saves the first TLS handshake record a
client sends, and closes. The ClientHello is the client's first flight, so
the tool needs no certificate and no server key: the client will report a
connection error, but the capture is already written by then.

`clienthello.py` parses the raw bytes (extensions, ciphers, key share
groups, ALPN, signature algorithms) and computes JA4 and JA4_r per the FoxIO
spec. `test_clienthello.py` proves the whole pipeline offline: the
`fixtures/clients` captures are real local handshakes whose JA4 matches the
`fixtures/oracle` files, the same clients seen server-side by
`tls.peet.ws/api/all`.

## Run the tests

```sh
cd tools/capture
python3 -m unittest test_clienthello.py -v
```

## Capture a browser

```sh
python3 tools/capture/peek.py --port 18443 --out fixtures/clients --label chrome-131-stable --count 1
```

Then open `https://localhost:18443` in the browser profile you want to
record. The page will fail with a connection error; the fixture JSON is
already under `fixtures/clients/`. Record the exact browser version and
platform on the issue when you file the capture.

Fixture provenance lives in the JSON itself: schema, label, captured_at,
peer address, raw hex, ja4, ja4_r, and the parsed fields. The raw bytes are
the strong gate; JA4 is the tripwire.

## Adding a client family

Capture locally with peek.py, fetch
`https://tls.peet.ws/api/all` with the same client pointed at the real
internet, and drop the trimmed response into `fixtures/oracle/<label>.json`
with the same base name. If the two JA4 strings diverge, the parser has a
bug: file it before adding the pair.

The h2 SETTINGS half of the capture story (connection preface frame, sent
field order) needs a terminating h2 server and is not built yet; see issue
#1.

## Capture the rustls baseline

`crates/handshake-probe` drives the pinned rustls through a real handshake,
so the baseline we patch away from is on record too. Build it with
`cd crates/handshake-probe && cargo build` (it path-depends on the rustls the
apply-rustls pipeline unpacks), then:

```sh
python3 tools/capture/peek.py --port 18444 --out fixtures/clients --label rustls-baseline &
sleep 1  # wait for the listener
./target/debug/handshake-probe local tls.peet.ws 18444
# same build, live oracle view:
./target/debug/handshake-probe live tls.peet.ws 443 /api/all
```

The capture-mode verifier accepts any server (peek.py never completes the
handshake) but advertises exactly the signature schemes the live WebPKI
verifier does, so both ClientHellos hash identically. The committed pair
`fixtures/{clients,oracle}/rustls-baseline.json` is that proof: the local
capture and the live server view agree on
`t13d101000_61a7ad8aa9b6_3fcd1a44f3e3` (the oracle note records peet's
one-zero ALPN rendering and the spec's `00` form).

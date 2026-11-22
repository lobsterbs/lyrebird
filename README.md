```
       \\
       (o>
    \\_//)
     \_/_)
```

# lyrebird

Lyrebird teaches rustls to speak with a real browser's voice.

The lyrebird copies other birds' calls so accurately that the originals answer
back. That is the standard here: a site that fingerprints TLS should read one of
our handshakes as its own regular visitor, not as a robot.

## Why this exists

Stock rustls ends TLS with an honest, unmistakable fingerprint: no GREASE
values, a rustls-specific shuffled extension order, no X25519MLKEM768 key
share, no ALPS, no
compress_certificate negotiation, and rustls ordering of cipher suites and
signature algorithms. Sites that fingerprint TLS gate on exactly these tells
before any page loads. DuckDuckGo refuses the stock shape outright, and the
Cloudflare-class risk gates score it below a real client even before IP
reputation enters the picture.

Importing a patched Chrome TLS stack is not an option either: the BoringSSL
family does not build to wasm32, and the client runs in the browser. So parity
has to come from rustls itself, tell by tell.

## What "done" means

A profile is finished when its handshake reproduces the following, asserted
byte by byte against pinned captures of the real browser:

| Tell | Where |
|---|---|
| GREASE values at the ClientHello bookends and in supported_versions | ClientHello |
| Chrome extension order with PSK-mode extensions last, permutation family matched | ClientHello extensions |
| application_settings (ALPS) with Chromium's encoding | extensions |
| compress_certificate with brotli | extensions |
| X25519MLKEM768 key share | key_share |
| Chrome cipher suite order and signature_algorithms order | ClientHello |
| Chrome SETTINGS frame: field order, values, WINDOW_UPDATE behavior | h2 |

JA4 parity against tls.peet.ws is the CI tripwire, not the definition of done.
JA4 is lossy, and gating services classify on more than it encodes. The pinned
raw captures are the strong gate.

## Approach

- A vendored rustls fork carrying small, documented patches to ClientHello
  construction and record behavior (`tools/apply-rustls.sh`, `patches/`),
  with every optional tell driven by profile data rather than hardcoded.
- h2 SETTINGS shaping at the hyper/h2 layer.
- Profiles ship as data, none is enabled by default. Fingerprint profiles stay
  opt-in unless a site lane needs one.
- Downstream seam: an `EpoxyIdentity` option threaded through epoxy-tls's
  `EpoxyClientOptions`, so an embedding engine selects a profile the same way
  it selects a user agent.
- CI gates: unit tests asserting bytes against the pinned fixtures, plus a JA4
  check against tls.peet.ws with each profile's pinned expected string.

## Status

Seeded 2026-11-22. Shipped so far: the [#1](../../issues/1) capture harness
(`tools/capture` builds JA4 from real ClientHellos, fixtures verified against
the tls.peet.ws oracle), the [#2](../../issues/2) patch pipeline with its
baseline CI (pinned rustls v/0.23.46, native and wasm32 checks green), and
the [#3](../../issues/3) first ClientHello patch:
`0001-clienthello-grease-profile.patch` adds a data-driven
`ClientHelloProfile` (RFC 8701 GREASE bookends plus preference orders for
cipher suites, signature schemes, and named groups, applied per connection
through `ClientConfig::with_client_hello_profile`). The wire proof is
committed: the `rustls-grease` fixture pair shows the GREASE first cipher,
first extension, and first supported version on the wire, live-verified
against tls.peet.ws, with JA4 unchanged from the baseline
(`t13d101000_61a7ad8aa9b6_3fcd1a44f3e3`). No order is claimed from memory:
profile order data lands only when pinned captures of real browsers exist.
The first real order data landed on 2026-11-22: tls.peet.ws captures of
Brave (Chromium 158) and Firefox 160 on Windows supplied the wire order
slices for cipher suites, signature algorithms, and named groups. The raw
capture JSONs stay out of the repo by the operator's choice; the derived
order slices ship as code in the probe
(`crates/handshake-probe/src/profiles.rs`, frozen by unit tests) and drive
new `brave-*` / `firefox-*` probe modes on the aws-lc-rs provider, which
puts X25519MLKEM768 first in supported_groups. Local captures against the
harness prove exact wire-order parity for every value the provider offers
(Brave: GREASE bookends then `1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8`;
Firefox: `1301,1303,1302,c02b,c02f,cca9,cca8,c02c,c030`, no GREASE), and
both live modes handshake HTTP 200 against tls.peet.ws with the MLKEM
key share first. Honest gaps remain, all tracked in [#4](../../issues/4):
the provider offers 9 suites where the browsers offer 15, rustls then
still appended the SCSV and a few aws-lc verifier schemes the browsers
do not list (both dropped later by the set contract), and
the extension set and its order are still rustls-native (no ALPS, no
compress_certificate, no ECH offer). [#5](../../issues/5) keeps the
Firefox-specific remainder and [#6](../../issues/6) the EpoxyIdentity seam
and parity gate.

The extension layer landed next, on 2026-11-22: the probe's profiles
grew a pinned extension order, verbatim static extensions, trailing
GREASE bookends, and a native GREASE-ECH offer, all capture-derived
(`0002-clienthello-browser-profiles.patch`). Two wire corrections came
out of reading the captures instead of the RFC: the leading GREASE
extension is gone (captured browsers keep GREASE at the tail; the old
leading slot went away along with a double-encoding bug in the first
GREASE patch), and the pinned order is also the set contract: native
extensions the captured hello does not carry are dropped, so Firefox
sends no session_ticket and Brave carries ALPS (0x44cd as peet printed
it), SCT, EMS, compress_certificate (brotli for Brave, zlib+brotli for
Firefox), and renego exactly where the captures put them, with both
wires proven byte-order-exact against the harness and live-verified
HTTP 200 against tls.peet.ws (extension count parity with real Brave:
16 plus two trailing GREASE; the peet oracle renders the same order and
JA4 as our own captures, committed as the `lyrebird-brave` /
`lyrebird-firefox` fixture families). The h2 shape joined as data too:
`tools/capture/h2shapes.py` pins both browsers' SETTINGS payloads,
WINDOW_UPDATE values, and pseudo-header orders, gated by the akamai
fingerprint hashes (md5 of the fingerprint string, preimage proven).
Honest gaps: Firefox's captured pre_shared_key is not emitted because
honest session state does not exist and an empty offer was proven
rejected by a live server (unexpected_message; extension count 16 vs
the capture's 17), Firefox-only 0203/0201 signature schemes are not
offerable, the provider still offers 9 of the browsers' 15 cipher suites,
and Firefox's zstd compression algorithm has no rustls decompressor.

The pin lists are now literal set contracts, not just order overrides
(`pin_by_preference` in 0002): a value the captured browser does not
offer is dropped from our wire. That closed the last non-hardware tells
in the signature-algorithms and extension lists — rustls's 00ff SCSV
artifact and the aws-lc verifier leftovers (0603/0807 and the 0x09xx
family the browsers do not list) are gone when a cipher pin is active,
and our Brave JA4 extension+signature part is byte-identical to the
real capture (`806a8c22fdea`, the same hash peet computed for the real
browser; the entire signature list matches entry for entry). The
remaining JA4 diffs against the real captures are frozen in the harness
parity ledger (`tools/capture/test_clienthello.py`, `ParityLedger`):
cipher count 9 vs 15 and the cipher hash (provider availability), the
two Firefox schemes the provider cannot sign, and Firefox's p-521
group. The h2 engine path is now proven 1:1 end to end: the probe grew
`brave-h2-live` / `firefox-h2-live` modes (a hand-rolled HTTP/2 client,
no new dependencies, byte contracts in
`crates/handshake-probe/src/h2shape.rs`) that sent
`1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`
(hash `52d84b11737d980aef856699f885ca86`) for Brave and
`1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s`
(hash `6ea73faa8fc5aac76bded7bd238f6433`) for Firefox against
tls.peet.ws — exactly the captured browsers' akamai fingerprints,
HEADERS priority included. CI is strict end to end: patches apply with
`--fuzz=0` against the pinned tarball, the harness discovers every
`test_*.py`, probe unit tests freeze the profile data and the exact
frame bytes, and the release build (the binary all captures are taken
with) is itself gated.

## Known constraints

- BoringSSL does not build to wasm32, so byte parity comes from patched rustls
  only.
- The X25519MLKEM768 ask is provider work: rustls 0.23.46 builds it only with
  the aws-lc-rs provider (`prefer-post-quantum`). Settled by experiment
  (evidence on #3, 2026-11-22): a native handshake against tls.peet.ws
  succeeds with X25519MLKEM768 offered first (peetprint `4588-29-23-24`), and
  the same feature set checks clean for wasm32-unknown-unknown (aws-lc-sys
  0.47.0; the C toolchain must provide libc headers for wasm32, zig cc's wasi
  libc works, freestanding headers alone do not). Caveat: switching providers
  is a bigger fingerprint event than the one extension, the aws-lc verifier
  offers a different signature-scheme list (12 values vs ring's 9) and that
  alone moves JA4's signature part.
- rustls is Apache-2.0 OR MIT OR ISC, and this fork keeps that licensing.
- epoxy-tls is AGPL-3.0-only. A combined wasm bundle that links epoxy-tls with
  lyrebird inherits AGPL-3.0, and the source-offering duty applies when it
  ships. This repo by itself distributes rustls patches only.

## Related

- [MercuryWorkshop/epoxy-tls](https://github.com/MercuryWorkshop/epoxy-tls):
  upstream epoxy, the wasm TLS transport these profiles are shaped for.
- [lobsterbs/epoxy-tls](https://github.com/lobsterbs/epoxy-tls): our fork of
  upstream, the development base for the EpoxyIdentity seam.
- [lobsterbs/LobsterBrowse](https://github.com/lobsterbs/LobsterBrowse): the
  product surface.

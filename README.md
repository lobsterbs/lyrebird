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
values, a fixed extension order, no X25519MLKEM768 key share, no ALPS, no
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
the tls.peet.ws oracle) and the [#2](../../issues/2) patch pipeline with its
baseline CI (pinned rustls v/0.23.46, zero patches, native and wasm32 checks
green). The baseline shape itself is pinned too: `crates/handshake-probe`
performed a live handshake against tls.peet.ws and the committed
`rustls-baseline` fixture matches the server-side view
(`t13d101000_61a7ad8aa9b6_3fcd1a44f3e3`). Next on the roadmap:
[#3](../../issues/3) the Chrome ClientHello
extension layer, [#4](../../issues/4) Chrome advanced tells,
[#5](../../issues/5) the Firefox profile, [#6](../../issues/6) the
EpoxyIdentity seam and parity gate.

## Known constraints

- BoringSSL does not build to wasm32, so byte parity comes from patched rustls
  only.
- The X25519MLKEM768 key share depends on a crypto provider that implements
  ML-KEM; the wasm32 feasibility of such a provider is an open question in the
  baseline milestone, not a settled fact.
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

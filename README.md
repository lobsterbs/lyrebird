```
       \\
       (o>
    \\_//)
     \_/_)
```

# lyrebird

Lyrebird teaches rustls to speak with a real browser's voice.

Stock rustls handshakes with an unmistakable fingerprint: no GREASE, a
rustls-shuffled extension order, no X25519MLKEM768 key share, no ALPS, no
compress_certificate, rustls-native cipher and signature ordering.
Fingerprinting sites gate on exactly these tells before any page loads,
DuckDuckGo refuses the stock shape outright, and the BoringSSL family does
not build to wasm32. So parity comes from rustls itself, tell by tell.

## Done means

A profile reproduces the real browser's handshake byte for byte against
pinned captures of that browser, never from memory: GREASE bookends,
extension set and order, ALPS, compress_certificate, the MLKEM key share,
cipher and signature orders, and the h2 SETTINGS / WINDOW_UPDATE / priority
shape. JA4 against tls.peet.ws is the CI tripwire, not the definition of
done; the pinned captures are the strong gate.

## Approach

- Vendored rustls v/0.23.46 with small, documented patches (`patches/`,
  applied by `tools/apply-rustls.sh`). Every optional tell is data, none
  hardcoded.
- Profile data lives in the patched rustls as
  `rustls::client::browser_profiles` (patch `0003`); the probe
  (`crates/handshake-probe`) and embedding engines read one frozen copy.
- Profiles are data and never default. Downstream selects one through
  epoxy's `EpoxyIdentity` the same way it selects a user agent.
- CI gates: `patch --fuzz=0` against the pinned tarball, capture-harness
  byte tests, probe unit tests on the frozen profile data, native + wasm32
  checks, and the live JA4 tripwire.

## Status

Brave (Chromium 158) and Firefox 160 profiles shipped, live-verified
against tls.peet.ws. With a profile active:

- Extension set/order and signature list match the real Brave capture:
  JA4 tail `9682305a41b3` (Firefox: `d7d6985f8b1a`), signature list
  entry-for-entry. The tails changed from the 2026-11-22 capture tails
  (`806a8c22fdea` / `ba4afa82cbcb`) after the 2026-11-25 structural-gap
  fix below.
- h2 shape is 1:1 with both real browsers, priority frames included:
  Brave akamai fingerprint
  `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`
  (hash `52d84b11737d980aef856699f885ca86`), Firefox
  `1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s`
  (hash `6ea73faa8fc5aac76bded7bd238f6433`).
- The epoxy seam is live: `EpoxyIdentity` in our epoxy fork shapes real
  handshakes, gated nightly by its live-parity workflow.

Honest gaps stay frozen in the parity ledger
(`tools/capture/test_clienthello.py`). Structural extension gaps,
verdicts recorded live 2026-11-25: rustls cannot offer ALPS
(0x44cd) or CertificateEntry SCT lists (0x0012) in the static
extensions, and Delegated Credentials (0x0022) cannot be offered
without a verifier for them. Offering any of them aborts real-server
handshakes: google.com negotiates ALPS and expects a client
EncryptedExtensions back (rustls aborts), Cloudflare-fronted edges
send delegated credentials rustls 0.23.46 cannot verify, and SCT
invites a certificate entry extension rustls rejects. All three stay
pinned in the capture-truth order lists as a visible ledger but are
not emitted. CI parity against tls.peet.ws never caught this because
peet does not actively parse those extensions; probes now also cover
real servers. Provider and profile remainders live on
[#4](../../issues/4), [#5](../../issues/5) and [#6](../../issues/6).

## Known constraints

- BoringSSL does not build to wasm32; byte parity comes from patched
  rustls only.
- X25519MLKEM768 is aws-lc-rs-only (`prefer-post-quantum`), proven native
  and wasm32-checkable. Provider choice is itself a fingerprint event:
  aws-lc's verifier lists 12 signature schemes vs ring's 9.
- GREASE values vary per connection by design (RFC 8701), as they do in
  the real browsers.
- rustls is Apache-2.0 OR MIT OR ISC; the patches keep that. epoxy-tls is
  AGPL-3.0-only, so a combined wasm bundle inherits AGPL; this repo
  distributes rustls patches only.

## Related

- [MercuryWorkshop/epoxy-tls](https://github.com/MercuryWorkshop/epoxy-tls):
  upstream epoxy, the wasm TLS transport these profiles are shaped for.
- [lobsterbs/epoxy-tls](https://github.com/lobsterbs/epoxy-tls): our
  fork carrying the active `EpoxyIdentity` seam.
- [lobsterbs/LobsterBrowse](https://github.com/lobsterbs/LobsterBrowse):
  the product surface.

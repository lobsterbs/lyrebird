# lyrebird

Patched rustls that speaks a real browser's TLS and HTTP/2 identity. Named for the bird that copies other species' calls accurately enough to fool the originals; the goal here is the same standard: a browser should not be able to tell our ClientHello from its own.

## What problem this solves

The Zeolite engine's epoxy transport terminates TLS with stock rustls. Stock rustls has an honest but unmistakable fingerprint: no GREASE values, a fixed extension order, no X25519MLKEM768 key share by default, no ALPS, no compress_certificate negotiation, and rustls ordering of cipher suites and signature_algorithms. Some sites gate on exactly these tells before any page loads. DuckDuckGo refuses the stock shape outright, and the Cloudflare-class risk gates score it below a real client even before IP reputation enters the picture.

The BoringSSL route (patched Chrome TLS stacks in the impersonate-rs family) is not an option here: BoringSSL does not build to wasm32, and epoxy runs in the browser. Parity therefore has to come from rustls itself, tell by tell.

## Done means: verified real-browser tells

A profile is finished when its handshake reproduces the following, asserted against pinned captures of the real browser:

| Tell | Where |
|---|---|
| GREASE values at the ClientHello bookends and in supported_versions | ClientHello |
| Chrome extension order with PSK-mode extensions last, permutation family matched | ClientHello extensions |
| application_settings (ALPS) with Chromium's encoding | extensions |
| compress_certificate with brotli | extensions |
| X25519MLKEM768 key share | key_share |
| Chrome cipher suite order and signature_algorithms order | ClientHello |
| Chrome SETTINGS frame: field order, values, WINDOW_UPDATE behavior | h2 |

JA4 parity against tls.peet.ws is the CI tripwire, not the definition of done. JA4 is lossy, and gating services classify on more than it encodes. The pinned raw captures are the strong gate.

## Approach

- A vendored rustls fork carrying small, documented patches to ClientHello construction and record-layer behavior, with every optional tell driven by profile data.
- h2 SETTINGS shaping at the hyper/h2 layer.
- Profiles ship as data and none is default, matching the standing engine policy: fingerprint profiles are opt-in, off unless a site lane needs one.
- Downstream seam: a `EpoxyIdentity` option threaded through epoxy-tls's `EpoxyClientOptions`, so an embedding engine selects a profile the same way it selects a user agent.
- CI gates: unit tests asserting bytes against the pinned fixtures, plus a JA4 check against tls.peet.ws with each profile's pinned expected string.

## Constraints

- BoringSSL does not build to wasm32; byte parity comes from patched rustls only.
- The X25519MLKEM768 key share depends on a crypto provider that implements ML-KEM; the wasm feasibility of such a provider is part of the baseline milestone, not settled yet.
- rustls is Apache-2.0 OR MIT OR ISC, and this fork keeps that licensing.
- epoxy-tls is AGPL-3.0-only. A combined wasm bundle that links epoxy-tls with lyrebird inherits AGPL-3.0, and the source-offering duty applies when it ships. This repo by itself distributes rustls patches only.

## Status

Seeded 2026-11-22. No code yet. The roadmap lives in the issues, in creation order: reference captures, a wasm-green rustls fork baseline, the Chrome extension layer, Chrome advanced tells (ALPS, compress_certificate, SETTINGS shape), the Firefox profile, and the EpoxyIdentity seam with the parity gate.

## Related

- lobsterbs/Zeolite: the engine whose epoxy transport consumes this.
- lobsterbs/LobsterBrowse: the product surface.

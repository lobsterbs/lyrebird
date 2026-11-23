# Patches

Each `NNNN-*.patch` file here is applied to `vendor/rustls/` in
lexicographic order by `tools/apply-rustls.sh`. With no patches the
pipeline must still pass CI: that is the baseline proof for issue #2
(vendored rustls 0.23.x, client feature set, builds for native and
wasm32-unknown-unknown with the ring provider).

Patches in this directory are what turn baseline rustls into the lyrebird
ClientHello shaping work of issues #3 and #4. Keep them small, one concern per
patch, and ordered so each applies on top of the previous one. 0003 moves the
capture-derived browser profile DATA into the patched rustls itself
(`rustls::client::browser_profiles`) so embedding engines (epoxy) consume one
frozen copy instead of duplicating the slices.

`tools/apply-rustls.sh` applies every patch with `--fuzz=0` against the
pinned tarball, so a patch that no longer applies byte-clean must be
regenerated rather than fuzzed in. Regenerate with
`tools/gen_patch.py <pristine-plus-0001> <patched-tree> <out.patch>`; the
result reproduces the vendored tree byte-identically (verified locally
2026-11-22 by walking both trees after a from-scratch double apply).

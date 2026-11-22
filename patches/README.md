# Patches

Each `NNNN-*.patch` file here is applied to `vendor/rustls/` in
lexicographic order by `tools/apply-rustls.sh`. With no patches the
pipeline must still pass CI: that is the baseline proof for issue #2
(vendored rustls 0.23.x, client feature set, builds for native and
wasm32-unknown-unknown with the ring provider).

Patches in this directory are what turn baseline rustls into the lyrebird
ClientHello shaping work of issues #3 and #4. Keep them small, one concern per
patch, and ordered so each applies on top of the previous one.

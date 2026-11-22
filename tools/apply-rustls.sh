#!/bin/sh
# Fetch a pinned rustls source tarball, unpack it under vendor/rustls/, and
# apply every patch in patches/ in lexicographic order. Zero patches means
# the baseline pipeline: the vendored tree must build unchanged.
#
# Run from the repo root: sh tools/apply-rustls.sh
# Override the pin with RUSTLS_TAG (tag format used by rustls: v/<version>).

set -eu

RUSTLS_TAG="${RUSTLS_TAG:-v/0.23.46}"
DEST="vendor/rustls"
ARCHIVE="$(mktemp)"

if [ -d "$DEST" ] && [ -n "$(ls -A "$DEST" 2>/dev/null)" ]; then
    echo "apply-rustls: $DEST already populated, nothing to do"
    exit 0
fi

mkdir -p vendor
echo "apply-rustls: fetching rustls $RUSTLS_TAG"
curl -fsSL "https://codeload.github.com/rustls/rustls/tar.gz/refs/tags/$RUSTLS_TAG" -o "$ARCHIVE"
tar -xzf "$ARCHIVE" -C vendor

# codeload names the top-level directory <repo>-<tag>, with / in the tag
# mapped to -
ROOT_DIR="$(printf 'rustls-%s' "$RUSTLS_TAG" | tr '/' '-')"
mv "vendor/$ROOT_DIR" "$DEST"

applied=0
for patch_file in patches/*.patch; do
    [ -e "$patch_file" ] || continue
    echo "apply-rustls: applying $patch_file"
    # strict: no fuzz, no offset drift tolerated; a patch that no longer
    # applies byte-clean against the pinned tarball must be regenerated
    patch -d "$DEST" -p1 --fuzz=0 < "$patch_file"
    applied=$((applied + 1))
done

echo "apply-rustls: done ($applied patch(es) applied)"

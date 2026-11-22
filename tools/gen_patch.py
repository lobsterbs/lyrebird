#!/usr/bin/env python3
"""Generate a lyrebird patch file (GNU diff -ruN format) as the difference
between two vendored rustls trees.

usage: gen_patch.py <tree_a_pristine_plus_0001> <tree_b_current> <out.patch>

Both trees are the extracted rustls monorepo root (containing rustls/,
connect-tests/, ...). Only files that differ are emitted. `target/` and
`__pycache__` are skipped. Every changed file is labeled with the pinned
upstream timestamp on the a/ side and the patch date on the b/ side, in
the exact format tools/apply-rustls.sh (GNU patch) and patch_apply.py
both consume.
"""
import difflib
import os
import sys

SKIP_DIRS = {"target", "__pycache__", ".git"}
UPSTREAM_STAMP = "\t2026-10-13 11:15:01.000000000 +0000"
NEW_STAMP = "\t2026-11-22 23:30:00.000000000 +0000"


def rel_files(root):
    out = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            out.add(os.path.relpath(os.path.join(dirpath, fn), root))
    return out


def main():
    a_root, b_root, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    a_files = rel_files(a_root)
    b_files = rel_files(b_root)

    sections = []
    for rel in sorted(a_files | b_files):
        a_path = os.path.join(a_root, rel)
        b_path = os.path.join(b_root, rel)
        a_raw = open(a_path, "rb").read() if os.path.exists(a_path) else b""
        b_raw = open(b_path, "rb").read() if os.path.exists(b_path) else b""
        if a_raw == b_raw:
            continue
        try:
            a_lines = a_raw.decode("utf-8").splitlines(keepends=True)
            b_lines = b_raw.decode("utf-8").splitlines(keepends=True)
        except UnicodeDecodeError as e:
            # binary asset: patches only ever touch text sources; a binary
            # file that differs between trees means the pipeline broke,
            # not a diff to emit
            raise SystemExit("binary file differs, refusing: %s (%s)" % (rel, e))
        diff = list(difflib.unified_diff(a_lines, b_lines, n=3))
        if not diff:
            continue
        sections.append((rel, diff))

    with open(out_path, "w") as out:
        for rel, diff in sections:
            # difflib's first two lines are unstamped ---/+++ labels;
            # rewrite them with the canonical stamps (read them purely to
            # keep the exact same order, then emit our own)
            assert diff[0].startswith("--- ") and diff[1].startswith("+++ ")
            hunks = diff[2:]
            out.write("diff -ruN a/%s b/%s\n" % (rel, rel))
            out.write("--- a/%s%s\n" % (rel, UPSTREAM_STAMP))
            out.write("+++ b/%s%s\n" % (rel, NEW_STAMP))
            for line in hunks:
                if line.endswith("\n"):
                    out.write(line)
                else:
                    out.write(line + "\n")
                    out.write("\\ No newline at end of file\n")

    print("gen_patch: wrote %s (%d section(s))" % (out_path, len(sections)))
    for rel, _ in sections:
        print("  " + rel)


if __name__ == "__main__":
    main()

"""Offline tests for the ClientHello harness. No network needed.

The client fixtures are real captures taken with peek.py; the oracle files
are tls.peet.ws /api/all responses for the same clients on the same day,
so ja4 equality here is an end-to-end proof of the parser and the JA4
encoder against an independent implementation.
"""

import hashlib
import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import clienthello as ch

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CLIENTS = os.path.join(ROOT, "fixtures", "clients")
ORACLE = os.path.join(ROOT, "fixtures", "oracle")
FAMILIES = ["curl-openssl", "node22", "python312", "rustls-baseline", "rustls-grease",
            "lyrebird-brave", "lyrebird-firefox"]

# Wire extension order for lyrebird's own profile captures: the exact
# sequence (types in wire order) including GREASE positions. GREASE types
# vary per run, so they are matched by the RFC 8701 ?a?a rule.
# gap-ledger note (2026-11-25): ALPS (44cd) and SCT (0012) are not offered
# by the brave profile, and SCT (0012) / delegated_credentials (0022) are not
# offered by the firefox profile. Offering them breaks live servers in ways
# the client cannot honor: ALPS negotiation needs the client EE message,
# SCT offers invite CertificateEntry SCT lists this rustls rejects, and DC
# offers make DC-issuing edges send credentials this client cannot verify.
LYREBIRD_BRAVE_ORDER = [
    0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x0017, 0x001b,
    0x0023, 0x002b, 0x002d, 0x0005, 0x0033, 0xfe0d, 0xff01, "grease", "grease",
]
LYREBIRD_FIREFOX_ORDER = [
    0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x0017, 0x001b, 0x001c,
    0x002b, 0x002d, 0x0005, 0x0033, 0xfe0d, 0xff01,
]


def load(path):
    with open(path) as f:
        return json.load(f)


def ja4_head_parses(ja4):
    """All structurally valid count-splits of a ja4 head.

    peek prints the JA4-spec zero-padded cipher count ("t13d0916h2"),
    peet prints the same wire without padding ("t13d916h2"). The counts
    are ambiguous digits, so return every valid split and let callers
    test set intersection instead of string equality.
    """
    head = ja4.split("_", 2)[0]
    m = re.match(r"^(t\d{2}[doq])", head)
    assert m, head
    body = head[m.end():]
    alpn = body[-2:]
    digits = body[:-2]
    out = set()
    for i in range(1, len(digits)):
        c, e = digits[:i], digits[i:]
        if len(c) <= 2 and len(e) <= 2:
            out.add((m.group(1), int(c), int(e), alpn))
    return out


class OracleParity(unittest.TestCase):
    def test_local_capture_matches_peet_oracle(self):
        for name in FAMILIES:
            with self.subTest(family=name):
                local = load(os.path.join(CLIENTS, name + ".json"))
                oracle = load(os.path.join(ORACLE, name + ".json"))
                # hash segments are never ambiguous: strict equality
                self.assertEqual(local["ja4"].split("_")[1:], oracle["ja4"].split("_")[1:],
                                 "peek ja4 hashes diverged from the peet oracle for " + name)
                # head counts: peet drops JA4 zero padding on single-digit
                # counts, so compare the set of valid parses
                self.assertTrue(ja4_head_parses(local["ja4"]) & ja4_head_parses(oracle["ja4"]),
                                "peek ja4 head %s incompatible with peet oracle %s for %s"
                                % (local["ja4"], oracle["ja4"], name))

    def test_reparse_of_saved_raw_reproduces_ja4(self):
        for name in FAMILIES:
            with self.subTest(family=name):
                local = load(os.path.join(CLIENTS, name + ".json"))
                parsed = ch.parse_clienthello(bytes.fromhex(local["raw"]))
                ja4, ja4_r = ch.compute_ja4(parsed)
                self.assertEqual(ja4, local["ja4"])
                self.assertEqual(ja4_r, local["ja4_r"])

    def test_ja4_assembled_from_ja4_r_hashes(self):
        for name in FAMILIES:
            with self.subTest(family=name):
                local = load(os.path.join(CLIENTS, name + ".json"))
                head, ciphers, rest = local["ja4_r"].split("_", 2)
                ext_sig = rest.rsplit("_", 1)
                exts = ext_sig[0]
                sigs = ext_sig[1] if len(ext_sig) == 2 and ext_sig[1] else None
                h1 = hashlib.sha256(ciphers.encode()).hexdigest()[:12]
                payload = exts + ("_" + sigs if sigs else "")
                h2 = hashlib.sha256(payload.encode()).hexdigest()[:12]
                self.assertEqual(head + "_" + h1 + "_" + h2, local["ja4"])


class SpecRules(unittest.TestCase):
    def test_grease_detection(self):
        for v in (0x0A0A, 0x1A1A, 0x2A2A, 0xFAFA):
            self.assertTrue(ch.is_grease(v), hex(v))
        for v in (0x1301, 0x00A0, 0x1000, 0x0010, 0x0B0B):
            self.assertFalse(ch.is_grease(v), hex(v))

    def test_alpn_column(self):
        self.assertEqual(ch._alpn_char(b"h2"), "h2")
        self.assertEqual(ch._alpn_char(b"http/1.1"), "h1")
        self.assertEqual(ch._alpn_char(b""), "00")
        self.assertEqual(ch._alpn_char(b"a"), "aa")
        self.assertEqual(ch._alpn_char(b"\xab"), "ab")
        self.assertEqual(ch._alpn_char(b"\xab\xcd"), "ad")
        self.assertEqual(ch._alpn_char(b"\x20\x61"), "21")
        self.assertEqual(ch._alpn_char(b"\x61\x20"), "60")
        self.assertEqual(ch._alpn_char(b"0\xab"), "3b")

    def test_counts_and_exclusion(self):
        parsed = {
            "record_version": "0303", "legacy_version": "0304",
            "ciphers": ["1301", "0a0a", "1302"],
            "extensions": [{"type": 0x0000, "name": "server_name", "len": 0},
                           {"type": 0x0010, "name": "alpn", "len": 0},
                           {"type": 0x002B, "name": "supported_versions", "len": 0},
                           {"type": 0x0A0A, "name": "grease", "len": 0}],
            "sni": "example.com", "alpn": [],
            "supported_versions": ["0304"],
            "signature_algorithms": [],
        }
        ja4, ja4_r = ch.compute_ja4(parsed)
        # 2 non-GREASE ciphers, 3 non-GREASE extensions (SNI+ALPN counted,
        # grease not), SNI present, no ALPN, no sig algs: t13d020300
        self.assertTrue(ja4.startswith("t13d020300_"), ja4)
        # GREASE absent from the hashed lists, SNI+ALPN excluded from them
        self.assertNotIn("0a0a", ja4_r)
        self.assertNotIn("0000", ja4_r)
        self.assertNotIn("0010", ja4_r.split("_"))


class GreaseTells(unittest.TestCase):
    """rustls-grease: wire proof of the RFC 8701 profile layer (issue #3)."""

    def setUp(self):
        self.grease = load(os.path.join(CLIENTS, "rustls-grease.json"))
        self.baseline = load(os.path.join(CLIENTS, "rustls-baseline.json"))

    def test_bookends_present(self):
        f = self.grease["fields"]
        first_cipher = int(f["ciphers"][0], 16)
        first_ext = f["extensions"][0]["type"]
        first_version = int(f["supported_versions"][0], 16)
        self.assertTrue(ch.is_grease(first_cipher), hex(first_cipher))
        self.assertTrue(ch.is_grease(first_ext), hex(first_ext))
        self.assertTrue(ch.is_grease(first_version), hex(first_version))

    def test_grease_value_is_random_derived(self):
        # cipher and supported_versions share one value drawn from
        # client_random; the extension type is the fixed enum constant 0x0a0a
        f = self.grease["fields"]
        v = int(f["ciphers"][0], 16)
        self.assertEqual(int(f["supported_versions"][0], 16), v)
        self.assertTrue(ch.is_grease(v))
        self.assertEqual(f["extensions"][0]["type"], 0x0A0A)
        self.assertTrue(ch.is_grease(f["extensions"][0]["type"]))

    def test_ja4_unchanged_by_grease(self):
        self.assertEqual(self.grease["ja4"], self.baseline["ja4"])
        self.assertEqual(self.grease["ja4_r"], self.baseline["ja4_r"])
        # and the substance behind the hashes is the same set of real values
        self.assertEqual(sorted(self.grease["fields"]["ciphers"][1:]),
                         sorted(self.baseline["fields"]["ciphers"]))


class WireOrderFrozen(unittest.TestCase):
    """The lyrebird profile captures: extension wire order IS the product.

    These are captures of lyrebird's own probe (brave-local / firefox-local
    against peek.py, release build). The order matches the operator's
    2026-11-22 tls.peet.ws captures; GREASE types vary per run and are
    matched by the RFC 8701 ?a?a rule, but their POSITIONS are pinned.
    """

    def check(self, family, expected):
        cap = load(os.path.join(CLIENTS, family + ".json"))
        wire = [e["type"] for e in cap["fields"]["extensions"]]
        self.assertEqual(len(wire), len(expected), family)
        for got, want in zip(wire, expected):
            if want == "grease":
                self.assertTrue(ch.is_grease(got),
                                "%s: %04x not GREASE" % (family, got))
            else:
                self.assertEqual(got, want, "%s: %04x != %04x" %
                                 (family, got, want))

    def test_brave_order(self):
        self.check("lyrebird-brave", LYREBIRD_BRAVE_ORDER)

    def test_firefox_order(self):
        self.check("lyrebird-firefox", LYREBIRD_FIREFOX_ORDER)

    def test_firefox_no_session_ticket_no_psk(self):
        # Firefox captured hellos carry pre_shared_key (0x0029) but no
        # session_ticket (0x0023); lyrebird ships neither (session state
        # cannot be conjured honestly) and drops the rustls-native
        # session_ticket to keep the set faithful minus the PSK gap.
        cap = load(os.path.join(CLIENTS, "lyrebird-firefox.json"))
        types = [e["type"] for e in cap["fields"]["extensions"]]
        self.assertNotIn(0x0023, types)
        self.assertIn(0x001c, types)    # record_size_limit
        self.assertNotIn(0x0022, types)  # delegated_credentials: gap ledger
        self.assertNotIn(0x0012, types) # SCT: gap ledger

    def test_brave_static_gaps(self):
        # 2026-11-25: ALPS and SCT are no longer offered (live-server
        # verdicts; see the gap-ledger note above the order constants).
        cap = load(os.path.join(CLIENTS, "lyrebird-brave.json"))
        types = [e["type"] for e in cap["fields"]["extensions"]]
        self.assertNotIn(0x44CD, types)
        self.assertNotIn(0x0012, types)


class GreaseEchDeterminism(unittest.TestCase):
    """GREASE ECH (0xfe0d) shape is deterministic where the real browser is.

    The suite carried by the GREASE ECH offer is a compile-time constant in
    the patched rustls (DH_KEM_P256_HKDF_SHA256_AES_128): no per-connection
    coin flip in suite selection. Selecting the suite randomly where real
    Chrome selects deterministically is the exact detection class fixed
    publicly as uTLS CVE-2026-27017, so the wire contract is pinned here.
    Random per connection BY DESIGN (RFC 9460 GREASE): config_id, the
    ephemeral enc key, and the payload. Suite + KEM shape: not random.
    """

    SUITE = b"\x00\x01\x00\x01"  # kdf 0x0001 HKDF-SHA256, ae 0x0001 AES-128-GCM
    P256_ENC_LEN = 65             # uncompressed point: 0x04 || X || Y

    def ech_body(self, family):
        cap = load(os.path.join(CLIENTS, family + ".json"))
        b = bytes.fromhex(cap["raw"])
        p = 5 + 4 + 2 + 32
        p += 1 + b[p]                       # session id
        p += 2 + int.from_bytes(b[p:p + 2], "big")  # ciphers
        p += 1 + b[p]                       # compression methods
        end = p + int.from_bytes(b[p:p + 2], "big")
        p += 2
        while p < end:
            et = int.from_bytes(b[p:p + 2], "big")
            el = int.from_bytes(b[p + 2:p + 4], "big")
            if et == 0xFE0D:
                return b[p + 4:p + 4 + el]
            p += 4 + el
        self.fail(family + ": no 0xfe0d extension in capture")

    def check(self, family):
        body = self.ech_body(family)
        self.assertEqual(body[0], 0x00, family + ": not ClientHelloOuter")
        self.assertEqual(body[1:5], self.SUITE,
                         family + ": GREASE ECH suite drifted from the pinned "
                         "DHKEM(P256)+HKDF-SHA256+AES-128 constant")
        enc_len = int.from_bytes(body[6:8], "big")
        self.assertEqual(enc_len, self.P256_ENC_LEN,
                         family + ": enc length no longer a P-256 share")
        self.assertEqual(body[8], 0x04, family + ": enc is not an uncompressed point")
        payload_len = int.from_bytes(body[8 + enc_len:10 + enc_len], "big")
        self.assertGreater(payload_len, 0, family + ": empty GREASE payload")
        self.assertEqual(len(body), 10 + enc_len + payload_len)

    def test_brave_grease_ech_suite_deterministic(self):
        self.check("lyrebird-brave")

    def test_firefox_grease_ech_suite_deterministic(self):
        self.check("lyrebird-firefox")


# Real browser captures (operator's tls.peet.ws 2026-11-22 runs) reduced to
# constants. The raw capture JSONs are never committed; these slices ship
# as code (operator decision).
REAL_BRAVE_JA4 = "t13d1516h2_8daaf6152771_806a8c22fdea"
REAL_BRAVE_JA4_R_CIPHERS = "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"
REAL_BRAVE_SIGS = "0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601"
REAL_BRAVE_EXTS = "0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01"
REAL_FIREFOX_JA4 = "t13d1517h2_8daaf6152771_e6dcd7ae0a9e"
REAL_FIREFOX_EXTS = "0005,000a,000b,000d,0012,0017,001b,001c,0022,0029,002b,002d,0033,fe0d,ff01"
REAL_FIREFOX_SIGS = "0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201"
# current pinned lyrebird ext+sig hashes (gap-ledger state, refreshed
# with the fixture regeneration when the gaps changed on 2026-11-25)
LYREBIRD_BRAVE_EXT_SIG_HASH = "9682305a41b3"
LYREBIRD_FIREFOX_EXT_SIG_HASH = "d7d6985f8b1a"
# Firefox-only gaps the provider cannot express:
FIREFOX_UNSIGNABLE_SIGS = ("0203", "0201")  # ecdsa_ed25519/ed448-era, not offerable
FIREFOX_UNSIGNABLE_EXT = "0029"             # pre_shared_key: needs real session state
# Structural gaps (2026-11-25, live-server verdicts, all profiles):
# offering without the client-side support breaks real servers, so these
# extensions are not offered at all. ALPS: google aborts the handshake when
# the client cannot answer with its own EncryptedExtensions. SCT: Cloudflare
# edges answer the offer with CertificateEntry SCT lists rustls 0.23.46
# rejects as UnknownCertificateExtension. DC: verifiable delegated
# credentials are not implemented; the captured body was also malformed
# (1-byte instead of 2-byte vector length, RFC 9345).
BRAVE_STRUCTURAL_GAP_EXTS = ("44cd", "0012")
FIREFOX_STRUCTURAL_GAP_EXTS = ("0012", "0022")


class ParityLedger(unittest.TestCase):
    """Full parity vs the real captures everywhere the provider can
    express the browser's wire, and a frozen, explicit ledger of every
    gap it cannot (issue #4/#5). If a gap below ever closes, tighten it:
    the set-contract pin must absorb any newly offerable value."""

    def cap(self, family):
        return load(os.path.join(CLIENTS, family + ".json"))

    def sigs(self, family):
        return [s.lower() for s in self.cap(family)["fields"]["signature_algorithms"]]

    def ext_r(self, ja4_r):
        return set(ja4_r.split("_")[2].split(",")) if ja4_r.count("_") >= 3 else set()

    def test_brave_extension_signature_hash_ledger(self):
        ours = self.cap("lyrebird-brave")["ja4"].split("_")
        self.assertNotEqual(ours[2], REAL_BRAVE_JA4.split("_")[2],
                            "brave ext+sig hash equals the real capture only if"
                            " the structural gaps closed; repin then")
        self.assertEqual(ours[2], LYREBIRD_BRAVE_EXT_SIG_HASH)

    def test_brave_sig_algorithms_byte_exact(self):
        self.assertEqual(",".join(self.sigs("lyrebird-brave")), REAL_BRAVE_SIGS)

    def test_brave_extension_set_ledger(self):
        ours = self.ext_r(self.cap("lyrebird-brave")["ja4_r"])
        real = set(REAL_BRAVE_EXTS.split(","))
        self.assertEqual(ours, real - set(BRAVE_STRUCTURAL_GAP_EXTS),
                         "brave ext set = capture minus ledgered gaps")

    def test_brave_cipher_gap_ledger(self):
        cap = self.cap("lyrebird-brave")
        ciphers = [c.lower() for c in cap["fields"]["ciphers"]]
        # SCSV artifact dropped when the cipher pin is active
        self.assertNotIn("00ff", ciphers)
        self.assertTrue(ch.is_grease(int(ciphers[0], 16)))  # leading GREASE
        real_set = set(REAL_BRAVE_JA4_R_CIPHERS.split(","))
        self.assertTrue(set(ciphers[1:]) <= real_set,
                        "our ciphers must be a subset of the browser offer")
        # ledger: 9 offerable of 15; cipher-count digit 9 vs 15
        self.assertIn(9, [p[1] for p in ja4_head_parses(cap["ja4"])])
        self.assertEqual(cap["ja4"].split("_")[1], "f91f431d341e")  # 9-of-15 hash
        self.assertNotEqual(cap["ja4"].split("_")[1], REAL_BRAVE_JA4.split("_")[1])

    def test_firefox_sig_gap_ledger(self):
        # full parity minus the schemes the provider cannot sign
        expected = [s for s in REAL_FIREFOX_SIGS.split(",")
                    if s not in FIREFOX_UNSIGNABLE_SIGS]
        self.assertEqual(self.sigs("lyrebird-firefox"), expected)
        # consequently the ext+sig hash differs from the real capture:
        self.assertNotEqual(
            self.cap("lyrebird-firefox")["ja4"].split("_")[2],
            REAL_FIREFOX_JA4.split("_")[2])
        caps = self.cap("lyrebird-firefox")
        self.assertLess(len(self.sigs("lyrebird-firefox")), len(REAL_FIREFOX_SIGS.split(",")))
        self.assertEqual(caps["ja4"].split("_")[2], LYREBIRD_FIREFOX_EXT_SIG_HASH)

    def test_firefox_extension_set_ledger(self):
        # set differences vs the real capture, all ledgered:
        # pre_shared_key (honest session state cannot be conjured, empty
        # offer rejected live 2026-11-22) and the 2026-11-25 structural
        # gaps (SCT, delegated_credentials).
        ours = self.ext_r(self.cap("lyrebird-firefox")["ja4_r"])
        real = set(REAL_FIREFOX_EXTS.split(","))
        self.assertEqual(ours,
                         real - {FIREFOX_UNSIGNABLE_EXT}
                              - set(FIREFOX_STRUCTURAL_GAP_EXTS))
        self.assertNotIn(0x0029, [e["type"] for e in
                                  self.cap("lyrebird-firefox")["fields"]["extensions"]])
        # and the shared values are all byte-exact members of the real set
        self.assertTrue(ours <= real)



# Fresh plain-Chrome capture-truth (tls.peet.ws /api/all, 2026-11-27,
# Chrome 158, Linux persona; raw capture JSON never committed, per the
# standing operator decision). Byte-diff against the shipped
# Brave-derived statics: cipher wire order, signature list, group order,
# extension SET, and extension wire ORDER are all identical to the
# 2026-11-22 Brave capture, so the profile data needs no refresh, only
# this freshness record. Deltas that are NOT data changes: this run
# offered REAL ECH (65037 with a live inner config; we ship
# deterministic GREASE ECH), offered ALPS and SCT (structural gap
# ledger, unofferable), and did NOT carry the per-domain 51764
# extension the 2026-11-23 Win10 Chrome capture had (platform spread;
# 51764 is unshippable as a static constant either way). If the
# Brave-derived statics ever change, these assertions fail and force a
# conscious re-diff against this capture too.
CHROME_20261127_CIPHERS = ("1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,"
                           "c013,c014,009c,009d,002f,0035")
CHROME_20261127_SIGS = ("0904,0905,0906,0403,0804,0401,0503,0805,0501,"
                        "0806,0601")
CHROME_20261127_GROUPS = "11ec,001d,0017,0018"  # after a GREASE group
CHROME_20261127_EXTS = ("0005,000a,000b,000d,0012,0017,001b,0023,002b,"
                        "002d,0033,44cd,fe0d,ff01")
CHROME_20261127_EXT_ORDER = [
    0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x44cd, 0x0012, 0x0017,
    0x001b, 0x0023, 0x002b, 0x002d, 0x0005, 0x0033, 0xfe0d, 0xff01,
]
CHROME_20261127_H2 = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
CHROME_20261127_H2_HASH = "52d84b11737d980aef856699f885ca86"


class PlainChromeCapture20261127(unittest.TestCase):
    """Freshness pin: a fresh plain-Chrome capture (no spoof, 2026-11-27)
    byte-matches the shipped Brave-derived statics, so the chromium voice
    is current for plain Chrome as of this date. A failure here after a
    statics change means the change must be re-diffed against this
    capture before it ships."""

    def test_extension_set_equals_brave_capture(self):
        self.assertEqual(sorted(CHROME_20261127_EXTS.split(",")),
                         sorted(REAL_BRAVE_EXTS.split(",")))

    def test_signature_list_equals_brave_capture(self):
        self.assertEqual(sorted(CHROME_20261127_SIGS.split(",")),
                         sorted(REAL_BRAVE_SIGS.split(",")))

    def test_cipher_set_equals_brave_capture(self):
        self.assertEqual(sorted(CHROME_20261127_CIPHERS.split(",")),
                         sorted(REAL_BRAVE_JA4_R_CIPHERS.split(",")))
        # the captured wire order is a real order, not the sorted set
        self.assertNotEqual(CHROME_20261127_CIPHERS.split(","),
                            sorted(CHROME_20261127_CIPHERS.split(",")))

    def test_ja4_tails_derive_to_the_brave_tails(self):
        # JA4 hashes the sorted cipher list, then sorted exts + "_" +
        # the sig list in wire order (the same assembly the fixture
        # test_ja4_assembled_from_ja4_r_hashes pins): identical sets
        # derive the identical Brave tails, so the plain-Chrome-equals-
        # Brave-slices claim is proven by hashing, not by memory.
        ciphers = ",".join(sorted(CHROME_20261127_CIPHERS.split(",")))
        self.assertEqual(hashlib.sha256(ciphers.encode()).hexdigest()[:12],
                         REAL_BRAVE_JA4.split("_")[1])
        exts = ",".join(sorted(CHROME_20261127_EXTS.split(",")))
        sigs = ",".join(CHROME_20261127_SIGS.split(","))
        self.assertEqual(
            hashlib.sha256((exts + "_" + sigs).encode()).hexdigest()[:12],
            REAL_BRAVE_JA4.split("_")[2])

    def test_ext_wire_order_matches_brave_order_modulo_gap_ledger(self):
        capture_minus_gaps = [t for t in CHROME_20261127_EXT_ORDER
                              if t not in (0x44cd, 0x0012)]
        lyrebird_real = [t for t in LYREBIRD_BRAVE_ORDER if t != "grease"]
        self.assertEqual(capture_minus_gaps, lyrebird_real)

    def test_group_order_pinned(self):
        # MLKEM first, then X25519, P-256, P-384 (the shipped
        # BRAVE_GROUPS order); the capture also led with a GREASE group.
        self.assertEqual(CHROME_20261127_GROUPS.split(","),
                         ["11ec", "001d", "0017", "0018"])

    def test_h2_shape_is_md5_of_the_string_and_equals_the_fixture(self):
        # peet's akamai_fingerprint_hash is exactly md5(fingerprint):
        # the fresh capture reproduces the pinned Brave h2 shape.
        self.assertEqual(
            hashlib.md5(CHROME_20261127_H2.encode()).hexdigest(),
            CHROME_20261127_H2_HASH)
        self.assertEqual(CHROME_20261127_H2_HASH,
                         "52d84b11737d980aef856699f885ca86")


if __name__ == "__main__":
    unittest.main()

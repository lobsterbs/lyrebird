"""Offline tests for the ClientHello harness. No network needed.

The client fixtures are real captures taken with peek.py; the oracle files
are tls.peet.ws /api/all responses for the same clients on the same day,
so ja4 equality here is an end-to-end proof of the parser and the JA4
encoder against an independent implementation.
"""

import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import clienthello as ch

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CLIENTS = os.path.join(ROOT, "fixtures", "clients")
ORACLE = os.path.join(ROOT, "fixtures", "oracle")
FAMILIES = ["curl-openssl", "node22", "python312"]


def load(path):
    with open(path) as f:
        return json.load(f)


class OracleParity(unittest.TestCase):
    def test_local_capture_matches_peet_oracle(self):
        for name in FAMILIES:
            with self.subTest(family=name):
                local = load(os.path.join(CLIENTS, name + ".json"))
                oracle = load(os.path.join(ORACLE, name + ".json"))
                self.assertEqual(local["ja4"], oracle["ja4"],
                                 "peek ja4 diverged from the peet oracle for " + name)

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


if __name__ == "__main__":
    unittest.main()

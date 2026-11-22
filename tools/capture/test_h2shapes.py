"""Offline gates for the h2 shape data from the 2026-11-22 captures.

Rebuilds each browser's akamai fingerprint string from the raw slices and
checks it against the value and md5 hash peet recorded, plus the exact
SETTINGS frame bytes.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import h2shapes as h2


class H2ShapeFrozen(unittest.TestCase):
    def fingerprint(self, settings, wu, pseudo, expect_s, expect_md5):
        fp = h2.akamai_fingerprint(settings, wu, 0, pseudo)
        self.assertEqual(fp, expect_s)
        self.assertEqual(h2.akamai_hash(fp), expect_md5)

    def test_brave_fingerprint_roundtrip(self):
        self.fingerprint(h2.BRAVE_SETTINGS, h2.BRAVE_WINDOW_UPDATE,
                         h2.BRAVE_PSEUDO_ORDER,
                         h2.BRAVE_AKAMAI, h2.BRAVE_AKAMAI_HASH)

    def test_firefox_fingerprint_roundtrip(self):
        self.fingerprint(h2.FIREFOX_SETTINGS, h2.FIREFOX_WINDOW_UPDATE,
                         h2.FIREFOX_PSEUDO_ORDER,
                         h2.FIREFOX_AKAMAI, h2.FIREFOX_AKAMAI_HASH)

    def test_brave_settings_payload_bytes(self):
        self.assertEqual(h2.settings_payload(h2.BRAVE_SETTINGS),
                         bytes.fromhex("000100010000"    # 1:65536
                                       "000200000000"    # 2:0
                                       "000400600000"    # 4:6291456
                                       "000600040000"))  # 6:262144

    def test_firefox_settings_payload_bytes(self):
        self.assertEqual(h2.settings_payload(h2.FIREFOX_SETTINGS),
                         bytes.fromhex("000100010000"    # 1:65536
                                       "000200000000"    # 2:0
                                       "000400020000"    # 4:131072
                                       "000500004000"))  # 5:16384

    def test_brave_settings_frame(self):
        frame = h2.frame(h2.settings_payload(h2.BRAVE_SETTINGS), 0x04)
        self.assertEqual(frame[:3], b"\x00\x00\x18")  # length 24 = 4*6
        self.assertEqual(frame[3:5], b"\x04\x00")    # SETTINGS, no flags

    def test_firefox_window_update_frame(self):
        frame = h2.frame(
            h2.FIREFOX_WINDOW_UPDATE.to_bytes(4, "big"), 0x08)
        self.assertEqual(frame[:3], b"\x00\x00\x04")
        self.assertEqual(frame[3:5], b"\x08\x00")
        self.assertEqual(frame[-4:], bytes.fromhex("00bf0001"))  # 12517377

    def test_headers_flags_and_priority_wire(self):
        # both browsers: EndStream | EndHeaders | Priority on stream 1
        self.assertEqual(h2.BRAVE_HEADERS_FLAGS, 0x25)
        self.assertEqual(h2.FIREFOX_HEADERS_FLAGS, 0x25)
        self.assertEqual(h2.BRAVE_HEADERS_PRIORITY,
                         bytes.fromhex("80000000ff"))  # exclusive, weight 256
        self.assertEqual(h2.FIREFOX_HEADERS_PRIORITY,
                         bytes.fromhex("00000000"
                                       "15"))  # weight 22


class EnginePathParity(unittest.TestCase):
    """The live gate: tls.peet.ws rendered our h2-shaped probe runs
    (brave-h2-live / firefox-h2-live, 2026-11-22) with akamai fingerprints
    field-for-field identical to the real browser captures and to the
    frozen data here."""

    HERE = os.path.dirname(os.path.abspath(__file__))
    ROOT = os.path.dirname(os.path.dirname(HERE))

    def oracle(self, name):
        with open(os.path.join(self.ROOT, "fixtures", "oracle", name + ".json")) as f:
            return json.load(f)

    def test_brave_engine_path_fingerprint(self):
        o = self.oracle("lyrebird-brave")
        self.assertEqual(o["akamai_fingerprint"], h2.BRAVE_AKAMAI)
        self.assertEqual(o["akamai_fingerprint_hash"], h2.BRAVE_AKAMAI_HASH)

    def test_firefox_engine_path_fingerprint(self):
        o = self.oracle("lyrebird-firefox")
        self.assertEqual(o["akamai_fingerprint"], h2.FIREFOX_AKAMAI)
        self.assertEqual(o["akamai_fingerprint_hash"], h2.FIREFOX_AKAMAI_HASH)


if __name__ == "__main__":
    unittest.main()

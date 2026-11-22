"""h2 SETTINGS shape data from the 2026-11-22 tls.peet.ws captures.

The operator's Brave (Chromium 158) and Firefox 160 captures carry the
akamai h2 fingerprint with its md5-based hash. peet's
akamai_fingerprint_hash is exactly md5(akamai_fingerprint string) --
preimage proven 2026-11-22 -- so the hash gates below are offline checks
over pure data. This module pins, per browser:

- the SETTINGS payload (frame body bytes: id u16 BE, value u32 BE),
- the connection-level WINDOW_UPDATE increment,
- the number of PRIORITY frames sent before the first HEADERS (0 for
  both captures, though Brave sent a PRIORITY flag on the HEADERS frame
  with weight 256, depends_on 0, exclusive), and
- the pseudo-header wire order.

Raw capture JSONs are never committed (operator constraint); these
slices are code-transcribed and hash-gated.
"""

import hashlib

BRAVE_SETTINGS = [
    (0x0001, 65536),      # HEADER_TABLE_SIZE
    (0x0002, 0),          # ENABLE_PUSH
    (0x0004, 6291456),    # INITIAL_WINDOW_SIZE
    (0x0006, 262144),     # MAX_HEADER_LIST_SIZE
]
BRAVE_WINDOW_UPDATE = 15663105
BRAVE_PSEUDO_ORDER = ("m", "a", "s", "p")
BRAVE_AKAMAI = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
BRAVE_AKAMAI_HASH = "52d84b11737d980aef856699f885ca86"

FIREFOX_SETTINGS = [
    (0x0001, 65536),      # HEADER_TABLE_SIZE
    (0x0002, 0),          # ENABLE_PUSH
    (0x0004, 131072),     # INITIAL_WINDOW_SIZE
    (0x0005, 16384),      # MAX_FRAME_SIZE (Firefox does not send 6)
]
FIREFOX_WINDOW_UPDATE = 12517377
FIREFOX_PSEUDO_ORDER = ("m", "p", "a", "s")
FIREFOX_AKAMAI = "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s"
FIREFOX_AKAMAI_HASH = "6ea73faa8fc5aac76bded7bd238f6433"

# flag bits of the first HEADERS frame in each capture
BRAVE_HEADERS_FLAGS = 0x25    # EndStream | EndHeaders | Priority
FIREFOX_HEADERS_FLAGS = 0x05  # EndStream | EndHeaders


def settings_payload(items):
    """Return the SETTINGS frame body bytes: (id u16 BE, value u32 BE)*."""
    out = b""
    for id_, value in items:
        out += id_.to_bytes(2, "big") + value.to_bytes(4, "big")
    return out


def frame(body, frame_type, flags=0, stream_id=0):
    """Return a serialized h2 frame around body."""
    length = len(body)
    return (length.to_bytes(3, "big") + bytes([frame_type, flags]) +
            stream_id.to_bytes(4, "big") + body)


def akamai_fingerprint(settings, window_update, priorities, pseudo):
    settings_s = ";".join("%d:%d" % (i, v) for i, v in settings)
    return "%s|%d|%d|%s" % (settings_s, window_update, priorities,
                           ",".join(pseudo))


def akamai_hash(fingerprint):
    return hashlib.md5(fingerprint.encode()).hexdigest()

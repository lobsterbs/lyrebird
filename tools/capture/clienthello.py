"""ClientHello parsing and JA4 computation, stdlib only.

JA4 follows the FoxIO technical spec (technical_details/JA4.md, v0.18.x):
count fields are two decimal characters, GREASE values are ignored
everywhere, SNI (0x0000) and ALPN (0x0010) are excluded from the extension
hash list but still counted, and both hashes are truncated to 12 lowercase
hex characters.
"""

import hashlib

# GREASE values (RFC 8701): 0x0a0a, 0x1a1a, ... 0xfafa
def is_grease(v):
    return v >> 8 == (v & 0xFF) and (v & 0x0F0F) == 0x0A0A

VERSION_MAP = {
    0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
    0x0300: "s3", 0x0002: "s2",
    0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3",
}

EXTENSION_NAMES = {
    0x0000: "server_name", 0x0001: "max_fragment_length", 0x0005: "status_request",
    0x000A: "supported_groups", 0x000B: "ec_point_formats", 0x000D: "signature_algorithms",
    0x0010: "alpn", 0x0012: "signed_certificate_timestamp", 0x0015: "padding",
    0x0016: "encrypt_then_mac", 0x0017: "extended_master_secret",
    0x001B: "compress_certificate", 0x0023: "session_ticket",
    0x0029: "pre_shared_key", 0x002B: "supported_versions",
    0x002D: "psk_key_exchange_modes", 0x0031: "post_handshake_auth",
    0x0033: "key_share", 0x4469: "application_settings_alps",
    0xFF01: "renegotiation_info",
}

CIPHER_TLS13 = {0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_CHACHA20_POLY1305_SHA256",
                0x1303: "TLS_AES_256_GCM_SHA384", 0x1304: "TLS_AES_128_CCM_SHA256",
                0x1305: "TLS_AES_128_CCM_8_SHA256"}

GROUP_NAMES = {0x001D: "x25519", 0x001E: "x448", 0x0017: "secp256r1",
               0x0018: "secp384r1", 0x0019: "secp521r1", 0x11EC: "X25519MLKEM768"}


class ParseError(Exception):
    pass


class _Cur:
    def __init__(self, data):
        self.d = data
        self.i = 0

    def take(self, n):
        if self.i + n > len(self.d):
            raise ParseError("truncated ClientHello at offset %d (need %d bytes)" % (self.i, n))
        b = self.d[self.i:self.i + n]
        self.i += n
        return b

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return int.from_bytes(self.take(2), "big")

    def u24(self):
        return int.from_bytes(self.take(3), "big")

    def rest(self):
        return self.d[self.i:]


def parse_clienthello(raw):
    """Parse raw bytes starting at the first TLS record. Returns a dict."""
    c = _Cur(raw)
    if c.u8() != 0x16:
        raise ParseError("not a handshake record (first byte 0x%02x)" % raw[0])
    record_version = c.u16()
    record_len = c.u16()
    body = c.take(record_len)
    hc = _Cur(body)
    if hc.u8() != 0x01:
        raise ParseError("first message is not a ClientHello")
    hs_len = hc.u24()
    ch = _Cur(hc.take(hs_len))
    legacy_version = ch.u16()
    client_random = ch.take(32)
    sid_len = ch.u8()
    session_id = ch.take(sid_len)
    cs_len = ch.u16()
    ciphers = [int.from_bytes(ch.take(2), "big") for _ in range(cs_len // 2)]
    cm_len = ch.u8()
    compression = list(ch.take(cm_len))
    ext_total = ch.u16()
    ext_end = ch.i + ext_total
    extensions = []
    sni = None
    alpn = []
    supported_versions = []
    sig_algs = []
    key_shares = []      # ordered list of group ids offered, GREASE included
    supported_groups = []
    psk_modes = []
    cert_compression = []
    while ch.i < ext_end:
        etype = ch.u16()
        elen = ch.u16()
        edata = _Cur(ch.take(elen))
        ext = {"type": etype, "name": EXTENSION_NAMES.get(etype, "0x%04x" % etype), "len": elen}

        if etype == 0x0000 and edata.d:
            list_len = edata.u16()
            end = edata.i + list_len
            while edata.i < end:
                ntype = edata.u8()
                hlen = edata.u16()
                hname = edata.take(hlen).decode("latin1")
                if ntype == 0:
                    sni = hname
        elif etype == 0x0010 and edata.d:
            list_len = edata.u16()
            end = edata.i + list_len
            while edata.i < end:
                plen = edata.u8()
                alpn.append(bytes(edata.take(plen)))
        elif etype == 0x000A and edata.d:
            list_len = edata.u16()
            end = edata.i + list_len
            while edata.i < end:
                supported_groups.append(edata.u16())
        elif etype == 0x000D and edata.d:
            list_len = edata.u16()
            end = edata.i + list_len
            while edata.i < end:
                sig_algs.append(edata.u16())
        elif etype == 0x002B and edata.d:
            list_len = edata.u8()
            end = edata.i + list_len
            while edata.i < end:
                supported_versions.append(edata.u16())
        elif etype == 0x0033 and edata.d:
            list_len = edata.u16()
            end = edata.i + list_len
            while edata.i < end:
                gid = edata.u16()
                klen = edata.u16()
                edata.take(klen)
                key_shares.append(gid)
        elif etype == 0x002D and edata.d:
            list_len = edata.u8()
            end = edata.i + list_len
            while edata.i < end:
                psk_modes.append(edata.u8())
        elif etype == 0x001B and edata.d:
            list_len = edata.u8()
            end = edata.i + list_len
            while edata.i < end:
                cert_compression.append(edata.u16())
        extensions.append(ext)

    return {
        "record_version": "%04x" % record_version,
        "legacy_version": "%04x" % legacy_version,
        "session_id": session_id.hex() or None,
        "ciphers": ["%04x" % c_ for c_ in ciphers],
        "compressions": ["%02x" % x for x in compression],
        "extensions": extensions,
        "sni": sni,
        "alpn": [a.decode("latin1") for a in alpn],
        "supported_versions": ["%04x" % v for v in supported_versions],
        "signature_algorithms": ["%04x" % s for s in sig_algs],
        "key_share_groups": ["%04x" % g for g in key_shares],
        "supported_groups": ["%04x" % g for g in supported_groups],
        "psk_modes": ["%02x" % m for m in psk_modes],
        "cert_compression": ["%04x" % a for a in cert_compression],
    }


def _alpn_char(v):
    if not v:
        return "00"
    fb, lb = v[0], v[-1]
    alnum = lambda x: 0x30 <= x <= 0x39 or 0x41 <= x <= 0x5A or 0x61 <= x <= 0x7A
    if alnum(fb) and alnum(lb):
        return chr(fb) + chr(lb)
    h = bytes(v).hex()
    return (h[0] + h[-1])


def _num2(n):
    return "%02d" % min(n, 99)


def _sh12(s):
    if not s:
        return "0" * 12
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def compute_ja4(parsed, transport="t"):
    """Return (ja4, ja4_r) per the FoxIO JA4 spec."""
    ciphers = [c_ for c_ in parsed["ciphers"] if not is_grease(int(c_, 16))]
    exts = [e["type"] for e in parsed["extensions"] if not is_grease(e["type"])]
    # version: highest non-GREASE in supported_versions, else legacy version
    versions = [int(v, 16) for v in parsed["supported_versions"] if not is_grease(int(v, 16))]
    ver_int = max(versions) if versions else int(parsed["legacy_version"], 16)
    if ver_int in (0xFEFC, 0xFEFD, 0xFEFF):
        transport = "d"
    version = VERSION_MAP.get(ver_int, "00")

    sni_char = "d" if parsed["sni"] is not None else "i"
    alpn_first = parsed["alpn"][0].encode("latin1") if parsed["alpn"] else b""
    alpn = _alpn_char(alpn_first)

    ciph_list = sorted(ciphers)
    ext_list = sorted(["%04x" % e for e in exts if e not in (0x0000, 0x0010)])
    sigs = parsed["signature_algorithms"]

    head = transport + version + sni_char + _num2(len(ciphers)) + _num2(len(exts)) + alpn
    ciph_str = ",".join(ciph_list)
    ext_str = ",".join(ext_list) + ("_" + ",".join(sigs) if sigs else "")
    ja4 = head + "_" + _sh12(ciph_str) + "_" + _sh12(ext_str)
    ja4_r = head + "_" + ciph_str + "_" + (",".join(ext_list) + ("_" + ",".join(sigs) if sigs else ""))
    return ja4, ja4_r

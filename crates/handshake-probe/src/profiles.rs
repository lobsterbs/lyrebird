//! Fingerprints-as-data: wire ORDER slices for cipher suites, signature
//! schemes, and named groups, derived from the operator's tls.peet.ws
//! reference captures of 2026-11-22 (Brave / Chromium 158, Firefox 160,
//! Windows). The raw capture JSONs are deliberately NOT part of this
//! repo; these slices are the derived order data.
//!
//! Honest scope: these slices reorder what the crypto provider offers.
//! They cannot conjure suites or schemes the provider lacks. Remaining
//! set differences (extensively documented on the issues): providers
//! offer 9 suites vs the browsers' 15, rustls appends the SCSV,
//! extension set and order are still rustls-native.

use rustls::{CipherSuite, ClientHelloProfile, NamedGroup, SignatureScheme};

use rustls::client::client_hello_profile::ProfileStaticExtension;

// Brave / Chromium 158, Windows: wire cipher order, GREASE bookend stripped
pub(super) const BRAVE_CIPHERS: &[u16] = &[
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035,
];
// Leading GREASE stripped. The three 0x09xx values lead Brave's list;
// tls.peet.ws does not decode signature algorithms, so no identity is
// claimed for them here beyond their wire value.
pub(super) const BRAVE_SIGS: &[u16] = &[
    0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
// GREASE group stripped; X25519MLKEM768 first
pub(super) const BRAVE_GROUPS: &[u16] = &[0x11ec, 0x001d, 0x0017, 0x0018];

// Firefox 160, Windows: no GREASE anywhere
pub(super) const FIREFOX_CIPHERS: &[u16] = &[
    0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035,
];
pub(super) const FIREFOX_SIGS: &[u16] = &[
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
];
pub(super) const FIREFOX_GROUPS: &[u16] = &[0x11ec, 0x001d, 0x0017, 0x0018, 0x0019];

// Capture-derived extension order, wire type ids. Both browsers start at
// server_name; real chrome-family hellos keep every GREASE extension at the
// tail (zero leading grease), so this slice carries none and hs.rs emits
// trailing bookends only. IDs follow tls.peet.ws rendering of the
// 2026-11-22 captures; ALPS is 17613 (0x44cd) as peet printed it.
pub(super) const BRAVE_EXT_ORDER: &[u16] = &[
    0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x44cd, 0x0012, 0x0017, 0x001b, 0x0023,
    0x002b, 0x002d, 0x0005, 0x0033, 0xfe0d, 0xff01,
];
// wire: ALPS body 01 02 68 32 ("h2" list); SCT empty; renego single 0x00
pub(super) const BRAVE_STATIC_EXTS: &[ProfileStaticExtension] = &[
    ProfileStaticExtension { ext_type: 0x0012, body: &[] },
    ProfileStaticExtension { ext_type: 0x44cd, body: &[0x01, 0x02, 0x68, 0x32] },
    ProfileStaticExtension { ext_type: 0xff01, body: &[0x00] },
];

pub(super) const FIREFOX_EXT_ORDER: &[u16] = &[
    0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x0012, 0x0017, 0x001b, 0x001c, 0x0022, 0x0029,
    0x002b, 0x002d, 0x0005, 0x0033, 0xfe0d, 0xff01,
];
// wire: SCT empty; record_size_limit 0x4001; delegated_credentials
// scheme list; renego single 0x00. The captured pre_shared_key (0x0029)
// is NOT emitted: real state requires session tickets a fresh client
// cannot honestly conjure, and an empty offer (zero identities) was
// proven rejected by a live server (unexpected_message alert on
// tls.peet.ws, 2026-11-22), so presence-parity is not shippable either.
// Documented as a session-state gap; extension count is 16 vs the
// capture's 17.
pub(super) const FIREFOX_STATIC_EXTS: &[ProfileStaticExtension] = &[
    ProfileStaticExtension { ext_type: 0x0012, body: &[] },
    ProfileStaticExtension { ext_type: 0x001c, body: &[0x40, 0x01] },
    ProfileStaticExtension {
        ext_type: 0x0022,
        body: &[0x04, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03],
    },
    ProfileStaticExtension { ext_type: 0xff01, body: &[0x00] },
];

// Cert-compression algorithms this profile advertises (RFC 8879 ids:
// zlib=1, brotli=2, zstd=3). rustls has no zstd decompressor, so the
// Firefox list is honestly two of three.
pub(super) const BRAVE_COMPRESSION: &[u16] = &[0x0002];
pub(super) const FIREFOX_COMPRESSION: &[u16] = &[0x0001, 0x0002];

fn build(
    grease: bool,
    ciphers: &[u16],
    sigs: &[u16],
    groups: &[u16],
    ext_order: &'static [u16],
    statics: &'static [ProfileStaticExtension],
    grease_tail: usize,
    ech_grease: bool,
) -> &'static ClientHelloProfile {
    Box::leak(Box::new(ClientHelloProfile {
        grease,
        cipher_suites: Box::leak(
            ciphers
                .iter()
                .map(|v| CipherSuite::from(*v))
                .collect::<Vec<CipherSuite>>()
                .into_boxed_slice(),
        ),
        signature_schemes: Box::leak(
            sigs
                .iter()
                .map(|v| SignatureScheme::from(*v))
                .collect::<Vec<SignatureScheme>>()
                .into_boxed_slice(),
        ),
        named_groups: Box::leak(
            groups
                .iter()
                .map(|v| NamedGroup::from(*v))
                .collect::<Vec<NamedGroup>>()
                .into_boxed_slice(),
        ),
        extension_order: ext_order,
        extensions: statics,
        grease_extension_tail: grease_tail,
        ech_grease,
    }))
}

/// The Brave (Chromium 158) order profile with GREASE bookends, the
/// captured extension set/order, and GREASE ECH.
pub fn brave() -> &'static ClientHelloProfile {
    build(
        true,
        BRAVE_CIPHERS,
        BRAVE_SIGS,
        BRAVE_GROUPS,
        BRAVE_EXT_ORDER,
        BRAVE_STATIC_EXTS,
        2,
        true,
    )
}

/// The Firefox 160 order profile, extension set/order, no GREASE,
/// GREASE ECH.
pub fn firefox() -> &'static ClientHelloProfile {
    build(
        false,
        FIREFOX_CIPHERS,
        FIREFOX_SIGS,
        FIREFOX_GROUPS,
        FIREFOX_EXT_ORDER,
        FIREFOX_STATIC_EXTS,
        0,
        true,
    )
}

/// ALPN both captured browsers offer, in wire order.
pub fn alpn() -> Vec<Vec<u8>> {
    vec![b"h2".to_vec(), b"http/1.1".to_vec()]
}

/// The profile's advertized cert-decompression algorithms, mapped to
/// rustls decompressors in the profile's wire order.
pub fn cert_decompressors(order: &[u16]) -> Vec<&'static dyn rustls::compress::CertDecompressor> {
    let defaults = rustls::compress::default_cert_decompressors();
    order
        .iter()
        .filter_map(|want| {
            defaults
                .iter()
                .find(|d| u16::from(d.algorithm()) == *want)
                .copied()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_slices_are_frozen() {
        // Regression guard: these arrays ARE the fingerprint data.
        assert_eq!(
            BRAVE_CIPHERS,
            &[
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ]
        );
        assert_eq!(
            BRAVE_SIGS,
            &[
                0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806,
                0x0601,
            ]
        );
        assert_eq!(BRAVE_GROUPS, &[0x11ec, 0x001d, 0x0017, 0x0018]);
        assert_eq!(
            FIREFOX_CIPHERS,
            &[
                0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ]
        );
        assert_eq!(
            FIREFOX_SIGS,
            &[
                0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203,
                0x0201,
            ]
        );
        assert_eq!(FIREFOX_GROUPS, &[0x11ec, 0x001d, 0x0017, 0x0018, 0x0019]);
        assert_eq!(
            BRAVE_EXT_ORDER,
            &[
                0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x44cd, 0x0012, 0x0017, 0x001b,
                0x0023, 0x002b, 0x002d, 0x0005, 0x0033, 0xfe0d, 0xff01,
            ]
        );
        assert_eq!(
            FIREFOX_EXT_ORDER,
            &[
                0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x0012, 0x0017, 0x001b, 0x001c, 0x0022,
                0x0029, 0x002b, 0x002d, 0x0005, 0x0033, 0xfe0d, 0xff01,
            ]
        );
        assert_eq!(
            BRAVE_STATIC_EXTS.iter().map(|e| e.ext_type).collect::<Vec<_>>(),
            vec![0x0012, 0x44cd, 0xff01]
        );
        assert_eq!(
            BRAVE_STATIC_EXTS.iter().map(|e| e.body).collect::<Vec<_>>(),
            vec![&[][..], &[0x01, 0x02, 0x68, 0x32][..], &[0x00][..]]
        );
        assert_eq!(
            FIREFOX_STATIC_EXTS.iter().map(|e| e.ext_type).collect::<Vec<_>>(),
            vec![0x0012, 0x001c, 0x0022, 0xff01]
        );
        assert_eq!(
            FIREFOX_STATIC_EXTS.iter().map(|e| e.body).collect::<Vec<_>>(),
            vec![
                &[][..],
                &[0x40, 0x01][..],
                &[0x04, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03][..],
                &[0x00][..],
            ]
        );
        // Firefox offers no session_ticket (0x0023): the pinned order is the
        // set contract for emitted extensions, and the captured hello lacks
        // it. The captured pre_shared_key (0x0029) is pinned in the order
        // slice but deliberately not emitted: honest session state does not
        // exist and empty offers fail against real servers.
        assert_eq!(FIREFOX_EXT_ORDER.iter().any(|&t| t == 0x0023), false);
        assert_eq!(FIREFOX_EXT_ORDER.iter().any(|&t| t == 0x0029), true);
        assert_eq!(
            FIREFOX_STATIC_EXTS.iter().any(|e| e.ext_type == 0x0029),
            false
        );
    }

    #[test]
    fn profiles_carry_the_slices() {
        let b = brave();
        assert!(b.grease);
        assert_eq!(b.grease_extension_tail, 2);
        assert_eq!(b.ech_grease, true);
        assert_eq!(b.extension_order, BRAVE_EXT_ORDER);
        assert_eq!(b.extensions.len(), BRAVE_STATIC_EXTS.len());
        assert_eq!(
            b.cipher_suites
                .iter()
                .map(|c| u16::from(*c))
                .collect::<Vec<_>>(),
            BRAVE_CIPHERS
        );
        assert_eq!(
            b.signature_schemes
                .iter()
                .map(|s| u16::from(*s))
                .collect::<Vec<_>>(),
            BRAVE_SIGS
        );
        assert_eq!(
            b.named_groups
                .iter()
                .map(|g| u16::from(*g))
                .collect::<Vec<_>>(),
            BRAVE_GROUPS
        );

        let f = firefox();
        assert!(!f.grease);
        assert_eq!(f.grease_extension_tail, 0);
        assert_eq!(f.ech_grease, true);
        assert_eq!(f.extension_order, FIREFOX_EXT_ORDER);
        assert_eq!(f.extensions.len(), FIREFOX_STATIC_EXTS.len());
        assert_eq!(
            f.cipher_suites
                .iter()
                .map(|c| u16::from(*c))
                .collect::<Vec<_>>(),
            FIREFOX_CIPHERS
        );
        assert_eq!(
            f.signature_schemes
                .iter()
                .map(|s| u16::from(*s))
                .collect::<Vec<_>>(),
            FIREFOX_SIGS
        );
        assert_eq!(
            f.named_groups
                .iter()
                .map(|g| u16::from(*g))
                .collect::<Vec<_>>(),
            FIREFOX_GROUPS
        );
    }
}

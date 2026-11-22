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

fn build(
    grease: bool,
    ciphers: &[u16],
    sigs: &[u16],
    groups: &[u16],
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
    }))
}

/// The Brave (Chromium 158) order profile with GREASE bookends.
pub fn brave() -> &'static ClientHelloProfile {
    build(true, BRAVE_CIPHERS, BRAVE_SIGS, BRAVE_GROUPS)
}

/// The Firefox 160 order profile, no GREASE.
pub fn firefox() -> &'static ClientHelloProfile {
    build(false, FIREFOX_CIPHERS, FIREFOX_SIGS, FIREFOX_GROUPS)
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
    }

    #[test]
    fn profiles_carry_the_slices() {
        let b = brave();
        assert!(b.grease);
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

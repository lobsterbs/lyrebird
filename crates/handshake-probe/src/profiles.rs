//! Thin seam over the wire data: the capture-derived profile slices live
//! with the patched rustls itself, as `rustls::client::browser_profiles`
//! (patch 0003, applied by tools/apply-rustls.sh), so every consumer --
//! this probe, and epoxy engines embedding the same patched rustls --
//! reads one frozen copy.
//!
//! The unit tests below re-freeze the data exactly where it now lives.

pub use rustls::client::browser_profiles::{
    BRAVE_CIPHERS, BRAVE_COMPRESSION, BRAVE_EXT_ORDER, BRAVE_GROUPS, BRAVE_SIGS,
    BRAVE_STATIC_EXTS, FIREFOX_CIPHERS, FIREFOX_COMPRESSION, FIREFOX_EXT_ORDER, FIREFOX_GROUPS,
    FIREFOX_SIGS, FIREFOX_STATIC_EXTS,
};
use rustls::ClientHelloProfile;

pub fn brave() -> &'static ClientHelloProfile {
    rustls::client::browser_profiles::brave()
}

pub fn firefox() -> &'static ClientHelloProfile {
    rustls::client::browser_profiles::firefox()
}

pub fn alpn() -> Vec<Vec<u8>> {
    rustls::client::browser_profiles::alpn()
}

pub fn cert_decompressors(order: &[u16]) -> Vec<&'static dyn rustls::compress::CertDecompressor> {
    rustls::client::browser_profiles::cert_decompressors(order)
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
            BRAVE_EXT_ORDER,
            &[
                0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x44cd, 0x0012, 0x0017, 0x001b, 0x0023,
                0x002b, 0x002d, 0x0005, 0x0033, 0xfe0d, 0xff01,
            ]
        );
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
            FIREFOX_EXT_ORDER,
            &[
                0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x0012, 0x0017, 0x001b, 0x001c, 0x0022,
                0x0029, 0x002b, 0x002d, 0x0005, 0x0033, 0xfe0d, 0xff01,
            ]
        );
    }

    #[test]
    fn profiles_carry_the_slices() {
        let b = brave();
        assert!(b.grease);
        assert_eq!(b.extension_order, BRAVE_EXT_ORDER);
        assert_eq!(b.grease_extension_tail, 2);
        assert_eq!(b.cipher_suites.len(), BRAVE_CIPHERS.len());
        assert_eq!(b.signature_schemes.len(), BRAVE_SIGS.len());
        assert_eq!(b.named_groups.len(), BRAVE_GROUPS.len());

        let f = firefox();
        assert!(!f.grease);
        assert_eq!(f.extension_order, FIREFOX_EXT_ORDER);
        assert_eq!(f.grease_extension_tail, 0);
        assert_eq!(f.named_groups.len(), FIREFOX_GROUPS.len());
        // the Firefox statics deliberately exclude pre_shared_key even
        // though the order slice pins it: honest session state does not
        // exist and an empty offer was proven rejected live
        let has_psk_static = FIREFOX_STATIC_EXTS
            .iter()
            .any(|e| e.ext_type == 0x0029);
        assert!(!has_psk_static);
        assert!(FIREFOX_EXT_ORDER.contains(&0x0029));
    }

    #[test]
    fn structural_gap_statics_are_ledgered() {
        // 2026-11-25 live-server verdicts: extensions whose negotiation
        // this rustls cannot honor are not offered (see browser_profiles).
        // brave: ALPS (server aborts on the missing client EE) and SCT
        // (invites CertificateEntry SCT lists the client rejects).
        for ext in BRAVE_STATIC_EXTS {
            assert!(ext.ext_type != 0x44cd && ext.ext_type != 0x0012);
        }
        // firefox: SCT and delegated_credentials (edges then send
        // credentials this client cannot verify).
        for ext in FIREFOX_STATIC_EXTS {
            assert!(ext.ext_type != 0x0012 && ext.ext_type != 0x0022);
        }
        // the capture-derived orders keep the gap types pinned so the gap
        // stays visible on the wire contract, but nothing emits them
        assert!(BRAVE_EXT_ORDER.contains(&0x44cd));
        assert!(FIREFOX_EXT_ORDER.contains(&0x0029));
    }
}

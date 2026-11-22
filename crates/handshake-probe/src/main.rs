//! handshake-probe: perform a real TLS handshake with the pinned rustls and
//! optionally a live HTTP/1.1 request, so the ClientHello our build sends can
//! be recorded and JA4-compared.
//!
//! Modes:
//!   probe live <host> <port> <path>   real WebPKI roots, prints the response
//!   probe local <sni-host> <port>     insecure verifier, for capture against
//!                                     peek.py (only the first flight is sent)
//!   probe grease-live <host> <port> <path>
//!   probe grease-local <sni-host> <port>
//!                                     same as live/local, with the GREASE
//!                                     profile (bookends only, native orders)
//!   probe brave-live <host> <port> <path>
//!   probe brave-local <sni-host> <port>
//!                                     Brave/Chromium 158 order profile
//!                                     (GREASE + captured orders), aws-lc
//!                                     provider (X25519MLKEM768 first group)
//!   probe firefox-live <host> <port> <path>
//!   probe firefox-local <sni-host> <port>
//!                                     Firefox 160 order profile, no GREASE,
//!                                     aws-lc provider
//!   probe brave-h2-live <host> <port> <path>
//!   probe firefox-h2-live <host> <port> <path>
//!                                     live TLS + hand-rolled HTTP/2 with the
//!                                     profile's SETTINGS/WINDOW_UPDATE/
//!                                     HEADERS shaping (h2 only ALPN)
//!
//! No ALPN is offered and no session resumption is used, so both modes send a
//! byte-similar ClientHello (only the SNI value varies).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls_pki_types::ServerName;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::ClientHelloProfile;
use rustls::DigitallySignedStruct;
use rustls::RootCertStore;

mod h2shape;
mod profiles;

#[derive(Debug)]
struct NoVerify(Arc<rustls::client::WebPkiServerVerifier>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    // Delegate to the real WebPKI verifier: rustls builds the ClientHello's
    // signature_algorithms extension from this, so the capture must advertise
    // exactly what the live (verifying) client would send.
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

static GREASE_PROFILE: rustls::ClientHelloProfile = rustls::ClientHelloProfile {
    grease: true,
    // Historical v0.2 GREASE shape: one leading GREASE extension, zero
    // trailing bookends, cipher/sig/group order left to rustls.
    cipher_suites: &[],
    signature_schemes: &[],
    named_groups: &[],
    extension_order: &[0x0a0a],
    extensions: &[],
    grease_extension_tail: 0,
    ech_grease: false,
};

fn build_config(
    insecure: bool,
    profile: Option<&'static ClientHelloProfile>,
    aws: bool,
) -> rustls::ClientConfig {
    let provider = if aws {
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    } else {
        Arc::new(rustls::crypto::ring::default_provider())
    };
    // The inner verifier feeds supported_verify_schemes(), which builds the
    // ClientHello signature_algorithms: it must carry the SAME provider as
    // the config, or the capture would advertise the wrong scheme list.
    let verifier_provider = provider.clone();
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("protocol versions");
    let config = if insecure {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            verifier_provider,
        )
        .build()
        .expect("webpki verifier");
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(inner)))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder
            .with_root_certificates(roots)
            .with_no_client_auth()
    };

    match profile {
        Some(p) => config.with_client_hello_profile(p),
        None => config,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "usage: probe live <host> <port> <path>\n       probe local <sni-host> <port>\n       probe grease-live <host> <port> <path>\n       probe grease-local <sni-host> <port>\n       probe brave-live <host> <port> <path>\n       probe brave-local <sni-host> <port>\n       probe firefox-live <host> <port> <path>\n       probe firefox-local <sni-host> <port>\n       probe brave-h2-live <host> <port> <path>\n       probe firefox-h2-live <host> <port> <path>"
        );
        std::process::exit(2);
    }
    let mode = args[1].as_str();
    let (sni, addr, insecure, path, profile, aws) = match mode {
        "live" => {
            let host = args[2].clone();
            let port = args[3].clone();
            let p = args.get(4).cloned().unwrap_or_else(|| "/".to_string());
            (host, format!("{}:{}", args[2], port), false, Some(p), None::<&'static ClientHelloProfile>, false)
        }
        "grease-live" => {
            let host = args[2].clone();
            let port = args[3].clone();
            let p = args.get(4).cloned().unwrap_or_else(|| "/".to_string());
            (host, format!("{}:{}", args[2], port), false, Some(p), Some(&GREASE_PROFILE), false)
        }
        "brave-live" | "firefox-live" | "brave-h2-live" | "firefox-h2-live" => {
            let host = args[2].clone();
            let port = args[3].clone();
            let p = args.get(4).cloned().unwrap_or_else(|| "/".to_string());
            let prof = if mode.starts_with("brave") { profiles::brave() } else { profiles::firefox() };
            (host, format!("{}:{}", args[2], port), false, Some(p), Some(prof), true)
        }
        "local" => {
            let sni_host = args[2].clone();
            let port = args[3].clone();
            (sni_host, format!("127.0.0.1:{}", port), true, None, None::<&'static ClientHelloProfile>, false)
        }
        "grease-local" => {
            let sni_host = args[2].clone();
            let port = args[3].clone();
            (sni_host, format!("127.0.0.1:{}", port), true, None, Some(&GREASE_PROFILE), false)
        }
        "brave-local" | "firefox-local" => {
            let sni_host = args[2].clone();
            let port = args[3].clone();
            let prof = if mode == "brave-local" { profiles::brave() } else { profiles::firefox() };
            (sni_host, format!("127.0.0.1:{}", port), true, None, Some(prof), true)
        }
        other => {
            eprintln!("unknown mode {}", other);
            std::process::exit(2);
        }
    };

    let mut config = build_config(insecure, profile, aws);
    match mode {
        "brave-h2-live" => {
            config.alpn_protocols = vec![b"h2".to_vec()];
            config.cert_decompressors = profiles::cert_decompressors(profiles::BRAVE_COMPRESSION);
        }
        "firefox-h2-live" => {
            config.alpn_protocols = vec![b"h2".to_vec()];
            config.cert_decompressors = profiles::cert_decompressors(profiles::FIREFOX_COMPRESSION);
        }
        "brave-live" | "brave-local" => {
            config.alpn_protocols = profiles::alpn();
            config.cert_decompressors = profiles::cert_decompressors(profiles::BRAVE_COMPRESSION);
        }
        "firefox-live" | "firefox-local" => {
            config.alpn_protocols = profiles::alpn();
            config.cert_decompressors = profiles::cert_decompressors(profiles::FIREFOX_COMPRESSION);
        }
        _ => {}
    }
    let name = ServerName::try_from(sni.clone()).expect("server name");
    let mut conn =
        rustls::ClientConnection::new(Arc::new(config), name).expect("client connection");
    let mut sock = TcpStream::connect(&addr).expect("tcp connect");

    let h2_shape = match mode {
        "brave-h2-live" => Some(&h2shape::BRAVE_H2),
        "firefox-h2-live" => Some(&h2shape::FIREFOX_H2),
        _ => None,
    };
    if let Some(shape) = h2_shape {
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        run_h2(&mut tls, shape, &sni, path.as_deref().unwrap_or("/"));
        return;
    }

    if let Some(p) = &path {
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: lyrebird-probe/0.1\r\nConnection: close\r\n\r\n",
            p, sni
        );
        tls.write_all(req.as_bytes()).expect("write request");
        tls.flush().expect("flush");
        let mut buf = Vec::new();
        let _ = tls.read_to_end(&mut buf);
        print!("{}", String::from_utf8_lossy(&buf));
    } else {
        // capture mode: push our first flight (the ClientHello) and let
        // peek.py record it; the listener never completes the handshake.
        conn.write_tls(&mut sock).expect("write clienthello");
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

/// Hand-rolled HTTP/2 client: sends the profile-shaped preface, SETTINGS,
/// WINDOW_UPDATE and a request HEADERS on stream 1, then reads until the
/// response body's END_STREAM and prints it. No h2 crate dependency.
fn run_h2(
    tls: &mut rustls::Stream<'_, rustls::ClientConnection, TcpStream>,
    shape: &h2shape::H2Shape,
    host: &str,
    path: &str,
) {
    let mut flight = Vec::new();
    flight.extend_from_slice(h2shape::PREFACE);
    flight.extend_from_slice(&h2shape::settings_frame(shape.settings));
    flight.extend_from_slice(&h2shape::window_update_frame(shape.window_update));
    flight.extend_from_slice(&h2shape::request_headers_frame(shape, host, path));
    tls.write_all(&flight).expect("write h2 preface");
    tls.flush().expect("flush");

    let mut buffered: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut body: Vec<u8> = Vec::new();
    'read: loop {
        match tls.read(&mut chunk) {
            Ok(0) => break 'read,
            Ok(n) => buffered.extend_from_slice(&chunk[..n]),
            Err(e) => {
                eprintln!("h2 read error: {}", e);
                break 'read;
            }
        }
        while buffered.len() >= 9 {
            let len = (usize::from(buffered[0]) << 16)
                | (usize::from(buffered[1]) << 8)
                | usize::from(buffered[2]);
            if buffered.len() < 9 + len {
                break;
            }
            let kind = buffered[3];
            let flags = buffered[4];
            let stream = u32::from_be_bytes([
                buffered[5],
                buffered[6],
                buffered[7],
                buffered[8] & 0x7f,
            ]);
            let payload_end = 9 + len;
            match kind {
                0x04 if flags & 0x01 == 0 => {
                    tls.write_all(&h2shape::settings_ack_frame()).expect("settings ack");
                    tls.flush().expect("flush");
                }
                0x06 if flags & 0x01 == 0 => {
                    let payload = &buffered[9..payload_end];
                    let mut ping = vec![0u8; 8];
                    for (i, b) in payload.iter().take(8).enumerate() {
                        ping[i] = *b;
                    }
                    tls.write_all(&h2shape::ping_ack_frame(&ping)).expect("ping ack");
                    tls.flush().expect("flush");
                }
                0x00 if stream == 1 => {
                    body.extend_from_slice(&buffered[9..payload_end]);
                    if flags & 0x01 != 0 {
                        buffered.drain(..payload_end);
                        break 'read;
                    }
                }
                0x01 if stream == 1 && flags & 0x01 != 0 => {
                    buffered.drain(..payload_end);
                    break 'read;
                }
                0x07 => {
                    eprintln!("h2: server sent GOAWAY");
                    buffered.drain(..payload_end);
                    break 'read;
                }
                _ => {}
            }
            buffered.drain(..payload_end);
        }
    }
    print!("{}", String::from_utf8_lossy(&body));
}

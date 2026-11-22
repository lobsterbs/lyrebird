//! handshake-probe: perform a real TLS handshake with the pinned rustls and
//! optionally a live HTTP/1.1 request, so the ClientHello our build sends can
//! be recorded and JA4-compared.
//!
//! Modes:
//!   probe live <host> <port> <path>   real WebPKI roots, prints the response
//!   probe local <sni-host> <port>     insecure verifier, for capture against
//!                                     peek.py (only the first flight is sent)
//!
//! No ALPN is offered and no session resumption is used, so both modes send a
//! byte-similar ClientHello (only the SNI value varies).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls_pki_types::ServerName;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring as rcrypto;
use rustls::DigitallySignedStruct;
use rustls::RootCertStore;

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

fn build_config(insecure: bool) -> rustls::ClientConfig {
    let provider = Arc::new(rcrypto::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("protocol versions");
    if insecure {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let inner = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
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
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: probe live <host> <port> <path>\n       probe local <sni-host> <port>");
        std::process::exit(2);
    }
    let mode = args[1].as_str();
    let (sni, addr, insecure, path) = match mode {
        "live" => {
            let host = args[2].clone();
            let port = args[3].clone();
            let p = args.get(4).cloned().unwrap_or_else(|| "/".to_string());
            (host, format!("{}:{}", args[2], port), false, Some(p))
        }
        "local" => {
            let sni_host = args[2].clone();
            let port = args[3].clone();
            (sni_host, format!("127.0.0.1:{}", port), true, None)
        }
        other => {
            eprintln!("unknown mode {}", other);
            std::process::exit(2);
        }
    };

    let config = build_config(insecure);
    let name = ServerName::try_from(sni.clone()).expect("server name");
    let mut conn =
        rustls::ClientConnection::new(Arc::new(config), name).expect("client connection");
    let mut sock = TcpStream::connect(&addr).expect("tcp connect");

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

//! Engine-path HTTP/2 shaping: client SETTINGS, connection WINDOW_UPDATE,
//! HEADERS flags/priority, and pseudo-header order, frozen per browser
//! profile from real captures. Byte contracts live here; main.rs only
//! takes these onto the wire.

pub struct H2Shape {
    pub settings: &'static [(u16, u32)],
    pub window_update: u32,
    pub pseudo_order: [&'static str; 4],
    pub headers_flags: u8,
    /// 5-byte HEADERS priority payload (exclusive+dep u32, weight-1)
    pub priority: Option<[u8; 5]>,
}

pub const BRAVE_H2: H2Shape = H2Shape {
    settings: &[(1, 65536), (2, 0), (4, 6291456), (6, 262144)],
    window_update: 15_663_105,
    pseudo_order: [":method", ":authority", ":scheme", ":path"],
    headers_flags: 0x25, // END_STREAM | END_HEADERS | PRIORITY
    priority: Some([0x80, 0x00, 0x00, 0x00, 0xff]), // exclusive dep 0, weight 256
};

pub const FIREFOX_H2: H2Shape = H2Shape {
    settings: &[(1, 65536), (2, 0), (4, 131072), (5, 16384)],
    window_update: 12_517_377,
    pseudo_order: [":method", ":path", ":authority", ":scheme"],
    headers_flags: 0x25, // END_STREAM | END_HEADERS | PRIORITY
    priority: Some([0x00, 0x00, 0x00, 0x00, 0x15]), // dep 0, weight 22
};

pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

fn u24(buf: &mut Vec<u8>, v: usize) {
    buf.push((v >> 16) as u8);
    buf.push((v >> 8) as u8);
    buf.push(v as u8);
}

pub fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + payload.len());
    u24(&mut out, payload.len());
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn settings_frame(settings: &[(u16, u32)]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(settings.len() * 6);
    for (id, value) in settings {
        payload.extend_from_slice(&id.to_be_bytes());
        payload.extend_from_slice(&value.to_be_bytes());
    }
    frame(0x04, 0, 0, &payload)
}

pub fn settings_ack_frame() -> Vec<u8> {
    frame(0x04, 0x01, 0, &[])
}

pub fn ping_ack_frame(payload: &[u8]) -> Vec<u8> {
    frame(0x06, 0x01, 0, payload)
}

pub fn window_update_frame(wu: u32) -> Vec<u8> {
    frame(0x08, 0, 0, &wu.to_be_bytes())
}

/// HPACK literal without indexing, integer never huffman-coded
/// (name and value lengths below 127). Matches what the profiled
/// browsers emit for fresh header names.
fn hpack_header(out: &mut Vec<u8>, name: &str, value: &str) {
    out.push(0x00);
    out.push(name.len() as u8);
    out.extend_from_slice(name.as_bytes());
    out.push(value.len() as u8);
    out.extend_from_slice(value.as_bytes());
}

/// HEADERS frame on stream 1 carrying the request. Pseudo headers go in
/// profile order first, then a minimal regular set (user-agent, accept).
pub fn request_headers_frame(shape: &H2Shape, host: &str, path: &str) -> Vec<u8> {
    let mut block = Vec::new();
    for pseudo in shape.pseudo_order {
        let (name, value): (&str, &str) = match pseudo {
            ":method" => (":method", "GET"),
            ":authority" => (":authority", host),
            ":scheme" => (":scheme", "https"),
            ":path" => (":path", path),
            other => unreachable!("unknown pseudo header {}", other),
        };
        hpack_header(&mut block, name, value);
    }
    hpack_header(&mut block, "user-agent", "lyrebird-probe/0.1");
    hpack_header(&mut block, "accept", "*/*");

    let mut payload = Vec::with_capacity(block.len() + 5);
    match shape.priority {
        Some(p) => payload.extend_from_slice(&p),
        None => {}
    }
    payload.extend_from_slice(&block);
    frame(0x01, shape.headers_flags, 1, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:04x}", b)).collect::<Vec<_>>().join(" ")
    }

    #[test]
    fn brave_settings_frame_frozen() {
        assert_eq!(
            hex(&settings_frame(BRAVE_H2.settings)),
            hex(&{
                let mut v = vec![0x00, 0x00, 0x18, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
                v.extend_from_slice(&[
                    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, // 1: 65536
                    0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // 2: 0
                    0x00, 0x04, 0x00, 0x60, 0x00, 0x00, // 4: 6291456
                    0x00, 0x06, 0x00, 0x04, 0x00, 0x00, // 6: 262144
                ]);
                v
            })
        );
    }

    #[test]
    fn firefox_settings_frame_frozen() {
        assert_eq!(
            hex(&settings_frame(FIREFOX_H2.settings)),
            hex(&{
                let mut v = vec![0x00, 0x00, 0x18, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
                v.extend_from_slice(&[
                    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, // 1: 65536
                    0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // 2: 0
                    0x00, 0x04, 0x00, 0x02, 0x00, 0x00, // 4: 131072
                    0x00, 0x05, 0x00, 0x00, 0x40, 0x00, // 5: 16384
                ]);
                v
            })
        );
    }

    #[test]
    fn window_update_frames_frozen() {
        assert_eq!(
            hex(&window_update_frame(15_663_105)),
            hex(&[0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xef, 0x00, 0x01])
        );
        assert_eq!(
            hex(&window_update_frame(12_517_377)),
            hex(&[0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbf, 0x00, 0x01])
        );
    }

    #[test]
    fn brave_request_headers_frame_frozen() {
        let frame = request_headers_frame(&BRAVE_H2, "tls.peet.ws", "/api/all");
        assert_eq!(
            hex(&frame),
            hex(&{
                let mut v = vec![0x00, 0x00, 0x74, 0x01, 0x25, 0x00, 0x00, 0x00, 0x01];
                v.extend_from_slice(&BRAVE_H2.priority.unwrap());
                v.extend_from_slice(&[
                    0x00, 0x07, b':', b'm', b'e', b't', b'h', b'o', b'd', 0x03, b'G', b'E', b'T',
                    0x00, 0x0a, b':', b'a', b'u', b't', b'h', b'o', b'r', b'i', b't', b'y',
                    0x0b, b't', b'l', b's', b'.', b'p', b'e', b'e', b't', b'.', b'w', b's',
                    0x00, 0x07, b':', b's', b'c', b'h', b'e', b'm', b'e', 0x05, b'h', b't', b't', b'p', b's',
                    0x00, 0x05, b':', b'p', b'a', b't', b'h', 0x08, b'/', b'a', b'p', b'i', b'/', b'a', b'l', b'l',
                    0x00, 0x0a, b'u', b's', b'e', b'r', b'-', b'a', b'g', b'e', b'n', b't',
                    0x12, b'l', b'y', b'r', b'e', b'b', b'i', b'r', b'd', b'-', b'p', b'r', b'o', b'b', b'e', b'/', b'0', b'.', b'1',
                    0x00, 0x06, b'a', b'c', b'c', b'e', b'p', b't', 0x03, b'*', b'/', b'*',
                ]);
                v
            })
        );
    }

    #[test]
    fn firefox_request_headers_frame_frozen() {
        let frame = request_headers_frame(&FIREFOX_H2, "tls.peet.ws", "/api/all");
        // first pseudo pair must be :method then :path (m,p,a,s)
        let payload = &frame[9..];
        assert_eq!(payload[5], 0x00);
        assert_eq!(payload[6], 0x07);
        assert_eq!(&payload[7..14], b":method");
        assert_eq!(payload[15..18], *b"GET");
        assert_eq!(payload[18], 0x00);
        assert_eq!(payload[19], 0x05);
        assert_eq!(&payload[20..25], b":path");
    }
}

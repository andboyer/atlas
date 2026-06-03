//! SAP / SDP listener for AES67 stream discovery.
//!
//! AES67 senders advertise themselves via Session Announcement Protocol
//! (RFC 2974) on `224.2.127.254:9875`. Each datagram carries a SAP
//! header followed by an SDP payload (RFC 8866) describing the stream:
//! multicast group, port, sample rate, channel count, ptime, payload
//! type. Joining the SAP group and parsing 5 seconds of announcements
//! gives us a free inventory of every AES67-capable transmitter in the
//! local VLAN — and pairs directly with the multicast snapshot in
//! [`probes::multicast`] to verify the receiver side joined them.
//!
//! Unprivileged on every platform. Listen window defaults to 8s
//! (advertisements typically repeat every 5-30s).

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

use crate::probes::iface as iface_probe;
use crate::types::{SapProbeResult, SapStream};

const SAP_PORT: u16 = 9875;
const SAP_GROUP: Ipv4Addr = Ipv4Addr::new(224, 2, 127, 254);

/// Synchronous blocking entrypoint — call from `tokio::task::spawn_blocking`.
pub fn run_blocking(iface: &str, listen_secs: u32) -> SapProbeResult {
    match listen_for_sap(iface, listen_secs) {
        Ok(r) => r,
        Err(e) => SapProbeResult {
            iface: iface.to_string(),
            listen_secs,
            streams: Vec::new(),
            verdict: "error".to_string(),
            error: Some(e.to_string()),
        },
    }
}

fn listen_for_sap(iface: &str, listen_secs: u32) -> anyhow::Result<SapProbeResult> {
    let iface_v4 = resolve_iface_v4(iface);

    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    {
        sock.set_reuse_port(true)?;
    }
    let bind: SocketAddr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, SAP_PORT).into();
    sock.bind(&bind.into())?;
    sock.set_multicast_loop_v4(false)?;
    if !iface_v4.is_unspecified() {
        sock.set_multicast_if_v4(&iface_v4)?;
    }
    sock.join_multicast_v4(&SAP_GROUP, &iface_v4)?;
    sock.set_read_timeout(Some(Duration::from_millis(500)))?;

    // Dedup by (origin + session_name) so the same advertised stream
    // repeated within the window is counted once.
    let mut streams: HashMap<String, SapStream> = HashMap::new();
    let deadline = Instant::now() + Duration::from_secs(listen_secs as u64);
    let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 4096];

    while Instant::now() < deadline {
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                let data: &[u8] = unsafe {
                    std::slice::from_raw_parts(buf.as_ptr() as *const u8, n)
                };
                let src_ip = from
                    .as_socket_ipv4()
                    .map(|a| a.ip().to_string())
                    .unwrap_or_default();
                if let Some(sdp) = parse_sap_payload(data) {
                    if let Some(stream) = parse_sdp(sdp, &src_ip) {
                        let key = format!("{}|{}", stream.origin, stream.session_name);
                        streams.entry(key).or_insert(stream);
                    }
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => continue,
        }
    }

    let streams: Vec<SapStream> = streams.into_values().collect();
    let verdict = if streams.is_empty() {
        "silent".to_string()
    } else {
        "streams_found".to_string()
    };

    Ok(SapProbeResult {
        iface: iface.to_string(),
        listen_secs,
        streams,
        verdict,
        error: None,
    })
}

fn resolve_iface_v4(iface: &str) -> Ipv4Addr {
    if iface.is_empty() || iface.eq_ignore_ascii_case("auto") || iface == "0.0.0.0" {
        return Ipv4Addr::UNSPECIFIED;
    }
    iface_probe::find_by_name(iface)
        .and_then(|i| i.ipv4)
        .and_then(|s| s.parse::<Ipv4Addr>().ok())
        .unwrap_or(Ipv4Addr::UNSPECIFIED)
}

/// Strip the SAP header per RFC 2974 §3 and return the SDP payload as
/// UTF-8. Returns None on malformed packets or when the announcement
/// type is `deletion` (we only care about adds).
fn parse_sap_payload(data: &[u8]) -> Option<&str> {
    if data.len() < 8 {
        return None;
    }
    let flags = data[0];
    let v = (flags >> 5) & 0x07;
    if v != 1 {
        // We only handle SAPv1 (the deployed standard).
        return None;
    }
    let is_deletion = (flags & 0x04) != 0;
    if is_deletion {
        return None;
    }
    let is_encrypted = (flags & 0x02) != 0;
    if is_encrypted {
        return None;
    }
    let is_ipv6 = (flags & 0x10) != 0;
    let auth_len_bytes = (data[1] as usize) * 4;
    let header_len = 8 + if is_ipv6 { 12 } else { 0 } + auth_len_bytes;
    if data.len() < header_len {
        return None;
    }
    let payload = &data[header_len..];

    // Optional MIME type prefix terminated by NUL. RFC 2974 §3 allows
    // it to be absent (legacy senders) — fall back to assuming SDP.
    let (payload, _mime) = match payload.iter().position(|&b| b == 0) {
        Some(idx) if idx < 64 && std::str::from_utf8(&payload[..idx]).is_ok() => {
            let mime = std::str::from_utf8(&payload[..idx]).unwrap_or("");
            if mime.eq_ignore_ascii_case("application/sdp") {
                (&payload[idx + 1..], mime)
            } else {
                // Unknown mime — assume entire payload is SDP.
                (payload, "")
            }
        }
        _ => (payload, ""),
    };

    std::str::from_utf8(payload).ok()
}

/// Parse the SDP description into a SapStream. Implements only the
/// fields we need; tolerant of missing lines.
fn parse_sdp(sdp: &str, src_ip: &str) -> Option<SapStream> {
    let mut origin = String::new();
    let mut session_name = String::new();
    let mut multicast_group: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut payload_type: Option<u8> = None;
    let mut sample_rate_hz: Option<u32> = None;
    let mut channels: Option<u8> = None;
    let mut ptime_ms: Option<f32> = None;

    for line in sdp.lines() {
        let line = line.trim_end_matches('\r');
        if line.len() < 2 || &line[1..2] != "=" {
            continue;
        }
        let key = &line[0..1];
        let val = &line[2..];
        match key {
            "o" => origin = val.to_string(),
            "s" => session_name = val.to_string(),
            "c" => {
                // c=IN IP4 239.69.123.45/64
                let parts: Vec<&str> = val.split_whitespace().collect();
                if parts.len() >= 3 {
                    let addr = parts[2].split('/').next().unwrap_or("");
                    if !addr.is_empty() {
                        multicast_group = Some(addr.to_string());
                    }
                }
            }
            "m" => {
                // m=audio 5004 RTP/AVP 96
                let parts: Vec<&str> = val.split_whitespace().collect();
                if parts.len() >= 4 && parts[0].eq_ignore_ascii_case("audio") {
                    if let Ok(p) = parts[1].parse::<u16>() {
                        port = Some(p);
                    }
                    if let Ok(pt) = parts[3].parse::<u8>() {
                        payload_type = Some(pt);
                    }
                }
            }
            "a" => {
                // a=rtpmap:96 L24/48000/8
                if let Some(rest) = val.strip_prefix("rtpmap:") {
                    let parts: Vec<&str> = rest.splitn(2, ' ').collect();
                    if parts.len() == 2 {
                        let codec_parts: Vec<&str> = parts[1].split('/').collect();
                        if codec_parts.len() >= 2 {
                            if let Ok(sr) = codec_parts[1].parse::<u32>() {
                                sample_rate_hz = Some(sr);
                            }
                        }
                        if codec_parts.len() >= 3 {
                            if let Ok(ch) = codec_parts[2].parse::<u8>() {
                                channels = Some(ch);
                            }
                        }
                    }
                } else if let Some(rest) = val.strip_prefix("ptime:") {
                    if let Ok(p) = rest.trim().parse::<f32>() {
                        ptime_ms = Some(p);
                    }
                }
            }
            _ => {}
        }
    }

    if origin.is_empty() && session_name.is_empty() {
        return None;
    }

    Some(SapStream {
        origin,
        session_name,
        multicast_group,
        port,
        sample_rate_hz,
        channels,
        payload_type,
        ptime_ms,
        source_ip: src_ip.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_aes67_sdp() {
        let sdp = "v=0\r\n\
            o=- 1 1 IN IP4 192.168.1.50\r\n\
            s=Atlas Test Stream\r\n\
            c=IN IP4 239.69.123.45/64\r\n\
            t=0 0\r\n\
            m=audio 5004 RTP/AVP 96\r\n\
            a=rtpmap:96 L24/48000/8\r\n\
            a=ptime:1\r\n";
        let stream = parse_sdp(sdp, "192.168.1.50").expect("parse");
        assert_eq!(stream.session_name, "Atlas Test Stream");
        assert_eq!(stream.multicast_group.as_deref(), Some("239.69.123.45"));
        assert_eq!(stream.port, Some(5004));
        assert_eq!(stream.payload_type, Some(96));
        assert_eq!(stream.sample_rate_hz, Some(48000));
        assert_eq!(stream.channels, Some(8));
        assert_eq!(stream.ptime_ms, Some(1.0));
    }

    #[test]
    fn rejects_sap_v2() {
        // Set version bits to 2 (unsupported).
        let mut pkt = vec![0u8; 16];
        pkt[0] = 0b0100_0000;
        assert!(parse_sap_payload(&pkt).is_none());
    }

    #[test]
    fn rejects_deletion_announcements() {
        let mut pkt = vec![0u8; 16];
        pkt[0] = 0b0010_0100; // v=1, T=1 (deletion)
        assert!(parse_sap_payload(&pkt).is_none());
    }

    #[test]
    fn parses_sap_v1_no_mime_prefix() {
        let sdp = b"v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=Test\r\nc=IN IP4 239.69.1.1/64\r\nm=audio 5004 RTP/AVP 96\r\n";
        let mut pkt: Vec<u8> = vec![0x20, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        pkt.extend_from_slice(sdp);
        let payload = parse_sap_payload(&pkt).expect("payload");
        assert!(payload.contains("s=Test"));
    }
}

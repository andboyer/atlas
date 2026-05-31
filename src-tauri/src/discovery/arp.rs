use anyhow::Result;
use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct ArpEntry {
    pub ip: String,
    pub mac: String,
    pub hostname_hint: Option<String>,
}

pub async fn read_arp_table() -> Result<Vec<ArpEntry>> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let out = Command::new("arp").arg("-an").output().await?;
        Ok(parse_arp_an(&String::from_utf8_lossy(&out.stdout)))
    }
    #[cfg(target_os = "windows")]
    {
        let out = Command::new("arp").arg("-a").output().await?;
        Ok(parse_arp_windows(&String::from_utf8_lossy(&out.stdout)))
    }
}

fn parse_arp_an(s: &str) -> Vec<ArpEntry> {
    // Examples:
    //   ? (192.168.1.84) at d4:9d:c0:ce:50:84 on en0 ifscope [ethernet]
    //   router.lan (192.168.1.1) at a4:2b:b0:11:22:33 on en0 ifscope [ethernet]
    let mut out = Vec::new();
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let name = line.split_whitespace().next().unwrap_or("?");
        let Some(open) = line.find('(') else { continue };
        let Some(close) = line.find(')') else {
            continue;
        };
        if close <= open + 1 {
            continue;
        }
        let ip = line[open + 1..close].to_string();
        let Some(at_idx) = line.find(" at ") else {
            continue;
        };
        let after_at = &line[at_idx + 4..];
        let mac = after_at.split_whitespace().next().unwrap_or("").to_string();
        if mac == "(incomplete)" || mac.is_empty() {
            continue;
        }
        let hostname_hint = if name != "?" {
            Some(name.to_string())
        } else {
            None
        };
        out.push(ArpEntry {
            ip,
            mac: normalize_mac(&mac),
            hostname_hint,
        });
    }
    out
}

#[cfg(target_os = "windows")]
fn parse_arp_windows(s: &str) -> Vec<ArpEntry> {
    // Lines look like:
    //   192.168.1.84         d4-9d-c0-ce-50-84     dynamic
    let mut out = Vec::new();
    for line in s.lines() {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[0].chars().filter(|c| *c == '.').count() == 3 {
            let mac = parts[1].replace('-', ":");
            out.push(ArpEntry {
                ip: parts[0].to_string(),
                mac: normalize_mac(&mac),
                hostname_hint: None,
            });
        }
    }
    out
}

/// Normalize a MAC address to lowercase, zero-padded hex with colons.
/// "a4:2b:b0:1:2:3" -> "a4:2b:b0:01:02:03"
pub fn normalize_mac(s: &str) -> String {
    s.split(':')
        .map(|seg| format!("{:0>2}", seg.to_ascii_lowercase()))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_short_mac_segments() {
        assert_eq!(normalize_mac("a4:2b:b0:1:2:3"), "a4:2b:b0:01:02:03");
        assert_eq!(normalize_mac("A4:2B:B0:11:22:33"), "a4:2b:b0:11:22:33");
    }

    #[test]
    fn parses_arp_an_with_and_without_hostname() {
        let sample = r#"
? (192.168.1.84) at d4:9d:c0:ce:50:84 on en0 ifscope [ethernet]
router.lan (192.168.1.1) at a4:2b:b0:11:22:33 on en0 ifscope [ethernet]
? (169.254.169.254) at (incomplete) on en0 [ethernet]
? (192.168.1.137) at 2c:0:ab:ad:5e:2 on en0 ifscope [ethernet]
"#;
        let entries = parse_arp_an(sample);
        assert_eq!(entries.len(), 3, "incomplete entry should be skipped");
        assert_eq!(entries[0].ip, "192.168.1.84");
        assert_eq!(entries[0].mac, "d4:9d:c0:ce:50:84");
        assert_eq!(entries[0].hostname_hint, None);
        assert_eq!(entries[1].hostname_hint.as_deref(), Some("router.lan"));
        // Short segments get zero-padded.
        assert_eq!(entries[2].mac, "2c:00:ab:ad:5e:02");
    }
}

//! Argument validators — strict allowlist for skill-pack command arguments.
//!
//! Skill packs declare each command's argument list with a `type` tag.
//! When the runbook engine renders `device.exec` arguments into the
//! command template, the validator MUST accept the value before any
//! template substitution happens. The motivation is two-fold:
//!
//!  1. **Block model hallucination.** An LLM that goes off-script and
//!     synthesises e.g. `iface = "Gi1/0/1; reload"` is rejected at this
//!     layer, even before the SSH transport sees the string. Validators
//!     are deliberately narrow — no general regex from the YAML.
//!  2. **Catch operator typos.** Same allowlist surfaces obvious mistakes
//!     in user-authored runbooks (`vlan = "core-vlan"` when the type is
//!     `vlan_id`) at edit time rather than after a failed remote call.

use thiserror::Error;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("missing required argument `{0}`")]
    Missing(String),
    #[error("argument `{name}` failed validation: expected {kind}, got `{actual}`")]
    BadValue {
        name: String,
        kind: String,
        actual: String,
    },
    #[error("argument `{0}` has unknown type tag `{1}`")]
    UnknownType(String, String),
}

/// Built-in validator kinds. Skill-pack TOML uses these as the `type`
/// field on each `args[]` entry. Unknown types fail closed.
#[derive(Debug, Clone, Copy)]
pub enum Kind {
    /// `1..=4094` per IEEE 802.1Q.
    VlanId,
    /// Cisco/Arista-style interface name: letters, digits, `/`, `-`, `.`.
    /// Length 2..=32. Examples: `Gi1/0/24`, `Te1/1/1.100`, `Ethernet48`,
    /// `Eth1/1`, `Po1`, `ge-0/0/1`.
    IfaceName,
    /// IPv4 dotted quad, no CIDR. Reject 0.0.0.0 and 255.255.255.255 to
    /// avoid `arp` etc. accidentally hitting the wire-edge addresses.
    Ipv4,
    /// MAC address in any common form (`aa:bb:cc:dd:ee:ff`,
    /// `aabb.ccdd.eeff`, `aabb-ccdd-eeff`). Normalised to lower-case
    /// colon form on output.
    Mac,
    /// PTP domain — 0..=127.
    PtpDomain,
    /// Plain port number 1..=65535.
    PortNumber,
    /// Site / org UUID for HTTPS controllers (UniFi, Omada). 32 hex chars
    /// optionally with dashes. Length 32..=36.
    SiteId,
    /// Free-form string limited to `[A-Za-z0-9_\-.: /]` and `len <= 64`.
    /// Used for command-line hostnames inside skill packs (BGP peers,
    /// LLDP neighbor names, etc.).
    SafeName,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "vlan_id" => Kind::VlanId,
            "iface_name" => Kind::IfaceName,
            "ipv4" => Kind::Ipv4,
            "mac" => Kind::Mac,
            "ptp_domain" => Kind::PtpDomain,
            "port_number" => Kind::PortNumber,
            "site_id" => Kind::SiteId,
            "safe_name" => Kind::SafeName,
            _ => return None,
        })
    }

    pub fn label(self) -> &'static str {
        match self {
            Kind::VlanId => "VLAN id (1-4094)",
            Kind::IfaceName => "interface name",
            Kind::Ipv4 => "IPv4 address",
            Kind::Mac => "MAC address",
            Kind::PtpDomain => "PTP domain (0-127)",
            Kind::PortNumber => "port number (1-65535)",
            Kind::SiteId => "controller site id",
            Kind::SafeName => "safe name string",
        }
    }
}

/// Validate one argument. Returns the canonicalised string form on success;
/// raw input is rejected on any character/length/range failure.
pub fn validate(name: &str, kind: Kind, value: &str) -> Result<String, ValidationError> {
    let bad = |actual: &str| ValidationError::BadValue {
        name: name.to_string(),
        kind: kind.label().to_string(),
        actual: actual.to_string(),
    };
    if value.is_empty() {
        return Err(ValidationError::Missing(name.into()));
    }
    match kind {
        Kind::VlanId => {
            let n: u32 = value.parse().map_err(|_| bad(value))?;
            if !(1..=4094).contains(&n) {
                return Err(bad(value));
            }
            Ok(n.to_string())
        }
        Kind::IfaceName => {
            if value.len() < 2 || value.len() > 32 {
                return Err(bad(value));
            }
            if !value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '.'))
            {
                return Err(bad(value));
            }
            Ok(value.to_string())
        }
        Kind::Ipv4 => {
            let parsed: std::net::Ipv4Addr = value.parse().map_err(|_| bad(value))?;
            let oct = parsed.octets();
            if oct == [0, 0, 0, 0] || oct == [255, 255, 255, 255] {
                return Err(bad(value));
            }
            Ok(parsed.to_string())
        }
        Kind::Mac => {
            let cleaned: String = value
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .map(|c| c.to_ascii_lowercase())
                .collect();
            if cleaned.len() != 12 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(bad(value));
            }
            let mut out = String::with_capacity(17);
            for (i, c) in cleaned.chars().enumerate() {
                if i > 0 && i % 2 == 0 {
                    out.push(':');
                }
                out.push(c);
            }
            Ok(out)
        }
        Kind::PtpDomain => {
            let n: u32 = value.parse().map_err(|_| bad(value))?;
            if n > 127 {
                return Err(bad(value));
            }
            Ok(n.to_string())
        }
        Kind::PortNumber => {
            let n: u32 = value.parse().map_err(|_| bad(value))?;
            if !(1..=65535).contains(&n) {
                return Err(bad(value));
            }
            Ok(n.to_string())
        }
        Kind::SiteId => {
            let cleaned: String = value
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .collect();
            if cleaned.len() != 32 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(bad(value));
            }
            Ok(value.to_string())
        }
        Kind::SafeName => {
            if value.len() > 64 {
                return Err(bad(value));
            }
            if !value.chars().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':' | '/' | ' ')
            }) {
                return Err(bad(value));
            }
            Ok(value.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vlan_id_accepts_range() {
        assert_eq!(validate("vlan", Kind::VlanId, "1").unwrap(), "1");
        assert_eq!(validate("vlan", Kind::VlanId, "4094").unwrap(), "4094");
    }

    #[test]
    fn vlan_id_rejects_oob() {
        assert!(validate("vlan", Kind::VlanId, "0").is_err());
        assert!(validate("vlan", Kind::VlanId, "4095").is_err());
        assert!(validate("vlan", Kind::VlanId, "abc").is_err());
        assert!(validate("vlan", Kind::VlanId, "1; reload").is_err());
    }

    #[test]
    fn iface_name_accepts_cisco_arista() {
        for ok in ["Gi1/0/24", "Te1/1/1.100", "Eth1/1", "Po1", "ge-0/0/1"] {
            validate("iface", Kind::IfaceName, ok).unwrap_or_else(|_| panic!("rejected {ok}"));
        }
    }

    #[test]
    fn iface_name_rejects_shell_meta() {
        for bad in [
            "Gi1/0/1; reload",
            "Gi1`reload`",
            "Gi$IFS",
            "G",
            "",
            "&&shutdown",
        ] {
            assert!(
                validate("iface", Kind::IfaceName, bad).is_err(),
                "accepted bad: {bad}"
            );
        }
    }

    #[test]
    fn ipv4_canonicalises() {
        assert_eq!(validate("ip", Kind::Ipv4, "10.0.0.2").unwrap(), "10.0.0.2");
        assert!(validate("ip", Kind::Ipv4, "0.0.0.0").is_err());
        assert!(validate("ip", Kind::Ipv4, "255.255.255.255").is_err());
        assert!(validate("ip", Kind::Ipv4, "not-an-ip").is_err());
    }

    #[test]
    fn mac_normalises_three_forms() {
        let expected = "aa:bb:cc:dd:ee:ff";
        assert_eq!(
            validate("m", Kind::Mac, "aa:bb:cc:dd:ee:ff").unwrap(),
            expected
        );
        assert_eq!(
            validate("m", Kind::Mac, "aabb.ccdd.eeff").unwrap(),
            expected
        );
        assert_eq!(
            validate("m", Kind::Mac, "aa-bb-cc-dd-ee-ff").unwrap(),
            expected
        );
        assert_eq!(validate("m", Kind::Mac, "AABBCCDDEEFF").unwrap(), expected);
    }

    #[test]
    fn ptp_domain_accepts_0_127() {
        validate("d", Kind::PtpDomain, "0").unwrap();
        validate("d", Kind::PtpDomain, "127").unwrap();
        assert!(validate("d", Kind::PtpDomain, "128").is_err());
    }
}

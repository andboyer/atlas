//! Skill pack loader.
//!
//! Each vendor pack is a single TOML file under `assets/skill-packs/<id>.toml`
//! and is embedded into the binary via `include_str!`. A pack declares the
//! catalogue of commands the runbook engine is allowed to send to a host
//! whose `skill = "<id>"`. Anything outside the catalogue is rejected by
//! the executor regardless of what the YAML runbook (or an LLM) asks for.
//!
//! TOML shape:
//!
//! ```toml
//! id = "cisco-ios"
//! name = "Cisco IOS / IOS-XE"
//! transport = "ssh"
//!
//! [[command]]
//! id = "show_interfaces"
//! risk = "read"
//! template = "show interfaces {iface}"
//! purpose = "Per-interface counters, errors, duplex, speed."
//! parser = "cisco_ios_show_interfaces"
//!
//!   [[command.args]]
//!   name = "iface"
//!   type = "iface_name"
//! ```
//!
//! HTTPS packs also carry `method = "GET" | "POST" | ...` and an optional
//! `body_template` for POST/PUT bodies.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tracing::warn;

use crate::device::Risk;

const BUNDLED: &[(&str, &str)] = &[
    (
        "cisco-ios",
        include_str!("../../../assets/skill-packs/cisco-ios.toml"),
    ),
    (
        "cisco-nxos",
        include_str!("../../../assets/skill-packs/cisco-nxos.toml"),
    ),
    (
        "extreme-exos",
        include_str!("../../../assets/skill-packs/extreme-exos.toml"),
    ),
    (
        "netgear-avline",
        include_str!("../../../assets/skill-packs/netgear-avline.toml"),
    ),
    (
        "tplink-omada",
        include_str!("../../../assets/skill-packs/tplink-omada.toml"),
    ),
    (
        "unifi",
        include_str!("../../../assets/skill-packs/unifi.toml"),
    ),
    (
        "luminex-gigacore",
        include_str!("../../../assets/skill-packs/luminex-gigacore.toml"),
    ),
    (
        "q-sys-core",
        include_str!("../../../assets/skill-packs/q-sys-core.toml"),
    ),
    (
        "mikrotik-routeros",
        include_str!("../../../assets/skill-packs/mikrotik-routeros.toml"),
    ),
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillPack {
    pub id: String,
    pub name: String,
    /// `ssh` or `https`. Must match the host's `transport` at exec time.
    pub transport: String,
    #[serde(default)]
    pub description: String,
    /// Optional login path / commands that the transport runs once per
    /// session before any real command (e.g. HTTPS controllers POST a
    /// login body and pick up a session cookie). v1 packs omit this and
    /// rely on the transport's default behaviour.
    #[serde(default)]
    pub login: Option<LoginSpec>,
    // TOML uses `[[command]]` blocks; the frontend expects a `commands`
    // array. Split the rename by direction so TOML still deserializes
    // from `command` while JSON serialized to the UI is `commands`.
    #[serde(rename(serialize = "commands", deserialize = "command"), default)]
    pub commands: Vec<CommandSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginSpec {
    /// HTTPS only: path to POST credentials to.
    #[serde(default)]
    pub path: String,
    /// Field names the controller expects in the login JSON body. For
    /// UniFi: `username`/`password`. For Omada: `username`/`password`.
    /// Both fields are populated from the host's `username` + keychain
    /// password.
    #[serde(default)]
    pub username_field: String,
    #[serde(default)]
    pub password_field: String,
    /// Optional API-key header name (Q-SYS Core JSON-RPC uses this shape).
    #[serde(default)]
    pub api_key_header: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandSpec {
    pub id: String,
    #[serde(default)]
    pub purpose: String,
    pub risk: Risk,
    /// Command template with `{arg}` placeholders.
    pub template: String,
    /// Used for HTTPS commands; ignored for SSH. Defaults to GET.
    #[serde(default = "default_method")]
    pub method: String,
    /// Optional JSON body template (HTTPS only). `{arg}` substitution
    /// happens before JSON parsing.
    #[serde(default)]
    pub body_template: String,
    /// Argument allowlist with type validators.
    #[serde(default)]
    pub args: Vec<ArgSpec>,
    /// Name of the parser this command's output is run through. See
    /// `device::parsers`. Empty means "return raw stdout".
    #[serde(default)]
    pub parser: String,
}

fn default_method() -> String {
    "GET".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgSpec {
    pub name: String,
    /// Validator id — must match a `device::validators::Kind` tag.
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub required: bool,
    /// Optional default value when the YAML runbook omits the argument.
    /// Validated through the same `Kind` validator before substitution.
    #[serde(default)]
    pub default: String,
}

#[derive(Debug, Clone, Default)]
pub struct PackRegistry {
    packs: HashMap<String, SkillPack>,
}

impl PackRegistry {
    pub fn get(&self, id: &str) -> Option<&SkillPack> {
        self.packs.get(id)
    }

    pub fn all(&self) -> Vec<&SkillPack> {
        let mut out: Vec<&SkillPack> = self.packs.values().collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }
}

#[derive(Debug, Error)]
pub enum PackError {
    #[error("unknown skill pack `{0}`")]
    UnknownPack(String),
    #[error("command `{cmd}` not in pack `{pack}`")]
    UnknownCommand { pack: String, cmd: String },
    #[error("validator: {0}")]
    Validation(#[from] crate::device::validators::ValidationError),
}

pub fn load_bundled() -> PackRegistry {
    let mut reg = PackRegistry::default();
    for (hint, src) in BUNDLED {
        match toml::from_str::<SkillPack>(src) {
            Ok(pack) => {
                if pack.id != *hint {
                    warn!("skill pack file `{hint}` declares id=`{}`", pack.id);
                }
                reg.packs.insert(pack.id.clone(), pack);
            }
            Err(e) => {
                warn!("failed to parse skill pack `{hint}`: {e}");
            }
        }
    }
    reg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_bundled_packs_parse() {
        let reg = load_bundled();
        assert_eq!(
            reg.all().len(),
            BUNDLED.len(),
            "one or more skill packs failed to parse"
        );
    }

    #[test]
    fn cisco_ios_has_read_and_mutate_commands() {
        let reg = load_bundled();
        let pack = reg.get("cisco-ios").expect("cisco-ios pack present");
        assert!(!pack.commands.is_empty(), "cisco-ios should ship commands");
        assert!(
            pack.commands.iter().any(|c| c.risk == Risk::Read),
            "cisco-ios should include read commands"
        );
        assert!(
            pack.commands.iter().any(|c| c.risk == Risk::Mutate),
            "cisco-ios should include at least one mutate command"
        );
    }

    #[test]
    fn pack_transport_is_ssh_or_https() {
        let reg = load_bundled();
        for pack in reg.all() {
            assert!(
                pack.transport == "ssh" || pack.transport == "https",
                "pack `{}` has unknown transport `{}`",
                pack.id,
                pack.transport
            );
        }
    }
}

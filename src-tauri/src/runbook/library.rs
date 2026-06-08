//! Bundled runbook library.
//!
//! Each YAML file under `assets/runbooks/*.yaml` is embedded into the
//! binary via `include_str!` at build time. We parse all of them at
//! startup; a malformed runbook logs a warning and is skipped rather
//! than crashing the process (since the rest of the library is still
//! useful).
//!
//! Phase 5 will add user-authored runbooks from the OS app-data dir on
//! top of this bundle.

use crate::runbook::Runbook;
use std::collections::HashMap;
use tracing::warn;

/// Static list of (id-hint, YAML source) pairs. The id-hint is used only
/// for error messages — the authoritative id is the `id:` field inside.
const BUNDLED: &[(&str, &str)] = &[
    (
        "dante-audio-dropouts",
        include_str!("../../../assets/runbooks/dante-audio-dropouts.yaml"),
    ),
    (
        "aes67-audio-dropouts",
        include_str!("../../../assets/runbooks/aes67-audio-dropouts.yaml"),
    ),
    (
        "dante-aes67-interop",
        include_str!("../../../assets/runbooks/dante-aes67-interop.yaml"),
    ),
    (
        "dante-device-unreachable",
        include_str!("../../../assets/runbooks/dante-device-unreachable.yaml"),
    ),
    (
        "aes67-stream-not-received",
        include_str!("../../../assets/runbooks/aes67-stream-not-received.yaml"),
    ),
    (
        "dante-latency-too-high",
        include_str!("../../../assets/runbooks/dante-latency-too-high.yaml"),
    ),
    (
        "ptp-multiple-grandmasters",
        include_str!("../../../assets/runbooks/ptp-multiple-grandmasters.yaml"),
    ),
    (
        "ptp-jittery-sync",
        include_str!("../../../assets/runbooks/ptp-jittery-sync.yaml"),
    ),
    (
        "ptp-domain-mismatch",
        include_str!("../../../assets/runbooks/ptp-domain-mismatch.yaml"),
    ),
    (
        "igmp-no-querier",
        include_str!("../../../assets/runbooks/igmp-no-querier.yaml"),
    ),
    (
        "igmp-multiple-queriers",
        include_str!("../../../assets/runbooks/igmp-multiple-queriers.yaml"),
    ),
    (
        "multicast-flooding",
        include_str!("../../../assets/runbooks/multicast-flooding.yaml"),
    ),
    (
        "qos-misconfigured",
        include_str!("../../../assets/runbooks/qos-misconfigured.yaml"),
    ),
    (
        "lldp-no-neighbor",
        include_str!("../../../assets/runbooks/lldp-no-neighbor.yaml"),
    ),
];

#[derive(Debug, Clone, Default)]
pub struct Library {
    by_id: HashMap<String, Runbook>,
}

impl Library {
    pub fn get(&self, id: &str) -> Option<&Runbook> {
        self.by_id.get(id)
    }

    pub fn all(&self) -> Vec<&Runbook> {
        let mut out: Vec<&Runbook> = self.by_id.values().collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    /// Merge user-authored YAML files from `dir/*.yaml` on top of any
    /// already-loaded runbooks. Entries with the same `id` override the
    /// bundled version — operators editing a copy of a shipped runbook
    /// don't have to rename it for the override to take effect.
    pub fn merge_dir(&mut self, dir: &std::path::Path) {
        let read = match std::fs::read_dir(dir) {
            Ok(r) => r,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!("user-runbook dir `{}`: {e}", dir.display());
                }
                return;
            }
        };
        for entry in read.flatten() {
            let path = entry.path();
            let is_yaml = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml"))
                .unwrap_or(false);
            if !is_yaml {
                continue;
            }
            let src = match std::fs::read_to_string(&path) {
                Ok(s) => s,
                Err(e) => {
                    warn!("failed to read user runbook `{}`: {e}", path.display());
                    continue;
                }
            };
            match serde_yaml_ng::from_str::<Runbook>(&src) {
                Ok(rb) => {
                    self.by_id.insert(rb.id.clone(), rb);
                }
                Err(e) => {
                    warn!("failed to parse user runbook `{}`: {e}", path.display());
                }
            }
        }
    }
}

pub fn load_bundled() -> Library {
    let mut lib = Library::default();
    for (hint, src) in BUNDLED {
        match serde_yaml_ng::from_str::<Runbook>(src) {
            Ok(rb) => {
                if rb.id != *hint {
                    warn!("runbook id mismatch: file `{hint}` declares id=`{}`", rb.id);
                }
                lib.by_id.insert(rb.id.clone(), rb);
            }
            Err(e) => {
                warn!("failed to parse bundled runbook `{hint}`: {e}");
            }
        }
    }
    lib
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_runbooks_parse() {
        let lib = load_bundled();
        assert!(
            !lib.all().is_empty(),
            "expected at least one bundled runbook"
        );
        // Every bundled file should round-trip cleanly.
        assert_eq!(
            lib.all().len(),
            BUNDLED.len(),
            "one or more bundled runbooks failed to parse"
        );
    }

    #[test]
    fn well_known_runbooks_present() {
        let lib = load_bundled();
        for required in [
            "dante-audio-dropouts",
            "aes67-audio-dropouts",
            "igmp-no-querier",
            "ptp-multiple-grandmasters",
        ] {
            assert!(
                lib.get(required).is_some(),
                "runbook `{required}` not in library"
            );
        }
    }
}

//! Per-skill-pack output parsers.
//!
//! Skill-pack TOML names a parser per command (e.g.
//! `parser = "cisco_ios_show_ip_igmp_snooping"`). The runbook engine
//! routes the raw stdout through `parse_named(name, stdout)` before
//! binding the result to the step's `bind:` slot, so YAML guards
//! (`querier.address is null`, `snoop.snooping_enabled == false`) operate
//! on structured JSON, not regex-on-text.
//!
//! Parsers are intentionally hand-rolled regex per command (no TextFSM /
//! ntc-templates dep — keeps the binary small and avoids the runtime
//! template-loader). Each returns `serde_json::Value`. Missing fields
//! materialise as `null` so guard expressions degrade gracefully.

use regex::Regex;
use serde_json::{json, Value};

/// Dispatch by parser name. Unknown names return the raw stdout wrapped
/// in `{"raw": "..."}` so the YAML can still bind it without errors.
pub fn parse_named(name: &str, stdout: &str) -> Value {
    match name {
        "cisco_ios_show_ip_igmp_snooping" => cisco_ios_show_ip_igmp_snooping(stdout),
        "cisco_ios_show_ip_igmp_snooping_querier" => {
            cisco_ios_show_ip_igmp_snooping_querier(stdout)
        }
        "cisco_ios_show_ip_igmp_snooping_groups" => cisco_ios_show_ip_igmp_snooping_groups(stdout),
        "cisco_ios_show_ptp_clock" => cisco_ios_show_ptp_clock(stdout),
        "cisco_ios_show_interfaces" => cisco_ios_show_interfaces(stdout),
        "cisco_ios_show_lldp_neighbors_detail" => cisco_ios_show_lldp_neighbors_detail(stdout),
        "cisco_ios_show_mls_qos_interface" => cisco_ios_show_mls_qos_interface(stdout),
        "extreme_show_igmp_snooping" => extreme_show_igmp_snooping(stdout),
        "json_passthrough" => parse_json_passthrough(stdout),
        "" => json!({ "raw": stdout }),
        other => json!({ "raw": stdout, "parser_not_implemented": other }),
    }
}

/// Best-effort JSON parse — used for HTTPS controllers whose responses
/// are already JSON. Falls back to `{"raw": "..."}` on parse failure.
fn parse_json_passthrough(stdout: &str) -> Value {
    match serde_json::from_str::<Value>(stdout) {
        Ok(v) => v,
        Err(_) => json!({ "raw": stdout }),
    }
}

// ── Cisco IOS / IOS-XE parsers ───────────────────────────────────────────────

/// `show ip igmp snooping`
/// Captures: `snooping_enabled: bool`, `vlan_count: int`, `raw: string`.
fn cisco_ios_show_ip_igmp_snooping(stdout: &str) -> Value {
    // "Global IGMP Snooping configuration: Enabled" / "Disabled"
    let enabled_re = Regex::new(r"(?i)Global IGMP Snooping configuration:\s*Enabled").unwrap();
    let snooping_enabled = enabled_re.is_match(stdout);
    let vlan_re = Regex::new(r"(?im)^\s*Vlan\s+(\d+)\s*:").unwrap();
    let vlan_count = vlan_re.captures_iter(stdout).count();
    json!({
        "snooping_enabled": snooping_enabled,
        "vlan_count": vlan_count,
        "raw": stdout,
    })
}

/// `show ip igmp snooping querier`
/// Returns `address` (string or null), `version` (int or null),
/// `interval_seconds` (int or null).
fn cisco_ios_show_ip_igmp_snooping_querier(stdout: &str) -> Value {
    let addr_re = Regex::new(r"(?i)IP address\s*:\s*(\d+\.\d+\.\d+\.\d+)").unwrap();
    let ver_re = Regex::new(r"(?i)IGMP version\s*:\s*v?(\d+)").unwrap();
    let int_re = Regex::new(r"(?i)Query interval\s*:\s*(\d+)").unwrap();
    let address = addr_re
        .captures(stdout)
        .map(|c| c[1].to_string())
        .map(Value::String)
        .unwrap_or(Value::Null);
    let version = ver_re
        .captures(stdout)
        .and_then(|c| c[1].parse::<u32>().ok())
        .map(|n| json!(n))
        .unwrap_or(Value::Null);
    let interval_seconds = int_re
        .captures(stdout)
        .and_then(|c| c[1].parse::<u32>().ok())
        .map(|n| json!(n))
        .unwrap_or(Value::Null);
    json!({
        "address": address,
        "version": version,
        "interval_seconds": interval_seconds,
        "raw": stdout,
    })
}

/// `show ip igmp snooping groups`
/// Returns `{groups: [{vlan, group, interfaces: [...]}], group_count}`.
fn cisco_ios_show_ip_igmp_snooping_groups(stdout: &str) -> Value {
    // Lines look like: " 100   239.69.0.1    igmp,v2   3:24    Gi1/0/24"
    let row_re =
        Regex::new(r"(?m)^\s*(\d{1,4})\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+(.+)$").unwrap();
    let mut groups = Vec::new();
    for cap in row_re.captures_iter(stdout) {
        let vlan: u32 = cap[1].parse().unwrap_or(0);
        let group = cap[2].to_string();
        let interfaces: Vec<String> = cap[3]
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        groups.push(json!({
            "vlan": vlan,
            "group": group,
            "interfaces": interfaces,
        }));
    }
    json!({
        "group_count": groups.len(),
        "groups": groups,
    })
}

/// `show ptp clock`
fn cisco_ios_show_ptp_clock(stdout: &str) -> Value {
    let domain_re = Regex::new(r"(?i)Domain\s+number:\s*(\d+)").unwrap();
    let prio1_re = Regex::new(r"(?i)Priority1:\s*(\d+)").unwrap();
    let prio2_re = Regex::new(r"(?i)Priority2:\s*(\d+)").unwrap();
    let mode_re = Regex::new(r"(?i)PTP clock mode:\s*(\S+)").unwrap();
    let domain = domain_re
        .captures(stdout)
        .and_then(|c| c[1].parse::<u32>().ok())
        .map(|n| json!(n))
        .unwrap_or(Value::Null);
    let priority1 = prio1_re
        .captures(stdout)
        .and_then(|c| c[1].parse::<u32>().ok())
        .map(|n| json!(n))
        .unwrap_or(Value::Null);
    let priority2 = prio2_re
        .captures(stdout)
        .and_then(|c| c[1].parse::<u32>().ok())
        .map(|n| json!(n))
        .unwrap_or(Value::Null);
    let mode = mode_re
        .captures(stdout)
        .map(|c| c[1].to_string())
        .map(Value::String)
        .unwrap_or(Value::Null);
    json!({
        "domain": domain,
        "priority1": priority1,
        "priority2": priority2,
        "mode": mode,
        "raw": stdout,
    })
}

/// `show interfaces <iface>` — single-iface summary.
fn cisco_ios_show_interfaces(stdout: &str) -> Value {
    let line_re = Regex::new(r"(?i)line protocol is\s+(\w+)").unwrap();
    let dup_re = Regex::new(r"(?i)(Full|Half)-duplex").unwrap();
    let speed_re = Regex::new(r"(?i)(\d+)\s*[KMG]?b/s").unwrap();
    let errs_re = Regex::new(r"(?i)(\d+)\s+input errors").unwrap();
    let link_protocol = line_re
        .captures(stdout)
        .map(|c| c[1].to_lowercase())
        .map(Value::String)
        .unwrap_or(Value::Null);
    let duplex = dup_re
        .captures(stdout)
        .map(|c| c[1].to_lowercase())
        .map(Value::String)
        .unwrap_or(Value::Null);
    let speed_text = speed_re
        .captures(stdout)
        .map(|c| c[0].to_string())
        .map(Value::String)
        .unwrap_or(Value::Null);
    let input_errors = errs_re
        .captures(stdout)
        .and_then(|c| c[1].parse::<u64>().ok())
        .map(|n| json!(n))
        .unwrap_or(Value::Null);
    json!({
        "link_protocol": link_protocol,
        "duplex": duplex,
        "speed_text": speed_text,
        "input_errors": input_errors,
        "raw": stdout,
    })
}

/// `show lldp neighbors detail`
fn cisco_ios_show_lldp_neighbors_detail(stdout: &str) -> Value {
    let sys_re = Regex::new(r"(?i)System Name:\s*(\S+)").unwrap();
    let chassis_re = Regex::new(r"(?i)Chassis id:\s*(\S+)").unwrap();
    let port_re = Regex::new(r"(?i)Port id:\s*(\S+)").unwrap();
    let mut neighbors = Vec::new();
    for sys in sys_re.captures_iter(stdout) {
        neighbors.push(json!({"system_name": sys[1].to_string()}));
    }
    let chassis: Vec<Value> = chassis_re
        .captures_iter(stdout)
        .map(|c| json!(c[1].to_string()))
        .collect();
    let ports: Vec<Value> = port_re
        .captures_iter(stdout)
        .map(|c| json!(c[1].to_string()))
        .collect();
    json!({
        "neighbor_count": neighbors.len(),
        "system_names": neighbors,
        "chassis_ids": chassis,
        "port_ids": ports,
        "raw": stdout,
    })
}

/// `show mls qos interface <iface>`
fn cisco_ios_show_mls_qos_interface(stdout: &str) -> Value {
    let drop_re = Regex::new(r"(?im)^\s*queue\s+\d+\s+drops:\s*(\d+)").unwrap();
    let mut priority_drops: u64 = 0;
    for cap in drop_re.captures_iter(stdout) {
        priority_drops = priority_drops.saturating_add(cap[1].parse::<u64>().unwrap_or(0));
    }
    let qos_enabled = stdout.to_lowercase().contains("trust dscp");
    json!({
        "priority_drops": priority_drops,
        "qos_enabled": qos_enabled,
        "raw": stdout,
    })
}

// ── Extreme EXOS ─────────────────────────────────────────────────────────────

fn extreme_show_igmp_snooping(stdout: &str) -> Value {
    let enabled = stdout.to_lowercase().contains("igmp snooping: enabled");
    json!({
        "snooping_enabled": enabled,
        "raw": stdout,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cisco_igmp_snooping_enabled() {
        let v = cisco_ios_show_ip_igmp_snooping(
            "Global IGMP Snooping configuration: Enabled\n  Vlan 100 :\n  Vlan 200 :\n",
        );
        assert_eq!(v["snooping_enabled"], json!(true));
        assert_eq!(v["vlan_count"], json!(2));
    }

    #[test]
    fn parses_cisco_igmp_snooping_disabled() {
        let v = cisco_ios_show_ip_igmp_snooping("Global IGMP Snooping configuration: Disabled\n");
        assert_eq!(v["snooping_enabled"], json!(false));
        assert_eq!(v["vlan_count"], json!(0));
    }

    #[test]
    fn parses_cisco_querier() {
        let s = "Vlan 100: IGMP snooping querier status\n IP address       : 10.0.0.1\n IGMP version     : v2\n Query interval   : 60\n";
        let v = cisco_ios_show_ip_igmp_snooping_querier(s);
        assert_eq!(v["address"], json!("10.0.0.1"));
        assert_eq!(v["version"], json!(2));
        assert_eq!(v["interval_seconds"], json!(60));
    }

    #[test]
    fn querier_returns_null_when_missing() {
        let v = cisco_ios_show_ip_igmp_snooping_querier(
            "Vlan 100: No querier configured on this VLAN\n",
        );
        assert_eq!(v["address"], Value::Null);
        assert_eq!(v["version"], Value::Null);
    }

    #[test]
    fn parses_cisco_ptp_clock_domain() {
        let s = "PTP CLOCK INFO\n  Domain number: 4\n  Priority1: 128\n  Priority2: 128\n  PTP clock mode: BOUNDARY-CLOCK\n";
        let v = cisco_ios_show_ptp_clock(s);
        assert_eq!(v["domain"], json!(4));
        assert_eq!(v["priority1"], json!(128));
        assert_eq!(v["mode"], json!("BOUNDARY-CLOCK"));
    }

    #[test]
    fn parses_interfaces_full_duplex_up() {
        let s = "GigabitEthernet1/0/24 is up, line protocol is up\n  Full-duplex, 1000Mb/s\n  0 input errors, 0 CRC, 0 frame\n";
        let v = cisco_ios_show_interfaces(s);
        assert_eq!(v["link_protocol"], json!("up"));
        assert_eq!(v["duplex"], json!("full"));
        assert_eq!(v["input_errors"], json!(0));
    }

    #[test]
    fn parses_lldp_neighbors_counts() {
        let s = "Local Intf: Gi1/0/24\n System Name: edge-sw-1\n Chassis id: 0011.2233.4455\n Port id: Gi0/1\n";
        let v = cisco_ios_show_lldp_neighbors_detail(s);
        assert_eq!(v["neighbor_count"], json!(1));
        assert_eq!(v["chassis_ids"][0], json!("0011.2233.4455"));
    }

    #[test]
    fn json_passthrough_returns_parsed() {
        let v = parse_named("json_passthrough", r#"{"sites":[{"id":"abc"}]}"#);
        assert_eq!(v["sites"][0]["id"], json!("abc"));
    }

    #[test]
    fn json_passthrough_falls_back_on_invalid() {
        let v = parse_named("json_passthrough", "<html>not json</html>");
        assert!(v["raw"].is_string());
    }

    #[test]
    fn unknown_parser_keeps_raw() {
        let v = parse_named("does-not-exist", "raw text");
        assert_eq!(v["raw"], json!("raw text"));
        assert_eq!(v["parser_not_implemented"], json!("does-not-exist"));
    }
}

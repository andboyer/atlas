//! OS keychain wrapper for switch / controller credentials.
//!
//! Uses the `keyring` crate which routes to:
//!  * macOS — Keychain Services (login keychain)
//!  * Windows — Credential Manager (generic credentials)
//!  * Linux — Secret Service (gnome-keyring, kwallet, etc.)
//!
//! Service name is constant (`com.andboyer.atlas`); the account id is the
//! inventory `host.id`. We store ONE secret per host: SSH password, SSH
//! key passphrase, controller password, or API key — the inventory's
//! `auth` field disambiguates what the secret is for.
//!
//! Secrets NEVER hit `hosts.toml`, the audit log, or the LLM prompt.
//! `device.exec` reads the secret at command-fire time and the in-memory
//! string is dropped immediately after the transport returns.

const SERVICE_NAME: &str = "com.andboyer.atlas";

#[derive(Debug, thiserror::Error)]
pub enum KeychainError {
    #[error("keychain backend unavailable: {0}")]
    Backend(String),
    #[error("no secret stored for host `{0}`")]
    NotFound(String),
    #[error("io error talking to keychain: {0}")]
    Io(String),
}

fn entry(host_id: &str) -> Result<keyring::Entry, KeychainError> {
    keyring::Entry::new(SERVICE_NAME, host_id).map_err(|e| KeychainError::Backend(e.to_string()))
}

/// Store (or overwrite) the secret for one inventory host.
pub fn set(host_id: &str, secret: &str) -> Result<(), KeychainError> {
    let e = entry(host_id)?;
    e.set_password(secret)
        .map_err(|e| KeychainError::Io(e.to_string()))
}

/// Fetch the secret for a host. Returns `NotFound` if the operator never
/// configured one (e.g. SSH key-only auth, or HTTPS API key).
pub fn get(host_id: &str) -> Result<String, KeychainError> {
    let e = entry(host_id)?;
    match e.get_password() {
        Ok(s) => Ok(s),
        Err(keyring::Error::NoEntry) => Err(KeychainError::NotFound(host_id.into())),
        Err(other) => Err(KeychainError::Io(other.to_string())),
    }
}

/// Delete the secret for a host (called when the operator removes the host
/// from the inventory). Idempotent: a missing entry returns `Ok(())`.
pub fn delete(host_id: &str) -> Result<(), KeychainError> {
    let e = entry(host_id)?;
    match e.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(other) => Err(KeychainError::Io(other.to_string())),
    }
}

/// Returns true if the operator has stored a secret for this host.
/// Convenience for the inventory UI's "✓ password set" indicator without
/// actually surfacing the secret to the renderer.
pub fn has(host_id: &str) -> bool {
    get(host_id).is_ok()
}

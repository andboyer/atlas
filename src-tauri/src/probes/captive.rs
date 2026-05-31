//! Captive portal detection via a lightweight HTTP probe.
//!
//! We GET `http://connectivitycheck.gstatic.com/generate_204` with a short
//! timeout. A healthy, open internet connection returns HTTP 204. Any other
//! response (200 redirect to a login page, 302, etc.) indicates a captive
//! portal is intercepting traffic.

/// Return `true` if a captive portal is intercepting traffic.
/// Returns `false` on any network error to avoid false positives when the
/// connection is genuinely broken (the latency/loss rules will catch that).
pub async fn is_captive_portal() -> bool {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    match client
        .get("http://connectivitycheck.gstatic.com/generate_204")
        .send()
        .await
    {
        Ok(r) => r.status().as_u16() != 204,
        Err(_) => false,
    }
}

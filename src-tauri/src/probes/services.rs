use crate::types::ServiceProbe;
use std::net::ToSocketAddrs;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::{timeout, Duration};

/// Probe a list of `host:port` targets via TCP connect (with a short timeout).
/// Returns one `ServiceProbe` per target, ordered the same as `targets`.
///
/// This is intentionally a TCP-connect-only probe: it confirms DNS resolves,
/// the host is reachable, and the port accepts connections, which is
/// sufficient evidence that a SaaS endpoint (e.g. `*.clover.com:443`) is
/// reachable from this network. Full TLS handshake checks are a follow-up.
pub async fn probe_services(targets: &[String]) -> Vec<ServiceProbe> {
    if targets.is_empty() {
        return vec![];
    }

    let mut set: JoinSet<(usize, ServiceProbe)> = JoinSet::new();
    for (i, target) in targets.iter().enumerate() {
        let t = target.clone();
        set.spawn(async move {
            let probe = probe_one(&t).await;
            (i, probe)
        });
    }

    let mut results: Vec<Option<ServiceProbe>> = (0..targets.len()).map(|_| None).collect();
    while let Some(r) = set.join_next().await {
        if let Ok((idx, probe)) = r {
            results[idx] = Some(probe);
        }
    }
    results.into_iter().flatten().collect()
}

async fn probe_one(target: &str) -> ServiceProbe {
    // Default to :443 if no port specified.
    let target_with_port = if target.contains(':') {
        target.to_string()
    } else {
        format!("{target}:443")
    };

    // DNS resolve (offload to blocking thread since to_socket_addrs is sync).
    let target_clone = target_with_port.clone();
    let resolved = tokio::task::spawn_blocking(move || {
        target_clone
            .to_socket_addrs()
            .map(|i| i.collect::<Vec<_>>())
    })
    .await;

    let addrs = match resolved {
        Ok(Ok(addrs)) if !addrs.is_empty() => addrs,
        Ok(Ok(_)) => {
            return ServiceProbe {
                target: target.to_string(),
                reachable: false,
                latency_ms: None,
                error: Some("DNS returned no addresses".to_string()),
            };
        }
        Ok(Err(e)) => {
            return ServiceProbe {
                target: target.to_string(),
                reachable: false,
                latency_ms: None,
                error: Some(format!("DNS error: {e}")),
            };
        }
        Err(e) => {
            return ServiceProbe {
                target: target.to_string(),
                reachable: false,
                latency_ms: None,
                error: Some(format!("DNS task error: {e}")),
            };
        }
    };

    let start = Instant::now();
    let connect_fut = TcpStream::connect(addrs.as_slice());
    match timeout(Duration::from_secs(3), connect_fut).await {
        Ok(Ok(_stream)) => {
            let elapsed_ms = start.elapsed().as_secs_f32() * 1000.0;
            ServiceProbe {
                target: target.to_string(),
                reachable: true,
                latency_ms: Some(elapsed_ms),
                error: None,
            }
        }
        Ok(Err(e)) => ServiceProbe {
            target: target.to_string(),
            reachable: false,
            latency_ms: None,
            error: Some(format!("connect: {e}")),
        },
        Err(_) => ServiceProbe {
            target: target.to_string(),
            reachable: false,
            latency_ms: None,
            error: Some("timeout".to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_targets_returns_empty() {
        let res = probe_services(&[]).await;
        assert!(res.is_empty());
    }

    #[tokio::test]
    async fn invalid_host_reports_unreachable() {
        let targets = vec!["host-that-does-not-exist.invalid:443".to_string()];
        let res = probe_services(&targets).await;
        assert_eq!(res.len(), 1);
        assert!(!res[0].reachable);
        assert!(res[0].error.is_some());
    }
}

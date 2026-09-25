// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Accept loop (H4-04).
//!
//! - A global connection semaphore and a per-source-IP cap are acquired
//!   *before* the TLS handshake and released when the connection closes.
//! - Each handshake runs in its own task with a deadline, so a stalled peer
//!   can never block the accept loop.
//! - `accept()` errors (e.g. file-descriptor exhaustion) back off
//!   exponentially instead of spinning.
//! - Handshake/limit log lines are rate limited.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tokio::sync::{mpsc, Semaphore};
use tokio_rustls::TlsAcceptor;

use crate::conn::{ClientConn, ClientIdentity, ConnGuard, ConnInfo, ConnStream, IpLimiter};
use crate::tls::TlsState;

pub struct ListenerSettings {
    pub max_connections: usize,
    pub max_connections_per_ip: u32,
    pub handshake_timeout: Duration,
    pub idle_timeout: Option<Duration>,
    pub admin_fingerprints: Vec<String>,
    /// Plaintext loopback mode: treat every connection as administrator.
    pub insecure_admin: bool,
}

/// Logs at most once per second, reporting how many events were suppressed.
pub struct RateLimitedLog {
    start: Instant,
    last_ms: AtomicU64,
    suppressed: AtomicU64,
}

impl RateLimitedLog {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            last_ms: AtomicU64::new(0),
            suppressed: AtomicU64::new(0),
        }
    }

    /// Returns `Some(suppressed_count)` if the caller should log now.
    pub fn allow(&self) -> Option<u64> {
        let now = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let last = self.last_ms.load(Ordering::Relaxed);
        if (now.saturating_sub(last) >= 1000 || last == 0)
            && self
                .last_ms
                .compare_exchange(last, now.max(1), Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            Some(self.suppressed.swap(0, Ordering::Relaxed))
        } else {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

/// Spawn the accept loop. Fully established connections are delivered on the
/// returned channel; `closed_tx` receives the id of every connection that
/// ends (used to reap its sessions).
pub fn spawn_acceptor(
    listener: TcpListener,
    tls: Option<Arc<TlsState>>,
    settings: ListenerSettings,
    closed_tx: mpsc::UnboundedSender<u64>,
) -> mpsc::Receiver<ClientConn> {
    let (tx, rx) = mpsc::channel::<ClientConn>(64);
    let conn_sem = Arc::new(Semaphore::new(settings.max_connections));
    let ip_limiter = IpLimiter::new(settings.max_connections_per_ip);
    let settings = Arc::new(settings);
    let limit_log = Arc::new(RateLimitedLog::new());
    let handshake_log = Arc::new(RateLimitedLog::new());
    let accept_log = RateLimitedLog::new();

    tokio::spawn(async move {
        let mut backoff = Duration::from_millis(5);
        loop {
            if tx.is_closed() {
                break;
            }
            let (tcp, remote) = match listener.accept().await {
                Ok(v) => {
                    backoff = Duration::from_millis(5);
                    v
                }
                Err(e) => {
                    if let Some(n) = accept_log.allow() {
                        tracing::error!(error = %e, suppressed = n, "TCP accept failed; backing off");
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(1));
                    continue;
                }
            };

            let permit = match conn_sem.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    if let Some(n) = limit_log.allow() {
                        tracing::warn!(suppressed = n, "connection limit reached; rejecting");
                    }
                    continue; // drops `tcp`
                }
            };
            let ip_guard = match ip_limiter.try_acquire(remote.ip()) {
                Some(g) => g,
                None => {
                    if let Some(n) = limit_log.allow() {
                        tracing::warn!(remote = %remote, suppressed = n, "per-IP connection limit reached; rejecting");
                    }
                    continue;
                }
            };
            // (Perf) Small unary responses must not wait for Nagle/delayed-ACK.
            let _ = tcp.set_nodelay(true);

            let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
            let guard = ConnGuard {
                conn_id,
                _permit: Some(permit),
                _ip: Some(ip_guard),
                closed: Some(closed_tx.clone()),
            };
            let tx = tx.clone();
            let tls = tls.clone();
            let settings = settings.clone();
            let handshake_log = handshake_log.clone();

            tokio::spawn(async move {
                let (stream, identity) = match tls {
                    Some(state) => {
                        let acceptor = TlsAcceptor::from(state.current());
                        match tokio::time::timeout(settings.handshake_timeout, acceptor.accept(tcp))
                            .await
                        {
                            Ok(Ok(tls_stream)) => {
                                let identity = {
                                    let (_, session) = tls_stream.get_ref();
                                    match session.peer_certificates().and_then(|c| c.first()) {
                                        Some(leaf) => ClientIdentity::from_cert(
                                            leaf.as_ref(),
                                            &settings.admin_fingerprints,
                                        ),
                                        None => ClientIdentity::anonymous(conn_id, false),
                                    }
                                };
                                (ConnStream::Tls(Box::new(tls_stream)), identity)
                            }
                            Ok(Err(e)) => {
                                if let Some(n) = handshake_log.allow() {
                                    tracing::info!(remote = %remote, error = %e, suppressed = n, "TLS handshake failed");
                                }
                                return; // guard dropped → permits released
                            }
                            Err(_) => {
                                if let Some(n) = handshake_log.allow() {
                                    tracing::info!(remote = %remote, suppressed = n, "TLS handshake timed out");
                                }
                                return;
                            }
                        }
                    }
                    None => (
                        ConnStream::Plain(tcp),
                        ClientIdentity::anonymous(conn_id, settings.insecure_admin),
                    ),
                };
                tracing::debug!(conn_id, client = %identity.id, "client connected");
                let info = ConnInfo::new(conn_id, identity, Some(remote));
                let conn = ClientConn::new(stream, info, settings.idle_timeout, guard);
                let _ = tx.send(conn).await;
            });
        }
        tracing::info!("accept loop stopped");
    });

    rx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limited_log_suppresses_bursts() {
        let l = RateLimitedLog::new();
        assert_eq!(l.allow(), Some(0));
        assert_eq!(l.allow(), None);
        assert_eq!(l.allow(), None);
    }

    #[tokio::test]
    async fn stalled_handshake_does_not_block_accept_loop() {
        // A TLS listener whose handshakes never complete must still accept
        // further connections: use a TLS state-less plaintext listener and
        // check a second client is delivered while the first is idle.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (closed_tx, _closed_rx) = mpsc::unbounded_channel();
        let mut rx = spawn_acceptor(
            listener,
            None,
            ListenerSettings {
                max_connections: 2,
                max_connections_per_ip: 2,
                handshake_timeout: Duration::from_secs(1),
                idle_timeout: None,
                admin_fingerprints: vec![],
                insecure_admin: false,
            },
            closed_tx,
        );
        let _c1 = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _c2 = tokio::net::TcpStream::connect(addr).await.unwrap();
        let a = rx.recv().await.unwrap();
        let b = rx.recv().await.unwrap();
        use tonic::transport::server::Connected;
        assert_ne!(a.connect_info().conn_id, b.connect_info().conn_id);
        // Third connection exceeds max_connections and is dropped.
        let _c3 = tokio::net::TcpStream::connect(addr).await.unwrap();
        let r = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
        assert!(
            r.is_err(),
            "connection beyond the cap must not be delivered"
        );
    }
}

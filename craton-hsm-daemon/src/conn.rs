// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Client identity and per-connection tracking.
//!
//! Every accepted connection is wrapped in a [`ClientConn`], which
//! - carries the authenticated client identity (SHA-256 fingerprint of the
//!   mTLS client certificate, or a per-connection anonymous identity when
//!   client authentication is disabled) into every request via tonic's
//!   `Connected` / request-extension mechanism (H4-01);
//! - holds the global connection permit and the per-IP slot, released when
//!   the connection is dropped (H4-04);
//! - closes the connection after `connection_idle_timeout_secs` without RPCs
//!   (H4-04);
//! - notifies the daemon when the connection goes away so that the sessions
//!   it opened can be closed (H4-10).

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, OwnedSemaphorePermit};
use tokio::time::Sleep;
use tonic::transport::server::Connected;

/// The principal on whose behalf a request is executed.
#[derive(Debug)]
pub struct ClientIdentity {
    /// Stable identifier: `cert:<sha256-hex>` for mTLS clients,
    /// `anon:<connection-id>` for unauthenticated connections.
    pub id: Arc<str>,
    /// True when the identity comes from a verified client certificate.
    pub authenticated: bool,
    /// True when the identity holds the administrator role (InitToken, SO).
    pub is_admin: bool,
}

impl ClientIdentity {
    /// Identity derived from a verified client certificate (DER).
    pub fn from_cert(cert_der: &[u8], admin_fingerprints: &[String]) -> Self {
        let fp = cert_fingerprint(cert_der);
        let is_admin = admin_fingerprints.iter().any(|a| a == &fp);
        Self {
            id: Arc::from(format!("cert:{}", fp)),
            authenticated: true,
            is_admin,
        }
    }

    /// Anonymous identity scoped to a single connection.
    pub fn anonymous(conn_id: u64, is_admin: bool) -> Self {
        Self {
            id: Arc::from(format!("anon:{}", conn_id)),
            authenticated: false,
            is_admin,
        }
    }
}

/// SHA-256 fingerprint (lowercase hex) of a DER certificate.
pub fn cert_fingerprint(cert_der: &[u8]) -> String {
    use craton_hsm::pkcs11_abi::constants::CKM_SHA256;
    let digest =
        craton_hsm::crypto::digest::compute_digest(CKM_SHA256, cert_der).unwrap_or_default();
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

/// RPC activity of one connection, used for the idle timeout.
#[derive(Debug)]
pub struct ConnActivity {
    base: Instant,
    last_ms: AtomicU64,
    inflight: AtomicU32,
}

impl ConnActivity {
    pub fn new() -> Self {
        Self {
            base: Instant::now(),
            last_ms: AtomicU64::new(0),
            inflight: AtomicU32::new(0),
        }
    }

    fn touch(&self) {
        let ms = u64::try_from(self.base.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_ms.store(ms, Ordering::Relaxed);
    }

    /// Mark the start of an RPC; the returned guard marks its end.
    pub fn begin(self: &Arc<Self>) -> RpcGuard {
        self.inflight.fetch_add(1, Ordering::AcqRel);
        self.touch();
        RpcGuard(self.clone())
    }

    /// Instant after which the connection counts as idle, or `None` while an
    /// RPC is in flight.
    fn idle_deadline(&self, timeout: Duration) -> Option<Instant> {
        if self.inflight.load(Ordering::Acquire) > 0 {
            return None;
        }
        let last = Duration::from_millis(self.last_ms.load(Ordering::Relaxed));
        Some(self.base + last + timeout)
    }
}

/// Guard held for the duration of one RPC.
pub struct RpcGuard(Arc<ConnActivity>);

impl Drop for RpcGuard {
    fn drop(&mut self) {
        self.0.touch();
        self.0.inflight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Per-connection information inserted into every request's extensions.
#[derive(Debug, Clone)]
pub struct ConnInfo {
    pub conn_id: u64,
    pub identity: Arc<ClientIdentity>,
    pub remote: Option<SocketAddr>,
    pub activity: Arc<ConnActivity>,
}

impl ConnInfo {
    pub fn new(conn_id: u64, identity: ClientIdentity, remote: Option<SocketAddr>) -> Self {
        Self {
            conn_id,
            identity: Arc::new(identity),
            remote,
            activity: Arc::new(ConnActivity::new()),
        }
    }
}

/// Transport underneath a client connection.
pub enum ConnStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::server::TlsStream<TcpStream>>),
}

/// Limits the number of simultaneous connections per source IP.
pub struct IpLimiter {
    max: u32,
    counts: Mutex<HashMap<IpAddr, u32>>,
}

impl IpLimiter {
    pub fn new(max: u32) -> Arc<Self> {
        Arc::new(Self {
            max,
            counts: Mutex::new(HashMap::new()),
        })
    }

    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<IpGuard> {
        let mut map = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        let n = map.entry(ip).or_insert(0);
        if *n >= self.max {
            return None;
        }
        *n += 1;
        Some(IpGuard {
            limiter: self.clone(),
            ip,
        })
    }
}

pub struct IpGuard {
    limiter: Arc<IpLimiter>,
    ip: IpAddr,
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        let mut map = self
            .limiter
            .counts
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(n) = map.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

/// Resources released when a connection ends.
pub struct ConnGuard {
    pub conn_id: u64,
    /// Global connection permit, released on drop.
    pub _permit: Option<OwnedSemaphorePermit>,
    /// Per-IP connection slot, released on drop.
    pub _ip: Option<IpGuard>,
    pub closed: Option<mpsc::UnboundedSender<u64>>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.closed.take() {
            let _ = tx.send(self.conn_id);
        }
    }
}

/// An accepted (and, with TLS, fully handshaken) client connection.
pub struct ClientConn {
    stream: ConnStream,
    info: ConnInfo,
    idle_timeout: Option<Duration>,
    idle_sleep: Option<Pin<Box<Sleep>>>,
    _guard: ConnGuard,
}

impl ClientConn {
    pub fn new(
        stream: ConnStream,
        info: ConnInfo,
        idle_timeout: Option<Duration>,
        guard: ConnGuard,
    ) -> Self {
        Self {
            stream,
            info,
            idle_timeout,
            idle_sleep: None,
            _guard: guard,
        }
    }

    /// Returns true once the connection has been idle past its deadline.
    /// Registers a timer wake-up otherwise.
    fn idle_expired(&mut self, cx: &mut Context<'_>) -> bool {
        let timeout = match self.idle_timeout {
            Some(t) => t,
            None => return false,
        };
        loop {
            // While an RPC is running, re-check after one full timeout period.
            let deadline = self
                .info
                .activity
                .idle_deadline(timeout)
                .unwrap_or_else(|| Instant::now() + timeout);
            let deadline_tokio = tokio::time::Instant::from_std(deadline);
            let sleep = self
                .idle_sleep
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline_tokio)));
            if sleep.deadline() != deadline_tokio {
                sleep.as_mut().reset(deadline_tokio);
            }
            match sleep.as_mut().poll(cx) {
                Poll::Pending => return false,
                Poll::Ready(()) => {
                    match self.info.activity.idle_deadline(timeout) {
                        Some(d) if Instant::now() >= d => return true,
                        // Activity happened meanwhile — re-arm and poll again.
                        _ => continue,
                    }
                }
            }
        }
    }
}

impl Connected for ClientConn {
    type ConnectInfo = ConnInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.info.clone()
    }
}

impl AsyncRead for ClientConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let res = match &mut this.stream {
            ConnStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            ConnStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        };
        match res {
            Poll::Pending => {
                if this.idle_expired(cx) {
                    tracing::info!(
                        conn_id = this.info.conn_id,
                        "closing idle client connection"
                    );
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "connection idle timeout",
                    )))
                } else {
                    Poll::Pending
                }
            }
            other => other,
        }
    }
}

impl AsyncWrite for ClientConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().stream {
            ConnStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            ConnStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().stream {
            ConnStream::Plain(s) => Pin::new(s).poll_flush(cx),
            ConnStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().stream {
            ConnStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            ConnStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().stream {
            ConnStream::Plain(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            ConnStream::Tls(s) => Pin::new(s.as_mut()).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match &self.stream {
            ConnStream::Plain(s) => s.is_write_vectored(),
            ConnStream::Tls(s) => s.is_write_vectored(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_limiter_enforces_cap_and_releases() {
        let lim = IpLimiter::new(2);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let a = lim.try_acquire(ip).unwrap();
        let _b = lim.try_acquire(ip).unwrap();
        assert!(lim.try_acquire(ip).is_none());
        assert!(lim.try_acquire("10.0.0.2".parse().unwrap()).is_some());
        drop(a);
        assert!(lim.try_acquire(ip).is_some());
    }

    #[test]
    fn identity_from_cert_matches_admin_fingerprint() {
        let der = b"not-really-a-certificate";
        let fp = cert_fingerprint(der);
        assert_eq!(fp.len(), 64);
        let id = ClientIdentity::from_cert(der, &[fp.clone()]);
        assert!(id.is_admin && id.authenticated);
        assert_eq!(&*id.id, format!("cert:{}", fp).as_str());
        let other = ClientIdentity::from_cert(b"other", &[fp]);
        assert!(!other.is_admin);
    }

    #[tokio::test]
    async fn idle_connection_is_closed() {
        use tokio::io::AsyncReadExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = TcpStream::connect(addr).await.unwrap();
        let (tcp, _) = listener.accept().await.unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let info = ConnInfo::new(7, ClientIdentity::anonymous(7, false), None);
        let guard = ConnGuard {
            conn_id: 7,
            _permit: None,
            _ip: None,
            closed: Some(tx),
        };
        let mut conn = ClientConn::new(
            ConnStream::Plain(tcp),
            info,
            Some(Duration::from_millis(200)),
            guard,
        );
        let mut buf = [0u8; 8];
        let err = conn.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        drop(conn);
        assert_eq!(rx.recv().await, Some(7));
    }
}

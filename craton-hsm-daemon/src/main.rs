// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Craton Software Company
//! Craton HSM Network Daemon — gRPC over TLS for remote HSM access.

mod config;
mod conn;
mod core_open;
mod listener;
mod mechanism;
mod registry;
mod server;
mod template;
mod throttle;
mod tls;

use std::future::Future;
use std::time::Duration;

use craton_hsm::config::config::HsmConfig;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tonic::transport::Server;
use tower::limit::ConcurrencyLimitLayer;
use tracing_subscriber::filter::LevelFilter;

pub mod proto {
    tonic::include_proto!("craton_hsm");
}

use proto::hsm_service_server::HsmServiceServer;

/// (H4-27) `RUST_LOG=<level>` selects the level (the core library caps
/// levels at INFO at compile time); `CRATON_HSM_LOG_FORMAT=json` emits
/// structured JSON for SIEM ingestion.
fn init_logging() {
    let level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|v| v.trim().parse::<LevelFilter>().ok())
        .unwrap_or(LevelFilter::INFO);
    let json = std::env::var("CRATON_HSM_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    let builder = tracing_subscriber::fmt()
        .with_target(false)
        .with_max_level(level);
    if json {
        builder.json().init();
    } else {
        builder.init();
    }
}

/// (H4-19) Never write PINs or key material to a core file.
fn disable_core_dumps() {
    #[cfg(unix)]
    {
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: setrlimit with a valid, fully initialised rlimit struct.
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) };
        if rc != 0 {
            tracing::warn!("could not disable core dumps (setrlimit RLIMIT_CORE failed)");
        }
    }
}

fn secs(v: u64) -> Option<Duration> {
    (v > 0).then(|| Duration::from_secs(v))
}

/// Resolves once the shutdown flag is set.
fn wait_shutdown(mut rx: watch::Receiver<bool>) -> impl Future<Output = ()> {
    async move {
        while !*rx.borrow() {
            if rx.changed().await.is_err() {
                break;
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install the rustls CryptoProvider before any TLS operations.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "Failed to install rustls CryptoProvider")?;

    init_logging();
    disable_core_dumps();

    // Canonicalize the config path and warn on symlinks.
    let raw_config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "craton_hsm.toml".to_string());
    let config_path = match std::fs::canonicalize(&raw_config_path) {
        Ok(canonical) => {
            if std::fs::symlink_metadata(&raw_config_path)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
            {
                tracing::warn!(
                    "Config path '{}' is a symlink — resolved to '{}'.",
                    raw_config_path,
                    canonical.display()
                );
            }
            canonical.to_string_lossy().to_string()
        }
        Err(_) => raw_config_path,
    };

    // The core loader enforces file permission / symlink checks; the daemon
    // then parses the same file strictly (unknown keys rejected, H4-17).
    let hsm_config = HsmConfig::load_from_path(&config_path).unwrap_or_else(|e| {
        tracing::error!("HSM config loading failed: {}", e);
        std::process::exit(1);
    });
    let full_config = config::FullConfig::load(&config_path).unwrap_or_else(|e| {
        tracing::error!("{}", e);
        std::process::exit(1);
    });
    if let Err(e) = hsm_config.validate() {
        tracing::error!("HSM config validation failed: {}", e);
        std::process::exit(1);
    }
    let dcfg = full_config.daemon;

    if let Err(e) = craton_hsm::crypto::self_test::run_post() {
        tracing::error!("FIPS POST self-tests failed: {:?}", e);
        std::process::exit(1);
    }
    tracing::info!("FIPS POST self-tests passed");

    let hsm = core_open::open_core(&hsm_config).unwrap_or_else(|e| {
        tracing::error!("{}", e);
        std::process::exit(1);
    });

    let max_blocking = if dcfg.max_blocking_tasks == 0 {
        std::thread::available_parallelism().map_or(2, |n| n.get())
    } else {
        dcfg.max_blocking_tasks as usize
    };
    let service = server::HsmServiceImpl::new(
        hsm,
        server::ServiceSettings {
            max_random_length: dcfg.max_random_length,
            max_digest_length: dcfg.max_digest_length,
            max_response_bytes: dcfg.max_response_bytes,
            max_login_attempts: dcfg.max_login_attempts,
            login_cooldown: Duration::from_secs(dcfg.login_cooldown_secs),
            max_sessions_per_client: dcfg.max_sessions_per_client,
            max_objects_per_client: dcfg.max_objects_per_client,
            max_blocking_tasks: max_blocking,
        },
    );
    let shared = service.shared();

    // ── Shutdown signal (H4-16) ─────────────────────────────────────────────
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    // ── Health service (H4-13) ──────────────────────────────────────────────
    // Reported SERVING only once the main listener is bound (below).
    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_not_serving::<HsmServiceServer<server::HsmServiceImpl>>()
        .await;
    health_reporter
        .set_service_status("", tonic_health::ServingStatus::NotServing)
        .await;
    {
        let reporter = health_reporter.clone();
        let rx = shutdown_rx.clone();
        tokio::spawn(async move {
            wait_shutdown(rx).await;
            reporter
                .set_not_serving::<HsmServiceServer<server::HsmServiceImpl>>()
                .await;
            reporter
                .set_service_status("", tonic_health::ServingStatus::NotServing)
                .await;
        });
    }
    if let Some(hb) = &dcfg.health_bind {
        let addr: std::net::SocketAddr = hb.parse()?;
        let health = health_service.clone();
        let rx = shutdown_rx.clone();
        tracing::info!(
            "health endpoint (grpc.health.v1 only, plaintext) on {}",
            addr
        );
        tokio::spawn(async move {
            let r = Server::builder()
                .timeout(Duration::from_secs(5))
                .concurrency_limit_per_connection(4)
                .load_shed(true)
                .layer(ConcurrencyLimitLayer::new(16))
                .add_service(health)
                .serve_with_shutdown(addr, wait_shutdown(rx))
                .await;
            if let Err(e) = r {
                tracing::error!("health listener failed: {}", e);
            }
        });
    }

    // ── Background maintenance (H4-10) ──────────────────────────────────────
    let (closed_tx, mut closed_rx) = mpsc::unbounded_channel::<u64>();
    {
        let shared = shared.clone();
        tokio::spawn(async move {
            while let Some(conn_id) = closed_rx.recv().await {
                let sh = shared.clone();
                let n = tokio::task::spawn_blocking(move || sh.cleanup_connection(conn_id))
                    .await
                    .unwrap_or(0);
                if n > 0 {
                    tracing::info!(
                        conn_id,
                        sessions = n,
                        "closed sessions of disconnected client"
                    );
                }
            }
        });
    }
    if let Some(idle) = secs(dcfg.session_idle_timeout_secs) {
        let shared = shared.clone();
        let period = (idle / 2).clamp(Duration::from_secs(1), Duration::from_secs(60));
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(period);
            loop {
                tick.tick().await;
                let sh = shared.clone();
                let n = tokio::task::spawn_blocking(move || sh.reap_idle_sessions(idle))
                    .await
                    .unwrap_or(0);
                if n > 0 {
                    tracing::info!(sessions = n, "closed idle sessions");
                }
            }
        });
    }

    // ── TLS (mandatory unless loopback development mode) ────────────────────
    let tls_state = match (&dcfg.tls_cert, &dcfg.tls_key) {
        (Some(cert), Some(key)) => {
            let state = tls::TlsState::new(tls::TlsSettings {
                cert_path: cert.clone(),
                key_path: key.clone(),
                client_ca_path: dcfg.tls_client_ca.clone(),
                client_crl_paths: dcfg.tls_client_crl.clone(),
            })?;
            tracing::info!("TLS enabled (cert: {}, TLS 1.3 only)", cert);
            if let (true, Some(every)) = (state.has_crls(), secs(dcfg.tls_client_crl_reload_secs)) {
                let st = state.clone();
                tokio::spawn(async move {
                    let mut tick = tokio::time::interval(every);
                    tick.tick().await;
                    loop {
                        tick.tick().await;
                        let st = st.clone();
                        let _ = tokio::task::spawn_blocking(move || st.reload()).await;
                    }
                });
            }
            Some(state)
        }
        _ => {
            // Config validation guarantees loopback + explicit opt-in here.
            tracing::error!(
                "TLS disabled — running WITHOUT encryption or client authentication on {}. \
                 Development only.",
                dcfg.bind
            );
            None
        }
    };

    let admin_fingerprints: Vec<String> = dcfg
        .admin_client_cert_sha256
        .iter()
        .filter_map(|f| config::normalize_fingerprint(f).ok())
        .collect();
    if admin_fingerprints.is_empty() && !dcfg.insecure_loopback_admin {
        tracing::warn!(
            "No administrator certificates configured: InitToken, SO login and InitPin \
             are unavailable over gRPC"
        );
    }

    let addr: std::net::SocketAddr = dcfg.bind.parse()?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("Craton HSM daemon listening on {}", addr);
    health_reporter
        .set_serving::<HsmServiceServer<server::HsmServiceImpl>>()
        .await;
    health_reporter
        .set_service_status("", tonic_health::ServingStatus::Serving)
        .await;

    let mut conn_rx = listener::spawn_acceptor(
        listener,
        tls_state,
        listener::ListenerSettings {
            max_connections: dcfg.max_connections as usize,
            max_connections_per_ip: dcfg.max_connections_per_ip,
            handshake_timeout: Duration::from_secs(dcfg.handshake_timeout_secs),
            idle_timeout: secs(dcfg.connection_idle_timeout_secs),
            admin_fingerprints,
            insecure_admin: dcfg.insecure_loopback_admin,
        },
        closed_tx,
    );
    let incoming = async_stream::stream! {
        while let Some(conn) = conn_rx.recv().await {
            yield Ok::<_, std::io::Error>(conn);
        }
    };

    // (H4-07) Message limits derived from configuration.
    let svc = HsmServiceServer::new(service)
        .max_decoding_message_size(dcfg.max_request_bytes as usize)
        .max_encoding_message_size(dcfg.max_response_bytes as usize);

    // (H4-04) Timeouts, keepalive, stream and in-flight limits, load shedding.
    let mut builder = Server::builder()
        .timeout(Duration::from_secs(dcfg.request_timeout_secs))
        .concurrency_limit_per_connection(dcfg.max_concurrent_streams as usize)
        .max_concurrent_streams(dcfg.max_concurrent_streams)
        .load_shed(true)
        .http2_keepalive_interval(secs(dcfg.http2_keepalive_interval_secs))
        .http2_keepalive_timeout(Some(Duration::from_secs(dcfg.http2_keepalive_timeout_secs)))
        .http2_max_pending_accept_reset_streams(Some(32));
    if let Some(age) = secs(dcfg.max_connection_age_secs) {
        builder = builder
            .max_connection_age(age)
            .max_connection_age_grace(Duration::from_secs(dcfg.request_timeout_secs));
    }
    let mut builder = builder.layer(ConcurrencyLimitLayer::new(
        dcfg.max_inflight_requests as usize,
    ));

    let serve = builder
        .add_service(health_service)
        .add_service(svc)
        .serve_with_incoming_shutdown(incoming, wait_shutdown(shutdown_rx.clone()));
    tokio::pin!(serve);

    let drain = Duration::from_secs(dcfg.request_timeout_secs + 5);
    let drain_deadline = {
        let rx = shutdown_rx.clone();
        async move {
            wait_shutdown(rx).await;
            tokio::time::sleep(drain).await;
        }
    };
    tokio::select! {
        r = &mut serve => {
            if let Err(e) = r {
                tracing::error!("server error: {}", e);
            }
        }
        _ = drain_deadline => {
            tracing::warn!("graceful drain timed out after {:?}; exiting", drain);
        }
    }

    // (H4-16) Make every queued audit event durable before exiting.
    let sh = shared.clone();
    let _ = tokio::task::spawn_blocking(move || sh.flush_audit()).await;
    tracing::info!("audit log flushed; shutdown complete");
    Ok(())
}

/// Graceful shutdown on SIGTERM (Kubernetes / Docker stop) or SIGINT.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {},
                    _ = term.recv() => {},
                }
            }
            Err(e) => {
                tracing::error!("cannot install SIGTERM handler: {}", e);
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    tracing::info!("Shutdown signal received, draining connections...");
}
